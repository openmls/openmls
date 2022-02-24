//! Module to encrypt and decrypt update paths for a [`TreeSyncDiff`] instance.
//!
//! # About
//!
//! This module contains structs and functions to encrypt and decrypt path
//! updates for a [`TreeSyncDiff`] instance.
use rayon::prelude::*;
use std::collections::HashSet;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, TlsVecU32};

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, HpkeCiphertext},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};

use crate::{
    binary_tree::{LeafIndex, OutOfBoundsError},
    ciphersuite::{hash_ref::KeyPackageRef, HpkePublicKey},
    error::LibraryError,
    key_packages::KeyPackage,
    messages::{proposals::AddProposal, EncryptedGroupSecrets, GroupSecrets, PathSecret},
    schedule::{psk::PreSharedKeys, CommitSecret, JoinerSecret},
    versions::ProtocolVersion,
};

use super::{
    diff::TreeSyncDiff,
    node::parent_node::{ParentNode, PlainUpdatePathNode},
    ApplyUpdatePathError,
};

impl<'a> TreeSyncDiff<'a> {
    /// Encrypt the given `path` to the nodes in the copath resolution of the
    /// owner of this [`TreeSyncDiff`]. The `group_context` is used in the
    /// encryption of the nodes, while the `exclusion_list` is used to filter
    /// target leaves from the encryption targets. The given [`KeyPackage`] is
    /// included in the resulting [`UpdatePath`].
    ///
    /// Returns the encrypted path (i.e. an [`UpdatePath`] instance).
    ///
    /// Returns an error if the path does not have the same length as the copath resolution.
    pub(crate) fn encrypt_path(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        path: &[PlainUpdatePathNode],
        group_context: &[u8],
        exclusion_list: &HashSet<&LeafIndex>,
        key_package: KeyPackage,
    ) -> Result<UpdatePath, LibraryError> {
        let copath_resolutions = self.copath_resolutions(self.own_leaf_index(), exclusion_list)?;

        // There should be as many copath resolutions.
        debug_assert_eq!(copath_resolutions.len(), path.len());

        // Encrypt the secrets
        let update_path_nodes = path
            .par_iter()
            .zip(copath_resolutions.par_iter())
            .map(|(node, resolution)| node.encrypt(backend, ciphersuite, resolution, group_context))
            .collect::<Vec<UpdatePathNode>>();

        Ok(UpdatePath {
            leaf_key_package: key_package,
            nodes: update_path_nodes.into(),
        })
    }

    /// Decrypt an [`UpdatePath`] originating from the given
    /// `sender_leaf_index`. The `group_context` is used in the decryption
    /// process and the `exclusion_list` is used to determine the position of
    /// the ciphertext in the `UpdatePath` that we can decrypt.
    ///
    /// Returns a vector containing the decrypted [`ParentNode`] instances, as
    /// well as the [`CommitSecret`] resulting from their derivation. Returns an
    /// error if the `sender_leaf_index` is outside of the tree.
    ///
    /// ValSem202: Path must be the right length
    /// ValSem203: Path secrets must decrypt correctly
    /// ValSem204: Public keys from Path must be verified and match the private keys from the direct path
    /// TODO #804
    pub(crate) fn decrypt_path(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        params: DecryptPathParams,
    ) -> Result<(Vec<ParentNode>, CommitSecret), ApplyUpdatePathError> {
        let path_position = self
            .subtree_root_position(params.sender_leaf_index, self.own_leaf_index())
            .map_err(|_| LibraryError::custom("Expected own leaf to be in the tree"))?;

        // ValSem202: Path must be the right length
        let direct_path_length =
            self.direct_path_len(params.sender_leaf_index)
                .map_err(|e| match e {
                    OutOfBoundsError::LibraryError(e) => ApplyUpdatePathError::LibraryError(e),
                    OutOfBoundsError::IndexOutOfBounds => ApplyUpdatePathError::MissingSender,
                })?;
        if direct_path_length != params.update_path.len() {
            return Err(ApplyUpdatePathError::PathLengthMismatch);
        }

        let update_path_node = params
            .update_path
            .get(path_position)
            // We know the update path has the right length through validation, therefore there must be an element at this position
            // TODO #804
            .ok_or_else(|| LibraryError::custom("Expected to find ciphertext in update path"))?;

        let (decryption_key, resolution_position) = self
            .decryption_key(params.sender_leaf_index, params.exclusion_list)
            // TODO #804
            .map_err(|_| LibraryError::custom("Expected sender to be in the tree"))?;
        let ciphertext = update_path_node
            .encrypted_path_secrets(resolution_position)
            // We know the update path has the right length through validation, therefore there must be a ciphertext at this position
            // TODO #804
            .ok_or_else(|| LibraryError::custom("Expected to find ciphertext in update path"))?;

        // ValSem203: Path secrets must decrypt correctly
        let path_secret = PathSecret::decrypt(
            backend,
            ciphersuite,
            params.version,
            ciphertext,
            decryption_key,
            params.group_context,
        )
        .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;

        let remaining_path_length = params.update_path.len() - path_position;
        let (mut derived_path, _plain_update_path, commit_secret) =
            ParentNode::derive_path(backend, ciphersuite, path_secret, remaining_path_length)?;
        // We now check that the public keys in the update path and in the
        // derived path match up.
        // ValSem204: Public keys from Path must be verified and match the private keys from the direct path
        for (update_parent_node, derived_parent_node) in params
            .update_path
            .iter()
            .skip(path_position)
            .zip(derived_path.iter())
        {
            if update_parent_node.public_key() != derived_parent_node.public_key() {
                return Err(ApplyUpdatePathError::PathMismatch);
            }
        }

        // Finally, we append the derived path to the part of the update path
        // below the first node that we have a private key for.
        let _update_path_len = params.update_path.len();

        let mut path: Vec<ParentNode> = params
            .update_path
            .into_iter()
            .take(path_position)
            .map(|update_path_node| update_path_node.public_key.into())
            .collect();
        path.append(&mut derived_path);

        debug_assert_eq!(path.len(), _update_path_len);

        Ok((path, commit_secret))
    }
}

pub(crate) struct DecryptPathParams<'a> {
    pub(crate) version: ProtocolVersion,
    pub(crate) update_path: Vec<UpdatePathNode>,
    pub(crate) sender_leaf_index: LeafIndex,
    pub(crate) exclusion_list: &'a HashSet<&'a LeafIndex>,
    pub(crate) group_context: &'a [u8],
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     HPKEPublicKey public_key;
///     HPKECiphertext encrypted_path_secret<0..2^32-1>;
/// } UpdatePathNode;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct UpdatePathNode {
    pub(super) public_key: HpkePublicKey,
    pub(super) encrypted_path_secrets: TlsVecU32<HpkeCiphertext>,
}

impl UpdatePathNode {
    /// Return the `encrypted_path_secrets`.
    fn encrypted_path_secrets(&self, ciphertext_index: usize) -> Option<&HpkeCiphertext> {
        self.encrypted_path_secrets.get(ciphertext_index)
    }

    /// Return the `public_key`.
    fn public_key(&self) -> &HpkePublicKey {
        &self.public_key
    }

    /// Flip the last byte of every `encrypted_path_secret` in this node.
    #[cfg(test)]
    fn flip_last_byte(&mut self) {
        let mut new_eps_vec = Vec::new();
        for eps in self.encrypted_path_secrets.as_slice() {
            let mut new_eps = eps.clone();
            let mut last_bits = new_eps
                .ciphertext
                .pop()
                .expect("An unexpected error occurred.");
            last_bits ^= 0xff;
            new_eps.ciphertext.push(last_bits);
            new_eps_vec.push(new_eps);
        }
        self.encrypted_path_secrets = new_eps_vec.into();
    }

    /// Flip the last byte of the public key in this node.
    #[cfg(test)]
    fn flip_last_pk_byte(&mut self) {
        use tls_codec::{Deserialize, Serialize};

        let mut new_pk_serialized = self
            .public_key
            .tls_serialize_detached()
            .expect("error serializing public key");
        let mut last_bits = new_pk_serialized
            .pop()
            .expect("An unexpected error occurred.");
        last_bits ^= 0xff;
        new_pk_serialized.push(last_bits);
        self.public_key = HpkePublicKey::tls_deserialize(&mut new_pk_serialized.as_slice())
            .expect("error deserializing pk");
    }
}

/// Helper struct holding values that are encrypted in the
/// `EncryptedGroupSecrets`. In particular, the `group_secrets_bytes` are
/// encrypted for the `public_key` into `encrypted_group_secrets` later.
pub(crate) struct PlaintextSecret {
    public_key: HpkePublicKey,
    group_secrets_bytes: Vec<u8>,
    key_package_ref: KeyPackageRef,
}

impl PlaintextSecret {
    /// Prepare the `GroupSecrets` for a number of `invited_members` based on a
    /// [`TreeSyncDiff`]. If a slice of [`PlainUpdatePathNode`] is given, they
    /// are included in the [`GroupSecrets`] of the path.
    ///
    /// Returns an error if
    ///  - the own node is outside the tree
    ///  - the invited members are not part of the tree yet
    ///  - the leaf index of a new member is identical to the own leaf index
    ///  - the plain path does not contain the correct secrets
    pub(crate) fn from_plain_update_path(
        diff: &TreeSyncDiff,
        joiner_secret: &JoinerSecret,
        invited_members: Vec<(LeafIndex, AddProposal)>,
        plain_path_option: Option<&[PlainUpdatePathNode]>,
        presharedkeys: &PreSharedKeys,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Vec<Self>, LibraryError> {
        let mut plaintext_secrets = vec![];
        for (leaf_index, add_proposal) in invited_members {
            let key_package = add_proposal.key_package;

            let direct_path_position = diff
                .subtree_root_position(diff.own_leaf_index(), leaf_index)
                // This can only fail if the nodes are outside the tree or identical
                .map_err(|_| LibraryError::custom("Unexpected error in subtree_root_position"))?;

            // If a plain path was given, there have to be secrets for every new member.
            let path_secret_option = if let Some(plain_path) = plain_path_option {
                Some(
                    plain_path
                        .get(direct_path_position)
                        .map(|pupn| pupn.path_secret())
                        // This only fails if the supplied plain path is invalid
                        .ok_or_else(|| LibraryError::custom("Invalid plain path"))?,
                )
            } else {
                None
            };

            // Create the GroupSecrets object for the respective member.
            let group_secrets_bytes =
                GroupSecrets::new_encoded(joiner_secret, path_secret_option, presharedkeys)
                    .map_err(LibraryError::missing_bound_check)?;
            plaintext_secrets.push(PlaintextSecret {
                public_key: key_package.hpke_init_key().clone(),
                group_secrets_bytes,
                key_package_ref: key_package.hash_ref(backend.crypto())?,
            });
        }
        Ok(plaintext_secrets)
    }

    /// Encrypt the `group_secret_bytes` using the `public_key`, both contained
    /// in this [`PlaintextSecret`].
    ///
    /// Returns the resulting [`EncryptedGroupSecrets`].
    pub(crate) fn encrypt(
        self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
    ) -> EncryptedGroupSecrets {
        let encrypted_group_secrets = backend.crypto().hpke_seal(
            ciphersuite.hpke_config(),
            self.public_key.as_slice(),
            &[],
            &[],
            &self.group_secrets_bytes,
        );
        EncryptedGroupSecrets::new(self.key_package_ref, encrypted_group_secrets)
    }
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     KeyPackage leaf_key_package;
///     UpdatePathNode nodes<0..2^32-1>;
/// } UpdatePath;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct UpdatePath {
    leaf_key_package: KeyPackage,
    nodes: TlsVecU32<UpdatePathNode>,
}

impl UpdatePath {
    /// Return the `leaf_key_package` of this [`UpdatePath`].
    pub(crate) fn leaf_key_package(&self) -> &KeyPackage {
        &self.leaf_key_package
    }

    /// Consume the [`UpdatePath`] and return its individual parts: A
    /// [`KeyPackage`] and a vector of [`UpdatePathNode`] instances.
    pub(crate) fn into_parts(self) -> (KeyPackage, Vec<UpdatePathNode>) {
        (self.leaf_key_package, self.nodes.into())
    }

    #[cfg(test)]
    /// Flip the last bytes of the ciphertexts of all contained nodes.
    pub fn flip_eps_bytes(&mut self) {
        let mut new_nodes = Vec::new();
        for node in self.nodes.as_slice() {
            let mut new_node = node.clone();
            new_node.flip_last_byte();
            new_nodes.push(new_node);
        }
        self.nodes = new_nodes.into();
    }

    #[cfg(test)]
    /// Set the path key package.
    pub fn set_leaf_key_package(&mut self, key_package: KeyPackage) {
        self.leaf_key_package = key_package
    }

    #[cfg(test)]
    /// Remove and return the last node in the update path. Returns `None` if
    /// the path is empty.
    pub fn pop(&mut self) -> Option<UpdatePathNode> {
        self.nodes.pop()
    }

    #[cfg(test)]
    /// Flip the last bytes of the public key in the last node in the path.
    pub fn flip_node_bytes(&mut self) {
        let mut last_node = self.nodes.pop().expect("path empty");
        last_node.flip_last_pk_byte();
        self.nodes.push(last_node)
    }
}
