//! Module to encrypt and decrypt update paths for a [`TreeSyncDiff`] instance.
//!
//! # About
//!
//! This module contains structs and functions to encrypt and decrypt path
//! updates for a [`TreeSyncDiff`] instance.
use std::collections::HashSet;

use tls_codec::{Error as TlsCodecError, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU32};

use openmls_traits::{crypto::OpenMlsCrypto, types::HpkeCiphertext, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafIndex,
    ciphersuite::{Ciphersuite, HpkePublicKey},
    config::ProtocolVersion,
    key_packages::{KeyPackage, KeyPackageError},
    messages::{
        proposals::AddProposal, EncryptedGroupSecrets, GroupSecrets, PathSecret, PathSecretError,
    },
    schedule::{CommitSecret, JoinerSecret, PreSharedKeys},
};

use super::{
    diff::TreeSyncDiff,
    node::parent_node::{ParentNode, ParentNodeError, PlainUpdatePathNode},
    TreeSyncDiffError, TreeSyncError,
};

impl<'a> TreeSyncDiff<'a> {
    /// Encrypt the given `path` to the nodes in the copath resolution of the
    /// owner of this [`TreeSyncDiff`]. The `group_context` is used in the
    /// encryption of the nodes, while the `exclusion_list` is used to filter
    /// target leaves from the encryption targets. The given [`KeyPackage`] is
    /// included in the resulting [`UpdatePath`].
    ///
    /// Returns the encrypted path (i.e. an [`UpdatePath`] instance).
    pub(crate) fn encrypt_path(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        path: &[PlainUpdatePathNode],
        group_context: &[u8],
        exclusion_list: &HashSet<&LeafIndex>,
        key_package: &KeyPackage,
    ) -> Result<UpdatePath, TreeKemError> {
        let copath_resolutions = self.copath_resolutions(self.own_leaf_index(), exclusion_list)?;

        // There should be as many copath resolutions.
        if copath_resolutions.len() != path.len() {
            return Err(TreeKemError::PathLengthError);
        }

        let mut update_path_nodes = Vec::with_capacity(path.len());
        // Encrypt the secrets
        for (node, resolution) in path.iter().zip(copath_resolutions.iter()) {
            let update_path_node = node.encrypt(backend, ciphersuite, resolution, group_context);
            update_path_nodes.push(update_path_node);
        }

        Ok(UpdatePath {
            leaf_key_package: key_package.clone(),
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
    pub(crate) fn decrypt_path(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &'static Ciphersuite,
        version: ProtocolVersion,
        update_path: Vec<UpdatePathNode>,
        sender_leaf_index: LeafIndex,
        exclusion_list: &HashSet<&LeafIndex>,
        group_context: &[u8],
    ) -> Result<(Vec<ParentNode>, CommitSecret), TreeKemError> {
        let path_position = self.subtree_root_position(sender_leaf_index, self.own_leaf_index())?;
        let update_path_node = update_path
            .get(path_position)
            .ok_or(TreeKemError::UpdatePathNodeNotFound)?;

        let (decryption_key, resolution_position) =
            self.decryption_key(sender_leaf_index, exclusion_list)?;
        let ciphertext = update_path_node
            .encrypted_path_secrets(resolution_position)
            .ok_or(TreeKemError::EncryptedCiphertextNotFound)?;

        let path_secret = PathSecret::decrypt(
            backend,
            ciphersuite,
            version,
            ciphertext,
            decryption_key,
            group_context,
        )?;

        let remaining_path_length = update_path.len() - path_position;
        let (mut derived_path, _plain_update_path, commit_secret) =
            ParentNode::derive_path(backend, ciphersuite, path_secret, remaining_path_length)?;
        // We now check that the public keys in the update path and in the
        // derived path match up.
        for (update_parent_node, derived_parent_node) in update_path
            .iter()
            .skip(path_position)
            .zip(derived_path.iter())
        {
            if update_parent_node.public_key() != derived_parent_node.public_key() {
                return Err(TreeKemError::PathMismatch);
            }
        }

        // Finally, we append the derived path to the part of the update path
        // below the first node that we have a private key for.
        #[cfg(debug_assertions)]
        let update_path_len = update_path.len();

        let mut path: Vec<ParentNode> = update_path
            .into_iter()
            .take(path_position)
            .map(|update_path_node| update_path_node.public_key.into())
            .collect();
        path.append(&mut derived_path);

        debug_assert_eq!(path.len(), update_path_len);

        Ok((path, commit_secret))
    }
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
}

/// Helper struct holding values that are encrypted in the
/// `EncryptedGroupSecrets`. In particular, the `group_secrets_bytes` are
/// encrypted for the `public_key` into `encrypted_group_secrets` later.
pub(crate) struct PlaintextSecret {
    public_key: HpkePublicKey,
    group_secrets_bytes: Vec<u8>,
    key_package_hash: Vec<u8>,
}

impl PlaintextSecret {
    /// Prepare the `GroupSecrets` for a number of `invited_members` based on a
    /// [`TreeSyncDiff`]. If a slice of [`PlainUpdatePathNode`] is given, they
    /// are included in the [`GroupSecrets`] of the path.
    pub(crate) fn from_plain_update_path(
        diff: &TreeSyncDiff,
        joiner_secret: &JoinerSecret,
        invited_members: Vec<(LeafIndex, AddProposal)>,
        plain_path_option: Option<&[PlainUpdatePathNode]>,
        presharedkeys: &PreSharedKeys,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Vec<Self>, TreeKemError> {
        let mut plaintext_secrets = vec![];
        for (leaf_index, add_proposal) in invited_members {
            let key_package = add_proposal.key_package;
            let key_package_hash = key_package.hash(backend)?;

            let direct_path_position =
                diff.subtree_root_position(diff.own_leaf_index(), leaf_index)?;

            // If a plain path was given, there have to be secrets for every new member.
            let path_secret_option = if let Some(plain_path) = plain_path_option {
                Some(
                    plain_path
                        .get(direct_path_position)
                        .map(|pupn| pupn.path_secret())
                        .ok_or(TreeKemError::PathSecretNotFound)?,
                )
            } else {
                None
            };

            // Create the GroupSecrets object for the respective member.
            let group_secrets_bytes =
                GroupSecrets::new_encoded(joiner_secret, path_secret_option, presharedkeys)?;
            plaintext_secrets.push(PlaintextSecret {
                public_key: key_package.hpke_init_key().clone(),
                group_secrets_bytes,
                key_package_hash,
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
        ciphersuite: &Ciphersuite,
    ) -> EncryptedGroupSecrets {
        let encrypted_group_secrets = backend.crypto().hpke_seal(
            ciphersuite.hpke_config(),
            self.public_key.as_slice(),
            &[],
            &[],
            &self.group_secrets_bytes,
        );
        EncryptedGroupSecrets {
            key_package_hash: self.key_package_hash.into(),
            encrypted_group_secrets,
        }
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
}

implement_error! {
    pub enum TreeKemError {
        Simple {
            LibraryError = "An inconsistency in the internal state of the tree was detected.",
            PathLengthError = "The given path to encrypt does not have the same length as the direct path.",
            PathMismatch = "The received update path and the derived nodes are inconsistent.",
            UpdatePathNodeNotFound = "Couldn't find our UpdatePathNode in the given UpdatePath.",
            EncryptedCiphertextNotFound = "Couldn't find a matching encrypted ciphertext in the given UpdatePathNode.",
            PathSecretNotFound = "Couldn't find the path secret to encrypt for one of the new members.",
        }
        Complex {
            TreeSyncError(TreeSyncError) = "Error while creating treesync diff.",
            TreeSyncDiffError(TreeSyncDiffError) = "Error while retrieving public keys from the tree.",
            PathSecretError(PathSecretError) = "Error decrypting PathSecret.",
            PathDerivationError(ParentNodeError) = "Error deriving path from PathSecret.",
            EncodingError(TlsCodecError) = "Error while encoding GroupSecrets.",
            KeyPackageError(KeyPackageError) = "Error while hashing KeyPackage.",
        }
    }
}
