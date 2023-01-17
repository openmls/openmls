//! Module to encrypt and decrypt update paths for a [`TreeSyncDiff`] instance.
//!
//! # About
//!
//! This module contains structs and functions to encrypt and decrypt path
//! updates for a [`TreeSyncDiff`] instance.
use rayon::prelude::*;
use std::collections::HashSet;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, HpkeCiphertext},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::{hash_ref::KeyPackageRef, HpkePublicKey},
    error::LibraryError,
    messages::{proposals::AddProposal, EncryptedGroupSecrets, GroupSecrets, PathSecret},
    schedule::{psk::PreSharedKeyId, CommitSecret, JoinerSecret},
    treesync::node::NodeReference,
    versions::ProtocolVersion,
};

use super::{
    diff::TreeSyncDiff,
    node::{
        encryption_keys::{EncryptionKey, EncryptionKeyPair},
        parent_node::{ParentNode, PlainUpdatePathNode},
    },
    ApplyUpdatePathError, LeafNode,
};

impl<'a> TreeSyncDiff<'a> {
    /// Encrypt the given `path` to the nodes in the copath resolution of the
    /// owner of this [`TreeSyncDiff`]. The `group_context` is used in the
    /// encryption of the nodes, while the `exclusion_list` is used to filter
    /// target leaves from the encryption targets. The given [`LeafNode`] is
    /// included in the resulting [`UpdatePath`].
    ///
    /// Returns the encrypted path (i.e. an [`UpdatePath`] instance).
    pub(crate) fn encrypt_path(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        path: &[PlainUpdatePathNode],
        group_context: &[u8],
        exclusion_list: &HashSet<&LeafNodeIndex>,
    ) -> Vec<UpdatePathNode> {
        // Copath resolutions with the corresponding public keys.
        let copath_resolutions = self
            .filtered_copath_resolutions(self.own_leaf_index(), exclusion_list)
            .into_iter()
            .map(|resolution| {
                resolution
                    .into_iter()
                    .map(|(_, node_ref)| match node_ref {
                        NodeReference::Leaf(leaf) => leaf.public_key().clone(),
                        NodeReference::Parent(parent) => parent.public_key().clone(),
                    })
                    .collect::<Vec<HpkePublicKey>>()
            })
            .collect::<Vec<Vec<HpkePublicKey>>>();

        // There should be as many copath resolutions.
        debug_assert_eq!(copath_resolutions.len(), path.len());

        // Encrypt the secrets
        let nodes = path
            .par_iter()
            .zip(copath_resolutions.par_iter())
            .map(|(node, resolution)| node.encrypt(backend, ciphersuite, resolution, group_context))
            .collect::<Vec<UpdatePathNode>>();

        nodes
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
        owned_keys: &[EncryptionKeyPair],
    ) -> Result<(Vec<ParentNode>, Vec<EncryptionKeyPair>, CommitSecret), ApplyUpdatePathError> {
        // ValSem202: Path must be the right length
        let direct_path_length = self.filtered_direct_path(params.sender_leaf_index).len();
        if direct_path_length != params.update_path.len() {
            // XXX: Rewrite tests to allow for debug asserts.
            // debug_assert!(
            //     false,
            //     "Path length mismatch {} != {}",
            //     direct_path_length,
            //     params.update_path.len()
            // );
            return Err(ApplyUpdatePathError::PathLengthMismatch);
        }

        let path_position = self
            .subtree_root_position(params.sender_leaf_index, self.own_leaf_index())
            .map_err(|_| LibraryError::custom("Expected own leaf to be in the tree"))?;

        let update_path_node = params
            .update_path
            .get(path_position)
            // We know the update path has the right length through validation, therefore there must be an element at this position
            // TODO #804
            .ok_or_else(|| LibraryError::custom("Expected to find ciphertext in update path 1"))?;

        let (decryption_key, resolution_position) = self
            .decryption_key(params.sender_leaf_index, params.exclusion_list, owned_keys)
            // TODO #804
            .map_err(|_| LibraryError::custom("Expected sender to be in the tree"))?;
        let ciphertext = update_path_node
            .encrypted_path_secrets(resolution_position)
            // We know the update path has the right length through validation, therefore there must be a ciphertext at this position
            // TODO #804
            .ok_or_else(|| LibraryError::custom("Expected to find ciphertext in update path 2"))?;

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

        let common_path =
            self.filtered_common_direct_path(self.own_leaf_index(), params.sender_leaf_index);
        let (derived_path, _plain_update_path, keypairs, commit_secret) =
            ParentNode::derive_path(backend, ciphersuite, path_secret, common_path)?;
        // We now check that the public keys in the update path and in the
        // derived path match up.
        // ValSem204: Public keys from Path must be verified and match the private keys from the direct path
        for (update_parent_node, (_, derived_parent_node)) in params
            .update_path
            .iter()
            .skip(path_position)
            .zip(derived_path.iter())
        {
            if update_parent_node.public_key() != derived_parent_node.public_key() {
                return Err(ApplyUpdatePathError::PathMismatch);
            }
        }

        let _update_path_len = params.update_path.len();

        // Finally, we append the derived path to the part of the update path
        // below the first node that we have a private key for.
        let mut path: Vec<ParentNode> = params
            .update_path
            .into_iter()
            .take(path_position)
            .map(|update_path_node| update_path_node.public_key.into())
            .collect();
        path.append(&mut derived_path.into_iter().map(|(_, node)| node).collect());

        // The output should have the same length as the input.
        debug_assert_eq!(_update_path_len, path.len());

        Ok((path, keypairs, commit_secret))
    }
}

pub(crate) struct DecryptPathParams<'a> {
    pub(crate) version: ProtocolVersion,
    pub(crate) update_path: Vec<UpdatePathNode>,
    pub(crate) sender_leaf_index: LeafNodeIndex,
    pub(crate) exclusion_list: &'a HashSet<&'a LeafNodeIndex>,
    pub(crate) group_context: &'a [u8],
}

/// 8.6. Update Paths
///
/// ```text
/// struct {
///     HPKEPublicKey public_key;
///     HPKECiphertext encrypted_path_secret<V>;
/// } UpdatePathNode;
/// ```
#[derive(
    Debug, Eq, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct UpdatePathNode {
    pub(super) public_key: EncryptionKey,
    pub(super) encrypted_path_secrets: Vec<HpkeCiphertext>,
}

impl UpdatePathNode {
    /// Return the `encrypted_path_secrets`.
    fn encrypted_path_secrets(&self, ciphertext_index: usize) -> Option<&HpkeCiphertext> {
        self.encrypted_path_secrets.get(ciphertext_index)
    }

    /// Return the `public_key`.
    fn public_key(&self) -> &HpkePublicKey {
        self.public_key.key()
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
        self.encrypted_path_secrets = new_eps_vec;
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
        self.public_key = EncryptionKey::tls_deserialize(&mut new_pk_serialized.as_slice())
            .expect("error deserializing pk");
    }
}

/// Helper struct holding values that are encrypted in the
/// `EncryptedGroupSecrets`. In particular, the `group_secrets_bytes` are
/// encrypted for the `public_key` into `encrypted_group_secrets` later.
pub(crate) struct PlaintextSecret {
    public_key: HpkePublicKey,
    group_secrets_bytes: Vec<u8>,
    new_member: KeyPackageRef,
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
        invited_members: Vec<(LeafNodeIndex, AddProposal)>,
        plain_path_option: Option<&[PlainUpdatePathNode]>,
        presharedkeys: &[PreSharedKeyId],
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
                new_member: key_package.hash_ref(backend.crypto())?,
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
        EncryptedGroupSecrets::new(self.new_member, encrypted_group_secrets)
    }
}

/// 8.6. Update Paths
///
/// ```text
/// struct {
///     LeafNode leaf_node;
///     UpdatePathNode nodes<V>;
/// } UpdatePath;
/// ```
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct UpdatePath {
    leaf_node: LeafNode,
    nodes: Vec<UpdatePathNode>,
}

impl UpdatePath {
    /// Generate a new update path.
    pub(crate) fn new(leaf_node: LeafNode, nodes: Vec<UpdatePathNode>) -> Self {
        Self { leaf_node, nodes }
    }

    /// Return the `leaf_node` of this [`UpdatePath`].
    pub(crate) fn leaf_node(&self) -> &LeafNode {
        &self.leaf_node
    }

    /// Consume the [`UpdatePath`] and return its individual parts: A
    /// [`LeafNode`] and a vector of [`UpdatePathNode`] instances.
    pub(crate) fn into_parts(self) -> (LeafNode, Vec<UpdatePathNode>) {
        (self.leaf_node, self.nodes)
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
        self.nodes = new_nodes;
    }

    #[cfg(test)]
    /// Set the path key package.
    pub fn set_leaf_node(&mut self, leaf_node: LeafNode) {
        self.leaf_node = leaf_node
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
