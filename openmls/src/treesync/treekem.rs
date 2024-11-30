//! Module to encrypt and decrypt update paths for a [`TreeSyncDiff`] instance.
//!
//! # About
//!
//! This module contains structs and functions to encrypt and decrypt path
//! updates for a [`TreeSyncDiff`] instance.
use std::collections::HashSet;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, HpkeCiphertext},
};
#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use super::{
    diff::TreeSyncDiff,
    errors::UpdatePathError,
    node::{
        encryption_keys::{EncryptionKey, EncryptionKeyPair},
        leaf_node::{LeafNodeIn, TreePosition, VerifiableLeafNode},
        parent_node::{ParentNode, PlainUpdatePathNode},
    },
    ApplyUpdatePathError, LeafNode,
};
use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::{hpke, signable::Verifiable, HpkePublicKey},
    error::LibraryError,
    messages::{proposals::AddProposal, EncryptedGroupSecrets, GroupSecrets, PathSecret},
    schedule::{psk::PreSharedKeyId, CommitSecret, JoinerSecret},
    treesync::node::NodeReference,
};

impl TreeSyncDiff<'_> {
    /// Encrypt the given `path` to the nodes in the copath resolution of the
    /// owner of this [`TreeSyncDiff`]. The `group_context` is used in the
    /// encryption of the nodes, while the `exclusion_list` is used to filter
    /// target leaves from the encryption targets. The given [`LeafNode`] is
    /// included in the resulting [`UpdatePath`].
    ///
    /// Returns the encrypted path (i.e. an [`UpdatePath`] instance).
    pub(crate) fn encrypt_path(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        path: &[PlainUpdatePathNode],
        group_context: &[u8],
        exclusion_list: &HashSet<&LeafNodeIndex>,
        own_leaf_index: LeafNodeIndex,
    ) -> Result<Vec<UpdatePathNode>, LibraryError> {
        // Copath resolutions with the corresponding public keys.
        let copath_resolutions = self
            .filtered_copath_resolutions(own_leaf_index, exclusion_list)
            .into_iter()
            .map(|resolution| {
                resolution
                    .into_iter()
                    .map(|(_, node_ref)| match node_ref {
                        NodeReference::Leaf(leaf) => leaf.encryption_key().clone(),
                        NodeReference::Parent(parent) => parent.encryption_key().clone(),
                    })
                    .collect::<Vec<EncryptionKey>>()
            })
            .collect::<Vec<Vec<EncryptionKey>>>();

        // There should be as many copath resolutions.
        debug_assert_eq!(copath_resolutions.len(), path.len());

        // Encrypt the secrets

        #[cfg(not(target_arch = "wasm32"))]
        let resolved_path = path.par_iter().zip(copath_resolutions.par_iter());
        #[cfg(target_arch = "wasm32")]
        let resolved_path = path.iter().zip(copath_resolutions.iter());

        resolved_path
            .map(|(node, resolution)| node.encrypt(crypto, ciphersuite, resolution, group_context))
            .collect::<Result<Vec<UpdatePathNode>, LibraryError>>()
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
    /// ValSem203: Path secrets must decrypt correctly
    /// ValSem204: Public keys from Path must be verified and match the private keys from the direct path
    /// TODO #804
    pub(crate) fn decrypt_path(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        params: DecryptPathParams,
        owned_keys: &[&EncryptionKeyPair],
        own_leaf_index: LeafNodeIndex,
    ) -> Result<(Vec<EncryptionKeyPair>, CommitSecret), ApplyUpdatePathError> {
        let path_position = self
            .subtree_root_position(params.sender_leaf_index, own_leaf_index)
            .map_err(|_| LibraryError::custom("Expected own leaf to be in the tree"))?;

        let update_path_node = params
            .update_path
            .get(path_position)
            // We know the update path has the right length through validation, therefore there must be an element at this position
            // TODO #804
            .ok_or_else(|| LibraryError::custom("Expected to find ciphertext in update path 1"))?;

        let (decryption_key, resolution_position) = self
            .decryption_key(
                params.sender_leaf_index,
                params.exclusion_list,
                owned_keys,
                own_leaf_index,
            )
            // TODO #804
            .map_err(|_| LibraryError::custom("Expected sender to be in the tree"))?;

        let ciphertext = update_path_node
            .encrypted_path_secrets(resolution_position)
            // We know the update path has the right length through validation, therefore there must be a ciphertext at this position
            // TODO #804
            .ok_or_else(|| LibraryError::custom("Expected to find ciphertext in update path 2"))?;

        // ValSem203: Path secrets must decrypt correctly
        let path_secret = PathSecret::decrypt(
            crypto,
            ciphersuite,
            ciphertext,
            decryption_key,
            params.group_context,
        )
        .map_err(|_| ApplyUpdatePathError::UnableToDecrypt)?;

        let common_path =
            self.filtered_common_direct_path(own_leaf_index, params.sender_leaf_index);
        let (derived_path, _plain_update_path, keypairs, commit_secret) =
            ParentNode::derive_path(crypto, ciphersuite, path_secret, common_path)?;
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

        Ok((keypairs, commit_secret))
    }

    /// Prepare the [`EncryptedGroupSecrets`] for a number of `invited_members`
    /// based on a [`TreeSyncDiff`]. If a slice of [`PlainUpdatePathNode`] is
    /// given, they are included in the [`GroupSecrets`] of the path.
    ///
    /// Returns an error if
    ///  - the own node is outside the tree
    ///  - the invited members are not part of the tree yet
    ///  - the leaf index of a new member is identical to the own leaf index
    ///  - the plain path does not contain the correct secrets
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn encrypt_group_secrets(
        &self,
        joiner_secret: &JoinerSecret,
        invited_members: Vec<(LeafNodeIndex, AddProposal)>,
        plain_path_option: Option<&[PlainUpdatePathNode]>,
        presharedkeys: &[PreSharedKeyId],
        encrypted_group_info: &[u8],
        crypto: &impl OpenMlsCrypto,
        encryptor_leaf_index: LeafNodeIndex,
    ) -> Result<Vec<EncryptedGroupSecrets>, LibraryError> {
        let mut encrypted_group_secrets_vec = vec![];
        for (leaf_index, add_proposal) in invited_members {
            let key_package = add_proposal.key_package;

            let direct_path_position = self
                .subtree_root_position(encryptor_leaf_index, leaf_index)
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
            let ciphertext = hpke::encrypt_with_label(
                key_package.hpke_init_key().as_slice(),
                "Welcome",
                encrypted_group_info,
                &group_secrets_bytes,
                key_package.ciphersuite(),
                crypto,
            )
            .map_err(|_| {
                LibraryError::custom(
                    "Error while encrypting group secrets. \
                     This could have really only been a missing bounds check in \
                     the serialization",
                )
            })?;
            let encrypted_group_secrets =
                EncryptedGroupSecrets::new(key_package.hash_ref(crypto)?, ciphertext);
            encrypted_group_secrets_vec.push(encrypted_group_secrets);
        }
        Ok(encrypted_group_secrets_vec)
    }
}

pub(crate) struct DecryptPathParams<'a> {
    pub(crate) update_path: &'a [UpdatePathNode],
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
    Debug,
    Eq,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
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

    pub(crate) fn encryption_key(&self) -> &EncryptionKey {
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

/// 8.6. Update Paths
///
/// ```text
/// struct {
///     LeafNode leaf_node;
///     UpdatePathNode nodes<V>;
/// } UpdatePath;
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
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

    /// Return the `nodes` of this [`UpdatePath`].
    pub(crate) fn nodes(&self) -> &[UpdatePathNode] {
        &self.nodes
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

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct UpdatePathIn {
    leaf_node: LeafNodeIn,
    nodes: Vec<UpdatePathNode>,
}

impl UpdatePathIn {
    /// Return the `leaf_node` of this [`UpdatePath`].
    pub(crate) fn leaf_node(&self) -> &LeafNodeIn {
        &self.leaf_node
    }

    /// Return a verified [`UpdatePath`].
    pub(crate) fn into_verified(
        self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        tree_position: TreePosition,
    ) -> Result<UpdatePath, UpdatePathError> {
        let leaf_node_in = self.leaf_node().clone();
        let verifiable_leaf_node = leaf_node_in.into_verifiable_leaf_node();

        // [valn1207](https://validation.openmls.tech/#valn1207)
        match verifiable_leaf_node {
            // https://validation.openmls.tech/#valn1208
            VerifiableLeafNode::Commit(mut commit_leaf_node) => {
                let pk = &commit_leaf_node
                    .signature_key()
                    .clone()
                    .into_signature_public_key_enriched(ciphersuite.signature_algorithm());
                commit_leaf_node.add_tree_position(tree_position);

                let leaf_node: LeafNode = commit_leaf_node.verify(crypto, pk)?;
                Ok(UpdatePath {
                    leaf_node,
                    nodes: self.nodes,
                })
            }
            VerifiableLeafNode::Update(_) | VerifiableLeafNode::KeyPackage(_) => {
                Err(UpdatePathError::InvalidType)
            }
        }
    }
}

// The following `From` implementation( breaks abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
#[cfg(any(feature = "test-utils", test))]
impl From<UpdatePathIn> for UpdatePath {
    fn from(update_path_in: UpdatePathIn) -> Self {
        Self {
            leaf_node: update_path_in.leaf_node.into(),
            nodes: update_path_in.nodes,
        }
    }
}

impl From<UpdatePath> for UpdatePathIn {
    fn from(update_path: UpdatePath) -> Self {
        Self {
            leaf_node: update_path.leaf_node.into(),
            nodes: update_path.nodes,
        }
    }
}
