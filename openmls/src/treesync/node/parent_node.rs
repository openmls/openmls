//! This module contains the [`ParentNode`] struct, its implementation, as well
//! as the [`PlainUpdatePathNode`], a helper struct for the creation of
//! [`UpdatePathNode`] instances.
use openmls_traits::{
    types::{Ciphersuite, HpkeCiphertext},
    OpenMlsCryptoProvider,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tls_codec::{TlsByteVecU8, TlsVecU32};

use crate::{
    binary_tree::LeafIndex,
    ciphersuite::{HpkePrivateKey, HpkePublicKey},
    error::LibraryError,
    messages::PathSecret,
    schedule::CommitSecret,
    treesync::{hashes::ParentHashInput, treekem::UpdatePathNode},
};

/// This struct implements the MLS parent node. It contains its public key,
/// parent hash and unmerged leaves. Additionally, it may contain the private
/// key corresponding to the public key.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ParentNode {
    pub(super) public_key: HpkePublicKey,
    pub(super) parent_hash: TlsByteVecU8,
    pub(super) unmerged_leaves: TlsVecU32<LeafIndex>,
    private_key_option: Option<HpkePrivateKey>,
}

impl From<(HpkePublicKey, HpkePrivateKey)> for ParentNode {
    fn from((public_key, private_key): (HpkePublicKey, HpkePrivateKey)) -> Self {
        let mut parent_node: ParentNode = public_key.into();
        parent_node.set_private_key(private_key);
        parent_node
    }
}

impl From<HpkePublicKey> for ParentNode {
    fn from(public_key: HpkePublicKey) -> Self {
        Self {
            public_key,
            parent_hash: vec![].into(),
            unmerged_leaves: vec![].into(),
            private_key_option: None,
        }
    }
}

/// Helper struct for the encryption of a [`ParentNode`].
#[derive(Debug)]
pub(crate) struct PlainUpdatePathNode {
    public_key: HpkePublicKey,
    path_secret: PathSecret,
}

impl PlainUpdatePathNode {
    /// Encrypt this node and return the resulting [`UpdatePathNode`].
    pub(in crate::treesync) fn encrypt(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        public_keys: &[HpkePublicKey],
        group_context: &[u8],
    ) -> UpdatePathNode {
        let encrypted_path_secrets: Vec<HpkeCiphertext> = public_keys
            .par_iter()
            .map(|pk| {
                self.path_secret
                    .encrypt(backend, ciphersuite, pk, group_context)
            })
            .collect();

        UpdatePathNode {
            public_key: self.public_key.clone(),
            encrypted_path_secrets: encrypted_path_secrets.into(),
        }
    }

    /// Return a reference to the `path_secret` of this node.
    pub(in crate::treesync) fn path_secret(&self) -> &PathSecret {
        &self.path_secret
    }
}

/// The result of a path derivation result containing the vector of
/// [`ParentNode`], as well as [`PlainUpdatePathNode`] instance and a
/// [`CommitSecret`].
pub(in crate::treesync) type PathDerivationResult =
    (Vec<ParentNode>, Vec<PlainUpdatePathNode>, CommitSecret);

impl ParentNode {
    /// Create a new [`ParentNode`].
    pub(super) fn new(
        public_key: HpkePublicKey,
        parent_hash: TlsByteVecU8,
        unmerged_leaves: TlsVecU32<u32>,
    ) -> Self {
        Self {
            public_key,
            parent_hash,
            unmerged_leaves,
            private_key_option: None,
        }
    }

    /// Derives a path from the given path secret, where the `node_secret` of
    /// the first node is immediately derived from the given `path_secret`.
    ///
    /// Returns the resulting vector of [`ParentNode`] instances, as well as the
    /// intermediary `PathSecret`s and the [`CommitSecret`].
    pub(crate) fn derive_path(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        path_secret: PathSecret,
        path_length: usize,
    ) -> Result<PathDerivationResult, LibraryError> {
        let mut next_path_secret = path_secret;
        let mut path_secrets = Vec::new();

        for _ in 0..path_length {
            let path_secret = next_path_secret;
            // Derive the next path secret.
            next_path_secret = path_secret.derive_path_secret(backend, ciphersuite)?;
            path_secrets.push(path_secret);
        }

        // Iterate over the path secrets and derive a key pair
        let (path, update_path_nodes) = path_secrets
            .into_par_iter()
            .map(|path_secret| {
                // Derive a key pair from the path secret. This includes the
                // intermediate derivation of a node secret.
                let (public_key, private_key) =
                    path_secret.derive_key_pair(backend, ciphersuite)?;
                let parent_node = ParentNode::from((public_key.clone(), private_key));
                // Store the current path secret and the derived public key for
                // later encryption.
                let update_path_node = PlainUpdatePathNode {
                    public_key,
                    path_secret,
                };
                Ok((parent_node, update_path_node))
            })
            .collect::<Result<Vec<(ParentNode, PlainUpdatePathNode)>, LibraryError>>()?
            .into_iter()
            .unzip();

        let commit_secret = next_path_secret.into();
        Ok((path, update_path_nodes, commit_secret))
    }

    /// Return a reference to the `public_key` of this node.
    pub(crate) fn public_key(&self) -> &HpkePublicKey {
        &self.public_key
    }

    /// Return a reference to the potential `private_key` of this node.
    pub(in crate::treesync) fn private_key(&self) -> Option<&HpkePrivateKey> {
        self.private_key_option.as_ref()
    }

    /// Set the `private_key` of this node to the given key.
    pub(in crate::treesync) fn set_private_key(&mut self, private_key: HpkePrivateKey) {
        self.private_key_option = Some(private_key)
    }

    /// Get the list of unmerged leaves.
    pub(in crate::treesync) fn unmerged_leaves(&self) -> &[LeafIndex] {
        self.unmerged_leaves.as_slice()
    }

    /// Add a [`LeafIndex`] to the node's list of unmerged leaves.
    pub(in crate::treesync) fn add_unmerged_leaf(&mut self, leaf_index: LeafIndex) {
        self.unmerged_leaves.push(leaf_index)
    }

    /// Compute the parent hash value of this node.
    pub(in crate::treesync) fn compute_parent_hash(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        parent_hash: &[u8],
        original_child_resolution: &[HpkePublicKey],
    ) -> Result<Vec<u8>, LibraryError> {
        let parent_hash_input =
            ParentHashInput::new(&self.public_key, parent_hash, original_child_resolution);
        parent_hash_input.hash(backend, ciphersuite)
    }

    /// Set the `parent_hash` of this node.
    pub(in crate::treesync) fn set_parent_hash(&mut self, parent_hash: Vec<u8>) {
        self.parent_hash = parent_hash.into()
    }

    /// Get the parent hash value of this node.
    pub(crate) fn parent_hash(&self) -> &[u8] {
        self.parent_hash.as_slice()
    }

    /// Create and return a clone of this node without any potentially contained
    /// private key material.
    pub(in crate::treesync) fn clone_without_private_key(&self) -> Self {
        Self {
            public_key: self.public_key().clone(),
            parent_hash: self.parent_hash().to_vec().into(),
            unmerged_leaves: self.unmerged_leaves().to_vec().into(),
            private_key_option: None,
        }
    }
}
