//! This module contains the [`ParentNode`] struct, its implementation, as well
//! as the [`PlainUpdatePathNode`], a helper struct for the creation of
//! [`UpdatePathNode`] instances.
use openmls_traits::{types::CryptoError, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsByteVecU8, TlsVecU32};

use crate::{
    binary_tree::LeafIndex,
    ciphersuite::{Ciphersuite, HpkePrivateKey, HpkePublicKey},
    messages::{PathSecret, PathSecretError},
    schedule::CommitSecret,
    treesync::{
        hashes::{ParentHashError, ParentHashInput},
        treekem::UpdatePathNode,
    },
};

/// This struct implements the MLS parent node. It contains its public key,
/// parent hash and unmerged leaves. Additionally, it may contain the private
/// key corresponding to the public key.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ParentNode {
    public_key: HpkePublicKey,
    parent_hash: TlsByteVecU8,
    unmerged_leaves: TlsVecU32<LeafIndex>,
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
        ciphersuite: &Ciphersuite,
        public_keys: &[HpkePublicKey],
        group_context: &[u8],
    ) -> UpdatePathNode {
        let mut encrypted_path_secrets = Vec::new();
        for pk in public_keys {
            let encrypted_path_secret =
                self.path_secret
                    .encrypt(backend, ciphersuite, pk, group_context);
            encrypted_path_secrets.push(encrypted_path_secret);
        }
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
        ciphersuite: &Ciphersuite,
        path_secret: PathSecret,
        path_length: usize,
    ) -> Result<PathDerivationResult, ParentNodeError> {
        let mut path = Vec::new();
        let mut update_path_nodes = Vec::new();
        let mut path_secret_option = Some(path_secret);
        for _ in 0..path_length {
            let path_secret = path_secret_option
                .take()
                .ok_or(ParentNodeError::LibraryError)?;
            let (public_key, private_key) = path_secret.derive_key_pair(backend, ciphersuite)?;
            let parent_node = (public_key.clone(), private_key).into();
            path.push(parent_node);
            // Derive the next path secret.
            path_secret_option = Some(path_secret.derive_path_secret(backend, ciphersuite)?);
            // Store the current path secret and the derived public key for
            // later encryption.
            let update_path_node = PlainUpdatePathNode {
                public_key,
                path_secret,
            };
            update_path_nodes.push(update_path_node);
        }
        let commit_secret = path_secret_option
            .take()
            .ok_or(ParentNodeError::LibraryError)?
            .into();
        Ok((path, update_path_nodes, commit_secret))
    }

    /// Return a reference to the `public_key` of this node.
    pub(crate) fn public_key(&self) -> &HpkePublicKey {
        &self.public_key
    }

    /// Return a reference to the potential `private_key` of this node.
    pub(in crate::treesync) fn private_key(&self) -> &Option<HpkePrivateKey> {
        &self.private_key_option
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
        ciphersuite: &Ciphersuite,
        parent_hash: &[u8],
        original_child_resolution: &[HpkePublicKey],
    ) -> Result<Vec<u8>, ParentNodeError> {
        let parent_hash_input =
            ParentHashInput::new(&self.public_key, parent_hash, original_child_resolution);
        Ok(parent_hash_input.hash(backend, ciphersuite)?)
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

implement_error! {
    pub enum ParentNodeError {
        Simple {
            LibraryError = "An unrecoverable error has occurred.",
        }
        Complex {
            CryptoError(CryptoError) = "An error occurred during key derivation.",
            DerivationError(PathSecretError) = "An error occurred during key derivation.",
            ParentHashError(ParentHashError) = "Error while computing parent hash.",
        }
    }
}
