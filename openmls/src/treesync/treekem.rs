use tls_codec::{Size, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU32};

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{CryptoError, HpkeCiphertext},
    OpenMlsCryptoProvider,
};
pub(crate) use serde::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafIndex,
    ciphersuite::{Ciphersuite, HpkePublicKey},
    messages::{PathSecret, PathSecretError},
    prelude::KeyPackage,
    schedule::CommitSecret,
};

use super::{
    node::parent_node::{ParentNode, ParentNodeError, PlainUpdatePathNode},
    TreeSync, TreeSyncDiffError,
};

impl TreeSync {
    pub(crate) fn encrypt_path(
        &self,
        backend: &impl OpenMlsCrypto,
        ciphersuite: &Ciphersuite,
        path: &[PlainUpdatePathNode],
        group_context: &[u8],
        exclusion_list: &[LeafIndex],
        key_package: &KeyPackage,
    ) -> Result<UpdatePath, TreeKemError> {
        let copath_resolutions = self
            .empty_diff()
            .copath_resolutions(self.own_leaf_index, exclusion_list)?;
        // Make sure that the lists have the same length.
        if path.len() != copath_resolutions.len() {
            return Err(TreeKemError::PathLengthError);
        }

        let mut update_path_nodes = Vec::new();
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

    pub(crate) fn decrypt_path(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &'static Ciphersuite,
        update_path: &UpdatePath,
        sender_leaf_index: LeafIndex,
        exclusion_list: &[LeafIndex],
        group_context: &[u8],
    ) -> Result<(Vec<ParentNode>, CommitSecret), TreeKemError> {
        // Create a diff that we can operate on. FIXME: A recurring problem is
        // that we need the same functions from Diff and Tree.
        let diff = self.empty_diff();
        let path_position = diff.subtree_root_position(sender_leaf_index)?;
        let update_path_node = update_path
            .nodes()
            .get(path_position)
            .ok_or(TreeKemError::UpdatePathNodeNotFound)?;

        let (decryption_key, resolution_position) =
            diff.decryption_key(sender_leaf_index, exclusion_list)?;

        let ciphertext = update_path_node
            .get_encrypted_ciphertext(resolution_position)
            .ok_or(TreeKemError::EncryptedCiphertextNotFound)?;

        let path_secret = PathSecret::decrypt(
            backend,
            ciphersuite,
            ciphertext,
            decryption_key,
            group_context,
        )?;

        // Now we prepare the path. The first part comes from the public keys in
        // the UpdatePath and the second we can derive from the PathSecret.
        let mut path = Vec::new();
        for update_path_node in update_path.nodes().iter().take(path_position) {
            // The path_position should be inside of the path. Otherwise we
            // wouldn've errored out earlier.
            let parent_node = update_path_node.public_key().clone().into();
            path.push(parent_node);
        }
        let remaining_path_length = update_path.nodes().len() - path_position;
        let (mut derived_path, _plain_update_path, commit_secret) =
            ParentNode::derive_path(backend, ciphersuite, path_secret, remaining_path_length)?;
        path.append(&mut derived_path);

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
    pub(crate) public_key: HpkePublicKey,
    pub(crate) encrypted_path_secrets: TlsVecU32<HpkeCiphertext>,
}

impl UpdatePathNode {
    fn get_encrypted_ciphertext(&self, ciphertext_index: usize) -> Option<&HpkeCiphertext> {
        self.encrypted_path_secrets.get(ciphertext_index)
    }

    fn public_key(&self) -> &HpkePublicKey {
        &self.public_key
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
    /// Create a new update path.
    fn new(leaf_key_package: KeyPackage, nodes: Vec<UpdatePathNode>) -> Self {
        Self {
            leaf_key_package,
            nodes: nodes.into(),
        }
    }

    fn nodes(&self) -> &TlsVecU32<UpdatePathNode> {
        &self.nodes
    }
}

implement_error! {
    pub enum TreeKemError {
        Simple {
            LibraryError = "An inconsistency in the internal state of the tree was detected.",
            PathLengthError = "The given path to encrypt does not have the same length as the direct path.",
            UpdatePathNodeNotFound = "Couldn't find our UpdatePathNode in the given UpdatePath.",
            EncryptedCiphertextNotFound = "Couldn't find a matching encrypted ciphertext in the given UpdatePathNode.",
        }
        Complex {
            TreeSyncError(TreeSyncDiffError) = "Error while retrieving public keys from the tree.",
            PathSecretError(PathSecretError) = "Error decrypting PathSecret.",
            PathDerivationError(ParentNodeError) = "Error deriving path from PathSecret.",
        }
    }
}
