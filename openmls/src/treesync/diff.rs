use openmls_traits::OpenMlsCryptoProvider;

use super::node::{Node, ParentNode, TreeSyncNode, TreeSyncNodeError};

use crate::{
    binary_tree::{LeafIndex, MlsBinaryTreeDiff, MlsBinaryTreeDiffError, StagedMlsBinaryTreeDiff},
    ciphersuite::{signable::Signable, Ciphersuite},
    credentials::{CredentialBundle, CredentialError},
    extensions::{Extension, ExtensionType, ParentHashExtension},
    prelude::{KeyPackage, KeyPackagePayload},
};

pub(crate) struct StagedTreeSyncDiff {
    diff: StagedMlsBinaryTreeDiff<TreeSyncNode>,
    new_tree_hash: Vec<u8>,
}

pub(crate) struct TreeSyncDiff<'a> {
    diff: MlsBinaryTreeDiff<'a, TreeSyncNode>,
}

/// Note: Any function that modifies a node should erase the tree hash of every
/// node in its direct path.
impl<'a> TreeSyncDiff<'a> {
    /// Update a leaf node and blank the nodes in the updated leaf's direct path.
    fn update_leaf(
        &mut self,
        leaf_node: KeyPackage,
        leaf_index: LeafIndex,
    ) -> Result<(), MlsBinaryTreeDiffError> {
        self.diff
            .replace_leaf(leaf_index, Node::LeafNode(leaf_node).into())?;
        // This effectively wipes the tree hashes in the direct path.
        self.diff.set_direct_path(leaf_index, None)?;
        Ok(())
    }

    /// Adds a new leaf to the tree either by filling a blank leaf or by
    /// creating a new leaf, inserting intermediate blanks as necessary. This
    /// also adds the leaf_index of the new leaf to the `unmerged_leaves` state
    /// of the parent nodes in its direct path.
    fn add_leaf(&mut self, leaf_node: KeyPackage) -> Result<(), TreeSyncDiffError> {
        // Add the new leaf to the tree.
        let leaf_index = if let Some(leaf_index) = self.diff.get_empty_leaf()? {
            self.diff
                .replace_leaf(leaf_index, Node::LeafNode(leaf_node).into())?;
            leaf_index
        } else {
            self.diff.add_leaf(Node::LeafNode(leaf_node).into())?
        };
        // Add new unmerged leaves entry to all nodes in direct path. Also, wipe
        // the cached tree hash.
        let add_unmerged_leaf = |tsn: &mut TreeSyncNode| -> Result<(), TreeSyncDiffError> {
            if let Some(ref mut node) = tsn.node_mut() {
                let pn = node.as_parent_node_mut()?;
                pn.add_unmerged_leaf(leaf_index);
            }
            tsn.erase_tree_hash();
            Ok(())
        };
        self.diff
            .apply_to_direct_path(leaf_index, add_unmerged_leaf)?;
        Ok(())
    }

    /// Remove a group member by blanking the target leaf and its direct path.
    fn remove_leaf(&mut self, leaf_index: LeafIndex) -> Result<(), MlsBinaryTreeDiffError> {
        self.diff.replace_leaf(leaf_index, TreeSyncNode::blank())?;
        // This also erases any cached tree hash.
        self.diff.set_direct_path(leaf_index, None)?;
        Ok(())
    }

    pub(crate) fn own_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        leaf_index: LeafIndex,
        mut key_package_payload: KeyPackagePayload,
        credential_bundle: &CredentialBundle,
        // FIXME: This should probably be a slice, since the path is needed to
        // prepare the commit as well. Same for the function below.
        mut path: Vec<ParentNode>,
    ) -> Result<KeyPackage, TreeSyncDiffError> {
        let parent_hash = self.process_update_path(backend, ciphersuite, leaf_index, path)?;

        let parent_hash_extension = Extension::ParentHash(ParentHashExtension::new(&parent_hash));
        key_package_payload.add_extension(parent_hash_extension);
        let key_package = key_package_payload.sign(backend, credential_bundle)?;

        // Replace the leaf.
        self.diff
            .replace_leaf(leaf_index, Node::LeafNode(key_package.clone()).into())?;
        Ok(key_package)
    }

    pub(crate) fn receive_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        leaf_index: LeafIndex,
        key_package: &KeyPackage,
        mut path: Vec<ParentNode>,
    ) -> Result<(), TreeSyncDiffError> {
        let parent_hash = self.process_update_path(backend, ciphersuite, leaf_index, path)?;
        // Verify the parent hash.
        let phe = key_package
            .extension_with_type(ExtensionType::ParentHash)
            .ok_or(TreeSyncDiffError::MissingParentHash)?;
        if phe
            .as_parent_hash_extension()
            .map_err(|_| TreeSyncDiffError::LibraryError)?
            .parent_hash()
            != parent_hash
        {
            return Err(TreeSyncDiffError::ParentHashMismatch);
        };

        // Replace the leaf.
        self.diff
            .replace_leaf(leaf_index, Node::LeafNode(key_package.clone()).into())?;
        Ok(())
    }

    /// Process a given update path, consisting of a vector of `Node`. This
    /// function
    /// * replaces the nodes in the direct path of the given `leaf_node` with
    /// the the ones in `path` and
    /// * computes the `parent_hash` of all nodes in the path and compares it to
    /// the one in the `leaf_node`.
    fn process_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        leaf_index: LeafIndex,
        mut path: Vec<ParentNode>,
    ) -> Result<Vec<u8>, TreeSyncDiffError> {
        // Compute the parent hash.
        let parent_hash = self.set_parent_hashes(backend, ciphersuite, &mut path, leaf_index)?;
        // Set the direct path.
        let direct_path = path
            .drain(..)
            .map(|node| Node::ParentNode(node).into())
            .collect();
        // Set the direct path. Note, that the nodes here don't have a tree hash
        // set.
        self.diff.set_direct_path(leaf_index, Some(direct_path))?;
        Ok(parent_hash)
    }

    /// Set the parent hash of the given nodes assuming that they are the new
    /// direct path of the leaf with the given index and return the parent hash
    /// of the leaf node. This function requires that all nodes in the direct
    /// path are non-blank.
    fn set_parent_hashes(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        path: &mut [ParentNode],
        leaf_index: LeafIndex,
    ) -> Result<Vec<u8>, TreeSyncDiffError> {
        // If the path is empty, return a zero-length string.
        if path.is_empty() {
            return Ok(Vec::new());
        }

        // Get the resolutions of the copath nodes (i.e. the original child
        // resolutions).
        let mut copath_resolutions = self.diff.copath_resolutions(leaf_index)?;
        // There should be as many copath resolutions as nodes in the direct
        // path.
        if path.len() != copath_resolutions.len() {
            return Err(TreeSyncDiffError::PathLengthError);
        }
        // We go through the nodes in the direct path in reverse order and get
        // the corresponding copath resolution for each node.
        let mut previous_parent_hash = vec![];
        for (path_node, resolution) in path
            .iter_mut()
            .rev()
            .zip(copath_resolutions.iter_mut().rev())
        {
            // Filter out the node's unmerged leaves before hashing.
            for leaf_index in path_node.unmerged_leaves() {
                let leaf_option = self
                    .diff
                    .leaf(*leaf_index)
                    .ok_or(MlsBinaryTreeDiffError::NodeNotFound)?;
                // All unmerged leaves should be non-blank.
                let leaf_node = leaf_option
                    .node()
                    .as_ref()
                    .ok_or(TreeSyncDiffError::LibraryError)?;
                let leaf = leaf_node.as_leaf_node()?;
                if let Some(position) = resolution
                    .iter()
                    .position(|bytes| bytes == leaf.hpke_init_key())
                {
                    resolution.remove(position);
                };
            }
            path_node.set_parent_hash(backend, ciphersuite, &previous_parent_hash, resolution)?;
            previous_parent_hash = path_node.parent_hash().to_vec()
        }
        // The final hash is the one of the leaf's parent.
        Ok(previous_parent_hash)
    }
}

implement_error! {
    pub enum TreeSyncDiffError {
        Simple {
            LibraryError = "An unrecoverable error has occurred.",
            PathLengthError = "The given path does not have the length of the given leaf's direct path.",
            MissingParentHash = "The given key package does not contain a parent hash extension.",
            ParentHashMismatch = "The parent hash of the given key package is invalid.",
        }
        Complex {
            TreeSyncNodeError(TreeSyncNodeError) = "We found a node with an unexpected type.",
            TreeDiffError(MlsBinaryTreeDiffError) = "An error occurred while operating on the diff.",
            CredentialError(CredentialError) = "An error occurred while signing a `KeyPackage`.",
        }
    }
}
