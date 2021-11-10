use hpke::HpkePublicKey;
use openmls_traits::OpenMlsCryptoProvider;

use super::node::{TreeSyncNode, TreeSyncNodeError};

use crate::{
    binary_tree::{
        Addressable, LeafIndex, MlsBinaryTreeDiff, MlsBinaryTreeDiffError, StagedMlsBinaryTreeDiff,
    },
    prelude::KeyPackage,
};

pub(crate) struct StagedTreeSyncDiff {
    diff: StagedMlsBinaryTreeDiff<Option<TreeSyncNode>>,
}

pub(crate) struct TreeSyncDiff<'a> {
    diff: MlsBinaryTreeDiff<'a, Option<TreeSyncNode>>,
    new_tree_hash: Vec<u8>,
}

impl<'a> TreeSyncDiff<'a> {
    /// Update a leaf node and blank the nodes in the updated leaf's direct path.
    fn update_leaf(
        &mut self,
        leaf_node: KeyPackage,
        leaf_index: LeafIndex,
    ) -> Result<(), MlsBinaryTreeDiffError> {
        self.diff
            .replace_leaf(leaf_index, Some(TreeSyncNode::LeafNode(leaf_node)))?;
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
                .replace_leaf(leaf_index, Some(TreeSyncNode::LeafNode(leaf_node)))?;
            leaf_index
        } else {
            self.diff
                .add_leaf(Some(TreeSyncNode::LeafNode(leaf_node)))?
        };
        // Get vector with mutable references.
        //let direct_path = self.diff.direct_path_mut(leaf_index)?;
        // Add new unmerged leaves entry to all nodes in direct path.
        let add_unmerged_leaf =
            |node_option: &mut Option<TreeSyncNode>| -> Result<(), TreeSyncDiffError> {
                if let Some(node) = node_option {
                    let pn = node.as_parent_node_mut()?;
                    pn.add_unmerged_leaf(leaf_index);
                }
                Ok(())
            };
        self.diff
            .apply_to_direct_path(leaf_index, add_unmerged_leaf)?;
        Ok(())
    }

    /// Remove a group member by blanking the target leaf and its direct path.
    fn remove_leaf(&mut self, leaf_index: LeafIndex) -> Result<(), MlsBinaryTreeDiffError> {
        self.diff.replace_leaf(leaf_index, None)?;
        self.diff.set_direct_path(leaf_index, None)?;
        Ok(())
    }

    /// Process a given update path, consisting of a vector of `Node`. This
    /// function
    /// * replaces the nodes in the direct path of the given `leaf_node` with
    /// the the ones in `path` and
    /// * computes the `parent_hash` of all nodes in the path and compares it to
    /// the one in the `leaf_node`.
    fn update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        leaf_index: LeafIndex,
        mut leaf_node: KeyPackage,
        path: &[Option<TreeSyncNode>],
    ) -> Result<(), TreeSyncDiffError> {
        // Set the direct path.
        self.diff.set_direct_path(leaf_index, Some(path))?;
        // Compute the parent hash.
        let parent_hash = self.set_parent_hashes(backend, leaf_index)?;
        // FIXME: Update key package before replacing.
        // Replace the leaf.
        self.diff
            .replace_leaf(leaf_index, Some(TreeSyncNode::LeafNode(leaf_node)))?;
        Ok(())
    }

    /// Set the parent hash of the nodes in the direct path of the leaf with the
    /// given index and set the resulting value in the leaf's
    /// `ParentHashExtension`. This function requires that all nodes in the
    /// direct path are non-blank.
    fn set_parent_hashes(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        leaf_index: LeafIndex,
    ) -> Result<(), TreeSyncDiffError> {
        // This serves as an intermediate place to store original child resolutions
        // during the update process.
        let mut original_child_resolutions: Vec<Vec<Vec<u8>>> = Vec::new();
        let mut direct_path = self.diff.direct_path(leaf_index)?;
        for node in &direct_path {
            let address = node.address().ok_or(MlsBinaryTreeDiffError::NodeNotFound)?;
            let ocr = self.diff.sibling_resolution(&address)?;
            original_child_resolutions.push(ocr);
        }
        let direct_path_len = direct_path.len();
        for _ in 0..direct_path_len {
            let node_option = direct_path
                .pop()
                // This shouldn't be none as we're iterating as many times as
                // the direct path has elements.
                .ok_or(MlsBinaryTreeDiffError::LibraryError)?;
            // TODO: Make this use `apply_to_direct_path` instead.
            todo!();
            //let node = node_option
            //    .as_ref()
            //    // This shouldn't be none, as we require nodes in the direct
            //    // path to be non-blank.
            //    .ok_or(MlsBinaryTreeDiffError::NodeNotFound)?
            //    .as_parent_node_mut()?;
            //let mut ocr = original_child_resolutions
            //    .pop()
            //    .ok_or(MlsBinaryTreeDiffError::LibraryError)?;
            //let mut unmerged_leaf_pks = Vec::new();
            //for leaf_index in node.unmerged_leaves() {
            //    let leaf = self
            //        .diff
            //        .leaf(*leaf_index)
            //        .ok_or(MlsBinaryTreeDiffError::NodeNotFound)?;
            //    let leaf_node = leaf
            //        .as_ref()
            //        // If this happens, the tree/diff was invalid.
            //        .ok_or(MlsBinaryTreeDiffError::LibraryError)?;
            //    let key_package = leaf_node.as_leaf_node()?;
            //    unmerged_leaf_pks.push(key_package.hpke_init_key().as_slice());
            //}
            //let filtered_ocr: Vec<Vec<u8>> = ocr
            //    .drain(..)
            //    .filter(|pk| !unmerged_leaf_pks.contains(&pk.as_slice()))
            //    .collect();
            //let node_hash =
        }
        todo!()
    }

    pub(crate) fn set_parent_hash(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        // Hash of the parent of this node.
        hash_of_parent: &[u8],
        node: &TreeSyncNode,
        // Resolution of the child of this node that is not updated.
        original_child_resolution: &[HpkePublicKey],
    ) -> Vec<u8> {
        // This is P.
        // 1. Create P's `ParentHashInput` struct. We need:
        //   * P's HpkePublicKey
        //   * The the hash of P's parent
        //   * The original child resolution of the child that is not being
        //     updated right now.
        //   * Filter P's unmerged leaves out of the original_child_resolution
        todo!()
    }

    /// Compute the tree hash of the TreeSync instance we would get when merging
    /// the diff.
    fn tree_hash(&self) -> Vec<u8> {
        todo!()
    }
}

implement_error! {
    pub enum TreeSyncDiffError {
        Simple {
            LibraryError = "An unrecoverable error has occurred.",
        }
        Complex {
            TreeSyncNodeError(TreeSyncNodeError) = "We found a node with an unexpected type.",
            TreeDiffError(MlsBinaryTreeDiffError) = "An error occurred while operating on the diff.",
        }
    }
}
