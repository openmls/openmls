use hpke::HpkePublicKey;
use openmls_traits::OpenMlsCryptoProvider;

use super::node::{Node, TreeSyncNode, TreeSyncNodeError};

use crate::{
    binary_tree::{
        Addressable, LeafIndex, MlsBinaryTreeDiff, MlsBinaryTreeDiffError, StagedMlsBinaryTreeDiff,
    },
    ciphersuite::Ciphersuite,
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
        ciphersuite: &Ciphersuite,
        leaf_index: LeafIndex,
        mut leaf_node: KeyPackage,
        mut path: Vec<Node>,
    ) -> Result<(), TreeSyncDiffError> {
        // Compute the parent hash.
        let parent_hash = self.set_parent_hashes(backend, ciphersuite, &mut path, leaf_index)?;
        let direct_path = path
            .drain(..)
            .map(|node| Some(TreeSyncNode::ParentNode(node)))
            .collect();
        // Set the direct path.
        self.diff.set_direct_path(leaf_index, Some(direct_path))?;

        // FIXME: Update key package before replacing.
        // Replace the leaf.
        self.diff
            .replace_leaf(leaf_index, Some(TreeSyncNode::LeafNode(leaf_node)))?;
        Ok(())
    }

    /// Set the parent hash of the given nodes assuming that they are the new
    /// direct path of the leaf with the given index and return the parent hash
    /// of the leaf node. This function requires that all nodes in the direct
    /// path are non-blank.
    fn set_parent_hashes(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        path: &mut [Node],
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
                    .as_ref()
                    .ok_or(TreeSyncDiffError::LibraryError)?;
                let leaf = leaf_node.as_leaf_node()?;
                let pk = leaf.hpke_init_key().as_slice();
                if let Some(position) = resolution.iter().position(|bytes| bytes == pk) {
                    resolution.remove(position);
                };
            }
            path_node.set_parent_hash(backend, ciphersuite, &previous_parent_hash, resolution);
            previous_parent_hash = path_node.parent_hash().to_vec()
        }
        // The final hash is the one of the leaf's parent.
        Ok(previous_parent_hash)
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
            PathLengthError = "The given path does not have the length of the given leaf's direct path.",
        }
        Complex {
            TreeSyncNodeError(TreeSyncNodeError) = "We found a node with an unexpected type.",
            TreeDiffError(MlsBinaryTreeDiffError) = "An error occurred while operating on the diff.",
        }
    }
}
