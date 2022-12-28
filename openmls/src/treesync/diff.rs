//! This module provides the diff functionality for [`TreeSync`].
//!
//! # About
//!
//! This module provides the [`TreeSyncDiff`] struct, that allows mutable
//! operations on otherwise immutable [`TreeSync`] instances. It also provides
//! the [`StagedTreeSyncDiff`] struct, which has to be created from a
//! [`TreeSyncDiff`] before it can be merged in to the original [`TreeSync`]
//! instance.
//!
//!
//! # Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable
//! [`LibraryError`](TreeSyncDiffError::LibraryError). This means that some
//! functions that are not expected to fail and throw an error, will still
//! return a [`Result`] since they may throw a
//! [`LibraryError`](TreeSyncDiffError::LibraryError).
use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};

use std::collections::HashSet;

use super::{
    errors::*,
    node::{
        leaf_node::{LeafNode, OpenMlsLeafNode},
        parent_node::{ParentNode, PathDerivationResult, PlainUpdatePathNode},
        Node,
    },
    treesync_node::{TreeSyncLeafNode, TreeSyncNode, TreeSyncParentNode},
    TreeSync, TreeSyncParentHashError, TreeSyncSetPathError,
};

use crate::{
    binary_tree::{
        array_representation::{direct_path, LeafNodeIndex, ParentNodeIndex, TreeNodeIndex},
        MlsBinaryTreeDiff, StagedMlsBinaryTreeDiff,
    },
    ciphersuite::{HpkePrivateKey, HpkePublicKey, Secret},
    credentials::CredentialBundle,
    error::LibraryError,
    group::GroupId,
    messages::PathSecret,
    schedule::CommitSecret,
};

pub(crate) type UpdatePathResult = (Vec<PlainUpdatePathNode>, CommitSecret);

/// The [`StagedTreeSyncDiff`] can be created from a [`TreeSyncDiff`], examined
/// and later merged into a [`TreeSync`] instance.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StagedTreeSyncDiff {
    own_leaf_index: LeafNodeIndex,
    diff: StagedMlsBinaryTreeDiff<TreeSyncLeafNode, TreeSyncParentNode>,
    new_tree_hash: Vec<u8>,
}

impl StagedTreeSyncDiff {
    pub(super) fn into_parts(
        self,
    ) -> (
        LeafNodeIndex,
        StagedMlsBinaryTreeDiff<TreeSyncLeafNode, TreeSyncParentNode>,
        Vec<u8>,
    ) {
        (self.own_leaf_index, self.diff, self.new_tree_hash)
    }
}

/// A [`TreeSyncDiff`] serves as a way to perform changes on an otherwise
/// immutable [`TreeSync`] instance. Before the changes made to a
/// [`TreeSyncDiff`] can be merged into the original [`TreeSync`] instance, it
/// has to be turned into a [`StagedTreeSyncDiff`], upon which a number of
/// checks are performed to ensure that the changes preseve the [`TreeSync`]
/// invariants. See [`TreeSync`] for the list of invariants.
pub(crate) struct TreeSyncDiff<'a> {
    diff: MlsBinaryTreeDiff<'a, TreeSyncLeafNode, TreeSyncParentNode>,
    own_leaf_index: LeafNodeIndex,
}

impl<'a> From<&'a TreeSync> for TreeSyncDiff<'a> {
    fn from(tree_sync: &'a TreeSync) -> Self {
        TreeSyncDiff {
            diff: tree_sync.tree.empty_diff(),
            own_leaf_index: tree_sync.own_leaf_index,
        }
    }
}

impl<'a> TreeSyncDiff<'a> {
    /// Check if the right-most leaf and its parent are blank. If that is the
    /// case, remove the right-most leaf and its parent until either the
    /// right-most leaf or its parent are not blank anymore.
    pub(crate) fn trim_tree(&mut self) {
        // Nothing to trim if there's only one leaf left.
        if self.leaf_count() == 1 {
            return;
        }

        // We reverse the nodes here to make sure we start with the right-most
        let mut leaves = self
            .diff
            .leaves()
            .collect::<Vec<(LeafNodeIndex, &TreeSyncLeafNode)>>();
        leaves.reverse();
        let mut parents = self
            .diff
            .parents()
            .collect::<Vec<(ParentNodeIndex, &TreeSyncParentNode)>>();
        parents.reverse();

        let mut blank_leaf_counter = 0;

        for (leaf, parent) in leaves.iter().zip(parents.iter()) {
            if leaf.1.node().as_ref().is_none() && parent.1.node().as_ref().is_none() {
                // Both leaf & parent are blank, so we want to remove them.
                blank_leaf_counter += 1;
            } else {
                break;
            }
        }

        for _ in 0..blank_leaf_counter {
            debug_assert!(self.diff.remove_leaf().is_ok());
        }
    }

    /// Returns the number of leaves in the tree that would result from merging
    /// this diff.
    pub(crate) fn leaf_count(&self) -> u32 {
        self.diff.leaf_count()
    }

    /// Updates an existing leaf node and blanks the nodes in the updated leaf's
    /// direct path.
    ///
    /// Returns an error if the target leaf is blank or outside of the tree.
    pub(crate) fn update_leaf(&mut self, leaf_node: OpenMlsLeafNode, leaf_index: LeafNodeIndex) {
        self.diff.replace_leaf(leaf_index, leaf_node.into());
        // This effectively wipes the tree hashes in the direct path.
        self.diff
            .set_direct_path_to_node(leaf_index, &TreeSyncParentNode::blank());
    }

    /// Find and return the index of either the left-most blank leaf, or, if
    /// there are no blank leaves, the leaf count.
    pub(crate) fn free_leaf_index(&self) -> LeafNodeIndex {
        // Find a free leaf and fill it with the new key package.
        let mut leaf_index_option = None;
        for (leaf_index, leaf_id) in self.diff.leaves() {
            if leaf_id.node().is_none() {
                leaf_index_option = Some(leaf_index);
                break;
            }
        }
        // If we found a free leaf, replace it with the new one, otherwise
        // extend the tree.
        leaf_index_option.unwrap_or_else(|| LeafNodeIndex::new(self.leaf_count()))
    }

    /// Adds a new leaf to the tree either by filling a blank leaf or by
    /// extending the tree to the right to create a new leaf, inserting
    /// intermediate blanks as necessary. This also adds the leaf_index of the
    /// new leaf to the `unmerged_leaves` of the parent nodes in its direct
    /// path.
    ///
    /// Returns the LeafNodeIndex of the new leaf.
    pub(crate) fn add_leaf(
        &mut self,
        leaf_node: OpenMlsLeafNode,
    ) -> Result<LeafNodeIndex, TreeSyncAddLeaf> {
        // Find a free leaf and fill it with the new key package.
        let leaf_index = self.free_leaf_index();
        // If the free leaf index is within the tree, put the new leaf there,
        // otherwise extend the tree.
        if leaf_index.u32() < self.leaf_count() {
            self.diff.replace_leaf(leaf_index, leaf_node.into())
        } else {
            self.diff
                .add_leaf(TreeSyncParentNode::blank(), leaf_node.into())
                .map_err(|_| TreeSyncAddLeaf::TreeFull)?;
        }
        // Add new unmerged leaves entry to all nodes in direct path. Also, wipe
        // the cached tree hash.
        for parent_index in self.diff.direct_path(leaf_index) {
            // We know that the nodes from the direct path are in the tree
            let tsn = self.diff.parent_mut(parent_index);
            if let Some(ref mut parent_node) = tsn.node_mut() {
                parent_node.add_unmerged_leaf(leaf_index);
            }
            tsn.erase_tree_hash();
        }
        Ok(leaf_index)
    }

    /// Clear the tree hash (root and own leaf index).
    pub(crate) fn clear_tree_hash(&mut self) {
        match self.diff.root() {
            TreeNodeIndex::Leaf(leaf_index) => {
                self.diff.leaf_mut(leaf_index).erase_tree_hash();
            }
            TreeNodeIndex::Parent(parent_index) => {
                self.diff.parent_mut(parent_index).erase_tree_hash();
            }
        }
        self.diff.leaf_mut(self.own_leaf_index()).erase_tree_hash();
    }

    /// Set the `own_leaf_index` to `leaf_index`. This has to be used with
    /// caution, as it can invalidate the [`TreeSync`] invariants.
    pub(crate) fn set_own_index(&mut self, leaf_index: LeafNodeIndex) {
        self.own_leaf_index = leaf_index
    }

    /// Remove a group member by blanking the target leaf and its direct path.
    /// After blanking the leaf and its direct path, the diff is trimmed, i.e.
    /// leaves are removed until the right-most leaf in the tree, as well as its
    /// parent are non-blank.
    ///
    /// Returns an error if the target leaf is outside of the tree.
    pub(crate) fn blank_leaf(&mut self, leaf_index: LeafNodeIndex) {
        self.diff
            .replace_leaf(leaf_index, TreeSyncLeafNode::blank());
        // This also erases any cached tree hash in the direct path.
        self.diff
            .set_direct_path_to_node(leaf_index, &TreeSyncParentNode::blank());
        self.trim_tree();
    }

    /// Derive a new direct path for our own leaf.
    ///
    /// Returns an error if the own leaf is not in the tree
    fn derive_path(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<PathDerivationResult, LibraryError> {
        let path_secret = PathSecret::from(
            Secret::random(ciphersuite, backend, None)
                .map_err(LibraryError::unexpected_crypto_error)?,
        );

        let path_length = self.diff.direct_path(self.own_leaf_index).len();

        ParentNode::derive_path(backend, ciphersuite, path_secret, path_length)
    }

    /// Given a new [`OpenMlsLeafNode`], use it to create a new path and
    /// apply it to this diff. The given [`CredentialBundle`] reference is used
    /// to sign the [`OpenMlsLeafNode`] after updating its parent hash.
    ///
    /// Returns the [`CommitSecret`] and the path resulting from the path
    /// derivation, as well as the [`KeyPackage`].
    ///
    /// Returns an error if the own leaf is not in the tree.
    pub(crate) fn apply_own_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        group_id: GroupId,
        credential_bundle: &CredentialBundle,
    ) -> Result<UpdatePathResult, LibraryError> {
        debug_assert!(self.own_leaf().is_ok(), "Tree diff is missing own leaf");

        let (path, update_path_nodes, commit_secret) = self.derive_path(backend, ciphersuite)?;

        let parent_hash =
            self.process_update_path(backend, ciphersuite, self.own_leaf_index, path)?;

        self.own_leaf_mut()
            .map_err(|_| LibraryError::custom("Didn't find own leaf in diff."))?
            .update_parent_hash(&parent_hash, group_id, credential_bundle, backend)?;

        Ok((update_path_nodes, commit_secret))
    }

    /// Set the given path as the direct path of the `sender_leaf_index` and
    /// replace the [`KeyPackage`] in the corresponding leaf with the given one.
    /// The given path of ParentNodes should already include any potential path
    /// secrets.
    ///
    /// Returns an error if the `sender_leaf_index` is outside of the tree.
    /// TODO #804
    pub(crate) fn apply_received_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        sender_leaf_index: LeafNodeIndex,
        leaf_node: LeafNode,
        path: Vec<ParentNode>,
    ) -> Result<(), ApplyUpdatePathError> {
        let parent_hash =
            self.process_update_path(backend, ciphersuite, sender_leaf_index, path)?;

        // Verify the parent hash.
        let leaf_node_parent_hash = leaf_node
            .parent_hash()
            .ok_or(ApplyUpdatePathError::MissingParentHash)?;
        if leaf_node_parent_hash != parent_hash {
            return Err(ApplyUpdatePathError::ParentHashMismatch);
        };

        // Update the `encryption_key` in the leaf.
        let mut leaf: OpenMlsLeafNode = leaf_node.into();
        leaf.set_leaf_index(sender_leaf_index);
        self.diff.replace_leaf(sender_leaf_index, leaf.into());
        Ok(())
    }

    /// Process a given update path, consisting of a vector of `ParentNode`.
    /// This function replaces the nodes in the direct path of the given
    /// `leaf_index` with the the ones in `path`.
    ///
    /// Returns the parent hash of the leaf at `leaf_index`. Returns an error if
    /// the target leaf is outside of the tree.
    /// TODO #804
    fn process_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        leaf_index: LeafNodeIndex,
        mut path: Vec<ParentNode>,
    ) -> Result<Vec<u8>, LibraryError> {
        // Compute the parent hash.
        let parent_hash = self.set_parent_hashes(backend, ciphersuite, &mut path, leaf_index)?;
        let direct_path: Vec<TreeSyncParentNode> = path
            .into_iter()
            .map(|parent_node| parent_node.into())
            .collect();

        // Set the direct path. Note, that the nodes here don't have a tree hash
        // TODO #804
        // set.
        self.diff.set_direct_path(leaf_index, direct_path);
        Ok(parent_hash)
    }

    /// Set the path secrets, but doesn't otherwise touch the nodes. This
    /// function also checks that the derived public keys match the existing
    /// public keys.
    ///
    /// Returns the `CommitSecret` derived from the path secret of the root
    /// node. Returns an error if the target leaf is outside of the tree.
    ///
    /// Returns TreeSyncSetPathError::PublicKeyMismatch if the derived keys don't
    /// match with the existing ones.
    ///
    /// Returns TreeSyncSetPathError::LibraryError if the sender_index is not
    /// in the tree.
    pub(super) fn set_path_secrets(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        mut path_secret: PathSecret,
        sender_index: LeafNodeIndex,
    ) -> Result<CommitSecret, TreeSyncSetPathError> {
        // We assume both nodes are in the tree, since the sender_index must be in the tree
        let subtree_path = self.diff.subtree_path(self.own_leaf_index, sender_index);
        for parent_index in subtree_path {
            // We know the node is in the diff, since it is in the subtree path
            let tsn = self.diff.parent_mut(parent_index);
            // We only care about non-blank nodes.
            if let Some(ref mut parent_node) = tsn.node_mut() {
                // If our own leaf index is not in the list of unmerged leaves
                // then we should have the secret for this node.
                if !parent_node.unmerged_leaves().contains(&self.own_leaf_index) {
                    let (public_key, private_key) =
                        path_secret.derive_key_pair(backend, ciphersuite)?;
                    // The derived public key should match the one in the node.
                    // If not, the tree is corrupt.
                    if parent_node.public_key() != &public_key {
                        return Err(TreeSyncSetPathError::PublicKeyMismatch);
                    } else {
                        // If everything is ok, set the private key and derive
                        // the next path secret.
                        parent_node.set_private_key(private_key);
                        path_secret = path_secret.derive_path_secret(backend, ciphersuite)?;
                    }
                };
                // If the leaf is blank or our index is in the list of unmerged
                // leaves, go to the next node.
            }
        }
        Ok(path_secret.into())
    }

    /// A helper function that filters the unmerged leaves of the given node
    /// from the given resolution.
    ///
    /// Returns a LibraryError when the ParentNode is not in the tree or
    /// its unmerged leaves are not in the tree.
    fn filter_resolution(&self, parent_node: &ParentNode, resolution: &mut Vec<HpkePublicKey>) {
        for leaf_index in parent_node.unmerged_leaves() {
            let leaf = self.diff.leaf(*leaf_index);
            // All unmerged leaves should be non-blank.
            if let Some(leaf_node) = leaf.node() {
                if let Some(position) = resolution
                    .iter()
                    .position(|bytes| bytes == leaf_node.public_key())
                {
                    resolution.remove(position);
                };
            }
        }
    }

    /// Set the parent hash of the given nodes assuming that they are the new
    /// direct path of the leaf with the given index. This function requires
    /// that all nodes in the direct path are non-blank.
    ///
    /// Returns the parent hash of the leaf node at `leaf_index`. Returns an
    /// error if the target leaf is outside of the tree.
    fn set_parent_hashes(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        path: &mut [ParentNode],
        leaf_index: LeafNodeIndex,
    ) -> Result<Vec<u8>, LibraryError> {
        // If the path is empty, return a zero-length string. This is the case
        // when the tree has only one leaf.
        if path.is_empty() {
            return Ok(Vec::new());
        }

        // Get the resolutions of the copath nodes (i.e. the original child
        // resolutions).
        let mut copath_resolutions = self.copath_resolutions(leaf_index, &HashSet::new());
        // There should be as many copath resolutions as nodes in the direct
        // path.
        debug_assert_eq!(path.len(), copath_resolutions.len());
        // We go through the nodes in the direct path in reverse order and get
        // the corresponding copath resolution for each node.
        let mut previous_parent_hash = vec![];
        for (path_node, resolution) in path
            .iter_mut()
            .rev()
            .zip(copath_resolutions.iter_mut().rev())
        {
            path_node.set_parent_hash(previous_parent_hash);
            // Filter out the node's unmerged leaves before hashing.
            self.filter_resolution(path_node, resolution);
            let parent_hash = path_node.compute_parent_hash(
                backend,
                ciphersuite,
                path_node.parent_hash(),
                resolution.as_slice(),
            )?;
            previous_parent_hash = parent_hash
        }
        // The final hash is the one of the leaf's parent.
        Ok(previous_parent_hash)
    }

    /// Helper function computing the resolution of a node with the given index.
    /// If an exclusion list is given, do not add the public keys of the leaves
    /// given in the list.
    ///
    /// Returns The list of HPKE public keys.
    /// In case node_id is not in the tree a LibraryError is returned.
    fn resolution(
        &self,
        node_index: TreeNodeIndex,
        excluded_indices: &HashSet<&LeafNodeIndex>,
    ) -> Vec<HpkePublicKey> {
        // If it's a full node, check if it's a leaf.
        match node_index {
            TreeNodeIndex::Leaf(leaf_index) => {
                // If the node is a leaf, check if it is in the exclusion list.
                if excluded_indices.contains(&leaf_index) {
                    vec![]
                } else {
                    // If it's not, return its public key as its resolution.
                    if let Some(leaf) = self.diff.leaf(leaf_index).node() {
                        vec![leaf.public_key().clone()]
                    } else {
                        vec![]
                    }
                }
            }
            TreeNodeIndex::Parent(parent_index) => {
                match self.diff.parent(parent_index).node() {
                    Some(parent) => {
                        // If it's a non-blank parent node, get the unmerged
                        // leaves, exclude them as necessary and add their
                        // public keys to the resulting resolution.
                        let mut resolution = vec![parent.public_key().clone()];
                        for leaf_index in parent.unmerged_leaves() {
                            if !excluded_indices.contains(&leaf_index) {
                                let leaf = self.diff.leaf(*leaf_index);
                                // TODO #800: unmerged leaves should be checked
                                if let Some(leaf_node) = leaf.node() {
                                    resolution.push(leaf_node.public_key().clone())
                                }
                            }
                        }
                        resolution
                    }
                    None => {
                        // If it is a blank parent node, continue resolving
                        // down the tree.
                        let mut resolution = Vec::new();
                        let left_child = self.diff.left_child(parent_index);
                        let right_child = self.diff.right_child(parent_index);
                        resolution.append(&mut self.resolution(left_child, excluded_indices));
                        resolution.append(&mut self.resolution(right_child, excluded_indices));
                        resolution
                    }
                }
            }
        }
    }

    /// Compute the resolution of the copath of the leaf node corresponding to
    /// the given leaf index. This includes the neighbour of the given leaf. If
    /// an exclusion list is given, do not add the public keys of the leaves
    /// given in the list.
    ///
    /// Returns a vector containing the copath resolutions of the given
    /// `leaf_index` beginning with the neighbour of the leaf. Returns an error
    /// if the target leaf is outside of the tree.
    pub(crate) fn copath_resolutions(
        &self,
        leaf_index: LeafNodeIndex,
        excluded_indices: &HashSet<&LeafNodeIndex>,
    ) -> Vec<Vec<HpkePublicKey>> {
        // If we're the only node in the tree, there's no copath.
        if self.diff.leaf_count() == 1 {
            return vec![];
        }

        // We want the full path here, including the leaf itself, but not the
        // root.
        let mut full_path = vec![TreeNodeIndex::Leaf(leaf_index)];
        let mut direct_path = direct_path(leaf_index, self.diff.size());
        if !direct_path.is_empty() {
            // Remove root
            direct_path.pop();
        }
        full_path.append(
            &mut direct_path
                .iter()
                .map(|i| TreeNodeIndex::Parent(*i))
                .collect(),
        );

        let mut copath_resolutions = Vec::new();
        for node_index in self.diff.copath(leaf_index) {
            let resolution = self.resolution(node_index, excluded_indices);
            copath_resolutions.push(resolution);
        }
        copath_resolutions
    }

    /// Verify the parent hashes of all nodes in the tree.
    ///
    /// Returns TreeSyncParentHashError::InvalidParentHash if a
    /// mismatching parent hash is found or a LibraryError if the
    /// tree is malformed.
    pub(crate) fn verify_parent_hashes(
        &self,
        _backend: &impl OpenMlsCryptoProvider,
        _ciphersuite: Ciphersuite,
    ) -> Result<(), TreeSyncParentHashError> {
        // TODO #995: Implement new parent hash verification
        /* for (parent_index, parent_node) in self.diff.parents() {
            let left_child_id = self.diff.left_child(parent_index);
            let mut right_child_id = self.diff.right_child(parent_index);
            // If the left child is blank, we continue with the next step
            // in the verification algorithm.
            let left_child_node = match left_child_id {
                TreeNodeIndex::Leaf(leaf_index) => self.diff.leaf(leaf_index).node(),
                TreeNodeIndex::Parent(parent_index) => self.diff.parent(parent_index).node(),
            };
            if let Some(left_child) = left_child_node {
                let mut right_child_resolution = self.resolution(right_child_id, &HashSet::new());
                // Filter unmerged leaves from resolution.
                self.filter_resolution(parent_node, &mut right_child_resolution);
                let node_hash = parent_node.compute_parent_hash(
                    backend,
                    ciphersuite,
                    parent_node.parent_hash(),
                    &right_child_resolution,
                )?;
                if let Some(left_child_parent_hash) = left_child.parent_hash() {
                    if node_hash == left_child_parent_hash {
                        // If the hashes match, we continue with the next node.
                        continue;
                    };
                }
            }

            // If the right child is blank, replace it with its left child
            // until it's non-blank or a leaf.
            if let TreeNodeIndex::Parent(parent_index) = right_child_id {
                let mut right_child = parent_index;
                right_child_id = TreeNodeIndex::Parent(right_child);
                while self.diff.parent(right_child).node().is_none() {
                    match self.diff.left_child(parent_index) {
                        TreeNodeIndex::Parent(left_child) => {
                            right_child = left_child;
                        }
                        TreeNodeIndex::Leaf(leaf_index) => {
                            right_child_id = TreeNodeIndex::Leaf(leaf_index);
                            break;
                        }
                    }
                }
            }

            // If the "right child" is a non-blank node, we continue,
            // otherwise it has to be a blank leaf node and the check
            // fails.
            let right_child_node = match right_child_id {
                TreeNodeIndex::Leaf(leaf_index) => self
                    .diff
                    .leaf(leaf_index)
                    .node()
                    .map(|node| TreeNode::Leaf(node)),
                TreeNodeIndex::Parent(parent_index) => self
                    .diff
                    .parent(parent_index)
                    .node()
                    .map(|node| TreeNode::Parent(node)),
            };
            if let Some(right_child) = right_child_node {
                // Perform the check with the parent hash of the "right
                // child" and the left child resolution.
                let mut left_child_resolution = self.resolution(left_child_id, &HashSet::new());
                // Filter unmerged leaves from resolution.
                self.filter_resolution(parent_node, &mut left_child_resolution);
                let node_hash = parent_node.compute_parent_hash(
                    backend,
                    ciphersuite,
                    parent_node.parent_hash(),
                    &left_child_resolution,
                )?;
                if let Some(right_child_parent_hash) = right_child.parent_hash() {
                    if node_hash == right_child_parent_hash {
                        // If the hashes match, we continue with the next node.
                        continue;
                    };
                }
                // If the hash doesn't match, or the leaf doesn't have a
                // parent hash extension (the `None` case in the `if let`
                // above), the verification fails.
            }
            return Err(TreeSyncParentHashError::InvalidParentHash);
        } */
        // Clippy warning suppersion
        let _ = TreeSyncParentHashError::InvalidParentHash;
        Ok(())
    }

    /// This turns the diff into a staged diff. In the process, the diff
    /// computes and sets the new tree hash.
    pub(crate) fn into_staged_diff(
        mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<StagedTreeSyncDiff, LibraryError> {
        let new_tree_hash = self.compute_tree_hashes(backend, ciphersuite)?;
        debug_assert!(self.verify_parent_hashes(backend, ciphersuite).is_ok());
        Ok(StagedTreeSyncDiff {
            own_leaf_index: self.own_leaf_index,
            diff: self.diff.into(),
            new_tree_hash,
        })
    }

    /// Helper function to compute and set the tree hash of the given node and
    /// all nodes below it in the tree. This function respects cached tree hash
    /// values. If a cached value is found it is returned without further
    /// computation of hashes of the node or the nodes below it.
    fn compute_tree_hash(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        node_index: TreeNodeIndex,
    ) -> Result<Vec<u8>, LibraryError> {
        match node_index {
            TreeNodeIndex::Leaf(leaf_index) => {
                let leaf = self.diff.leaf_mut(leaf_index);

                if let Some(hash) = leaf.tree_hash() {
                    // Return early if there's already a cached tree hash.
                    Ok(hash.to_vec())
                } else {
                    leaf.compute_tree_hash(backend, ciphersuite, leaf_index)
                }
            }
            TreeNodeIndex::Parent(parent_index) => {
                let node = self.diff.parent(parent_index);

                if let Some(hash) = node.tree_hash() {
                    // Return early if there's already a cached tree hash.
                    Ok(hash.to_vec())
                } else {
                    // Compute left hash.
                    let left_child = self.diff.left_child(parent_index);
                    let left_hash = self.compute_tree_hash(backend, ciphersuite, left_child)?;
                    // Compute right hash.
                    let right_child = self.diff.right_child(parent_index);
                    let right_hash = self.compute_tree_hash(backend, ciphersuite, right_child)?;

                    let node = self.diff.parent_mut(parent_index);

                    node.compute_tree_hash(backend, ciphersuite, left_hash, right_hash)
                }
            }
        }
    }

    /// Return the own leaf index.
    pub(crate) fn own_leaf_index(&self) -> LeafNodeIndex {
        self.own_leaf_index
    }

    /// Return a reference to our own leaf.
    pub(crate) fn own_leaf(&self) -> Result<&OpenMlsLeafNode, TreeSyncDiffError> {
        let node = self.diff.leaf(self.own_leaf_index);
        match node.node() {
            Some(node) => Ok(node),
            None => Err(LibraryError::custom("Node was empty.").into()),
        }
    }

    /// Return a mutable reference to our own leaf.
    pub(crate) fn own_leaf_mut(&mut self) -> Result<&mut OpenMlsLeafNode, TreeSyncDiffError> {
        let node = self.diff.leaf_mut(self.own_leaf_index);
        match node.node_mut() {
            Some(node) => Ok(node),
            None => Err(LibraryError::custom("Node was empty.").into()),
        }
    }

    /// Compute and set the tree hash of all nodes in the tree.
    pub(crate) fn compute_tree_hashes(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<Vec<u8>, LibraryError> {
        self.compute_tree_hash(backend, ciphersuite, self.diff.root())
    }

    /// Returns the position of the subtree root shared by both given indices in
    /// the direct path of `leaf_index_1`.
    ///
    /// Returns an error if the given leaf indices are identical or if either of
    /// the given leaf indices is outside of the tree.
    pub(crate) fn subtree_root_position(
        &self,
        leaf_index_1: LeafNodeIndex,
        leaf_index_2: LeafNodeIndex,
    ) -> Result<usize, TreeSyncDiffError> {
        Ok(self
            .diff
            .subtree_root_position(leaf_index_1, leaf_index_2)?)
    }

    /// Compute the position of the highest node in the tree in the filtered
    /// copath resolution of the given `sender_leaf_index` that we have a
    /// private key for.
    ///
    /// Returns the resulting position, as well as the private key of the node
    /// corresponding to that node private key. Returns an error if the given
    /// `sender_leaf_index` is outside of the tree.
    pub(crate) fn decryption_key(
        &self,
        sender_leaf_index: LeafNodeIndex,
        excluded_indices: &HashSet<&LeafNodeIndex>,
    ) -> Result<(&HpkePrivateKey, usize), TreeSyncDiffError> {
        // Get the copath node of the sender that is in our direct path, as well
        // as its position in our direct path.
        let subtree_root_copath_node_id = self
            .diff
            .subtree_root_copath_node(sender_leaf_index, self.own_leaf_index);

        let sender_copath_resolution =
            self.resolution(subtree_root_copath_node_id, excluded_indices);

        // Get all of the public keys that we have secret keys for, i.e. our own
        // leaf pk, as well as potentially a number of public keys from our
        // direct path.
        let mut own_node_ids = vec![TreeNodeIndex::Leaf(self.own_leaf_index)];

        own_node_ids.append(
            &mut self
                .diff
                .direct_path(self.own_leaf_index)
                .iter()
                .map(|node| TreeNodeIndex::Parent(*node))
                .collect(),
        );
        for node_index in own_node_ids {
            // If the node is blank, skip it.
            // If we don't have the private key, skip it.
            if let Some((Some(private_key), public_key)) = match node_index {
                TreeNodeIndex::Leaf(leaf_index) => self
                    .diff
                    .leaf(leaf_index)
                    .node()
                    .as_ref()
                    .map(|node| (node.private_key(), node.public_key())),
                TreeNodeIndex::Parent(parent_index) => self
                    .diff
                    .parent(parent_index)
                    .node()
                    .as_ref()
                    .map(|node| (node.private_key(), node.public_key())),
            } {
                // If we do have the private key, check if the key is in the
                // resolution.
                if let Some(resolution_position) = sender_copath_resolution
                    .iter()
                    .position(|pk| pk == public_key)
                {
                    return Ok((private_key, resolution_position));
                };
            }
        }
        Err(TreeSyncDiffError::NoPrivateKeyFound)
    }

    /// Returns a vector of all nodes in the tree resulting from merging this
    /// diff.
    pub(crate) fn export_nodes(&self) -> Vec<Option<Node>> {
        self.diff
            .export_nodes()
            .into_iter()
            .map(|node| TreeSyncNode::from(node).into())
            .collect()
    }

    /// Get the length of the direct path of the given [`LeafNodeIndex`].
    pub(super) fn direct_path_len(&self, leaf_index: LeafNodeIndex) -> usize {
        self.diff.direct_path(leaf_index).len()
    }
}
