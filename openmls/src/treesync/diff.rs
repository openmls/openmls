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
        encryption_keys::{EncryptionKey, EncryptionKeyPair, EncryptionPrivateKey},
        leaf_node::{LeafNode, OpenMlsLeafNode},
        parent_node::{ParentNode, PathDerivationResult, PlainUpdatePathNode},
        Node, NodeReference,
    },
    treesync_node::{TreeSyncLeafNode, TreeSyncParentNode},
    TreeSync, TreeSyncParentHashError, TreeSyncSetPathError,
};

use crate::{
    binary_tree::{
        array_representation::{LeafNodeIndex, ParentNodeIndex, TreeNodeIndex, MIN_TREE_SIZE},
        MlsBinaryTreeDiff, StagedMlsBinaryTreeDiff,
    },
    ciphersuite::Secret,
    credentials::CredentialBundle,
    error::LibraryError,
    group::GroupId,
    messages::PathSecret,
    schedule::CommitSecret,
};

pub(crate) type UpdatePathResult = (
    Vec<PlainUpdatePathNode>,
    Vec<EncryptionKeyPair>,
    CommitSecret,
);

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
    /// Filtered direct path, skips the nodes whose copath resolution is empty.
    pub(crate) fn filtered_direct_path(&self, leaf_index: LeafNodeIndex) -> Vec<ParentNodeIndex> {
        // Full direct path
        let direct_path = self.diff.direct_path(leaf_index);
        // Copath resolutions
        let copath_resolutions = self.copath_resolutions(leaf_index);

        // The two vectors should have the same length
        debug_assert_eq!(direct_path.len(), copath_resolutions.len());

        direct_path
            .into_iter()
            .zip(copath_resolutions.into_iter())
            .filter_map(|(index, resolution)| {
                // Filter out the nodes whose copath resolution is empty
                if !resolution.is_empty() {
                    Some(index)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Filtered copath, skips the nodes whose copath resolution is empty.
    /// Matches the filtered direct path.
    pub(crate) fn filtered_copath(&self, leaf_index: LeafNodeIndex) -> Vec<TreeNodeIndex> {
        // Full copath
        let copath = self.diff.copath(leaf_index);
        // Copath resolutions
        let copath_resolutions = self.copath_resolutions(leaf_index);

        // The two vectors should have the same length
        debug_assert_eq!(copath.len(), copath_resolutions.len());

        copath
            .into_iter()
            .zip(copath_resolutions.into_iter())
            .filter_map(|(index, resolution)| {
                // Filter out the nodes whose copath resolution is empty
                if !resolution.is_empty() {
                    Some(index)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Trims the tree by shrinking it until the last full leaf is in the
    /// right part of the tree.
    fn trim_tree(&mut self) {
        // Nothing to trim if there's only one leaf left.
        if self.leaf_count() == MIN_TREE_SIZE {
            return;
        }

        let rightmost_full_leaf = self.rightmost_full_leaf();

        // We shrink the tree until the last full leaf is the right part of the
        // tree
        while self.diff.size().leaf_is_left(rightmost_full_leaf) {
            let res = self.diff.shrink_tree();
            // We should never run into an error here, since `leaf_is_left`
            // returns false when the tree only has one leaf.
            debug_assert!(res.is_ok());
        }
    }

    /// Returns the index of the last full leaf in the tree.
    fn rightmost_full_leaf(&self) -> LeafNodeIndex {
        let mut index = LeafNodeIndex::new(0);
        for (leaf_index, leaf) in self.diff.leaves() {
            if leaf.node().as_ref().is_some() {
                index = leaf_index;
            }
        }
        index
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
        let leaf_count = self.diff.leaves().count() as u32;

        // Search for blank leaves in existing leaves
        for (leaf_index, leaf_id) in self.diff.leaves() {
            if leaf_id.node().is_none() {
                return leaf_index;
            }
        }

        // Return the next free virtual blank leaf
        LeafNodeIndex::new(leaf_count)
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
        // otherwise extend the tree first.
        while leaf_index.u32() >= self.diff.size().leaf_count() {
            self.diff
                .grow_tree()
                .map_err(|_| TreeSyncAddLeaf::TreeFull)?;
        }
        self.diff.replace_leaf(leaf_index, leaf_node.into());

        // Add new unmerged leaves entry to all nodes in direct path. Also, wipe
        // the cached tree hash.
        for parent_index in self.diff.direct_path(leaf_index) {
            // We know that the nodes from the direct path are in the tree
            let tsn = self.diff.parent_mut(parent_index);
            if let Some(ref mut parent_node) = tsn.node_mut() {
                parent_node.add_unmerged_leaf(leaf_index);
            }
        }
        Ok(leaf_index)
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

        let path_indices = self.filtered_direct_path(self.own_leaf_index);

        ParentNode::derive_path(backend, ciphersuite, path_secret, path_indices)
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

        let (path, update_path_nodes, keypairs, commit_secret) =
            self.derive_path(backend, ciphersuite)?;

        let parent_hash =
            self.process_update_path(backend, ciphersuite, self.own_leaf_index, path)?;

        self.own_leaf_mut()
            .map_err(|_| LibraryError::custom("Didn't find own leaf in diff."))?
            .update_parent_hash(&parent_hash, group_id, credential_bundle, backend)?;

        Ok((update_path_nodes, keypairs, commit_secret))
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
        let filtered_direct_path = self.filtered_direct_path(sender_leaf_index);
        debug_assert_eq!(filtered_direct_path.len(), path.len());
        let path = filtered_direct_path
            .into_iter()
            .zip(path.into_iter())
            .collect();
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
        mut path: Vec<(ParentNodeIndex, ParentNode)>,
    ) -> Result<Vec<u8>, LibraryError> {
        // Compute the parent hash.
        let parent_hash = self.set_parent_hashes(backend, ciphersuite, &mut path, leaf_index)?;

        // While probably not necessary, the spec mandates we blank the direct path nodes
        let direct_path_nodes = self.diff.direct_path(leaf_index);
        for node in direct_path_nodes {
            *self.diff.parent_mut(node) = TreeSyncParentNode::blank();
        }

        // Set the node of the filtered direct path.
        // Note, that the nodes here don't have a tree hash set.
        // TODO #804
        for (index, node) in path.into_iter() {
            *self.diff.parent_mut(index) = node.into();
        }

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
    pub(crate) fn derive_path_secrets(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        mut path_secret: PathSecret,
        sender_index: LeafNodeIndex,
    ) -> Result<(Vec<EncryptionKeyPair>, CommitSecret), TreeSyncSetPathError> {
        // We assume both nodes are in the tree, since the sender_index must be in the tree
        // Skip the nodes in the subtree path for which we are an unmerged leaf.
        let subtree_path = self.diff.subtree_path(self.own_leaf_index, sender_index);
        let mut keypairs = Vec::new();
        for parent_index in subtree_path {
            // We know the node is in the diff, since it is in the subtree path
            let tsn = self.diff.parent(parent_index);
            // We only care about non-blank nodes.
            if let Some(ref parent_node) = tsn.node() {
                // If our own leaf index is not in the list of unmerged leaves
                // then we should have the secret for this node.
                if !parent_node.unmerged_leaves().contains(&self.own_leaf_index) {
                    let keypair = path_secret.derive_key_pair(backend, ciphersuite)?;
                    // The derived public key should match the one in the node.
                    // If not, the tree is corrupt.
                    if parent_node.encryption_key() != keypair.public_key() {
                        return Err(TreeSyncSetPathError::PublicKeyMismatch);
                    } else {
                        // If everything is ok, set the private key and derive
                        // the next path secret.
                        keypairs.push(keypair);
                        path_secret = path_secret.derive_path_secret(backend, ciphersuite)?;
                    }
                };
                // If the leaf is blank or our index is in the list of unmerged
                // leaves, go to the next node.
            }
        }
        Ok((keypairs, path_secret.into()))
    }

    /// Set the parent hash of the given nodes assuming that they are the new
    /// filtered direct path of the leaf with the given index.
    ///
    /// Returns the parent hash of the leaf node at `leaf_index` and a
    /// `LibraryError` if an unexpected error occurs.
    fn set_parent_hashes(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        path: &mut [(ParentNodeIndex, ParentNode)],
        leaf_index: LeafNodeIndex,
    ) -> Result<Vec<u8>, LibraryError> {
        // If the path is empty, return a zero-length string. This is the case
        // when the tree has only one leaf.
        if path.is_empty() {
            return Ok(Vec::new());
        }

        // Compute the filtered copath corresponding to the given filtered
        // direct path.
        let filtered_copath = self.filtered_copath(leaf_index);
        debug_assert_eq!(filtered_copath.len(), path.len());

        // For every copath node, compute the tree hash.
        let copath_tree_hashes = filtered_copath.into_iter().map(|node_index| {
            self.compute_tree_hash(backend, ciphersuite, node_index, &HashSet::new())
        });

        // We go through the nodes in the direct path in reverse order and get
        // the corresponding tree hash for each copath node.
        let mut previous_parent_hash = vec![];
        for ((_, path_node), original_sibling_tree_hash) in
            path.iter_mut().rev().zip(copath_tree_hashes.rev())
        {
            path_node.set_parent_hash(previous_parent_hash);
            let parent_hash = path_node.compute_parent_hash(
                backend,
                ciphersuite,
                &original_sibling_tree_hash?,
            )?;
            previous_parent_hash = parent_hash
        }
        // The final hash is the one of the leaf's parent.
        Ok(previous_parent_hash)
    }

    /// Helper function computing the resolution of a node with the given index.
    /// If an exclusion list is given, do not add the leaves given in the list.
    fn resolution(
        &self,
        node_index: TreeNodeIndex,
        excluded_indices: &HashSet<&LeafNodeIndex>,
    ) -> Vec<(TreeNodeIndex, NodeReference)> {
        match node_index {
            TreeNodeIndex::Leaf(leaf_index) => {
                // If the node is a leaf, check if it is in the exclusion list.
                if excluded_indices.contains(&leaf_index) {
                    vec![]
                } else {
                    // If it's not, return it as its resolution.
                    if let Some(leaf) = self.diff.leaf(leaf_index).node() {
                        vec![(TreeNodeIndex::Leaf(leaf_index), NodeReference::Leaf(leaf))]
                    } else {
                        // If it's a blank, return an empty vector.
                        vec![]
                    }
                }
            }
            TreeNodeIndex::Parent(parent_index) => {
                match self.diff.parent(parent_index).node() {
                    Some(parent) => {
                        // If it's a non-blank parent node, get the unmerged
                        // leaves, exclude them as necessary and add the node to
                        // the resulting resolution.
                        let mut resolution = vec![(
                            TreeNodeIndex::Parent(parent_index),
                            NodeReference::Parent(parent),
                        )];
                        for leaf_index in parent.unmerged_leaves() {
                            if !excluded_indices.contains(&leaf_index) {
                                let leaf = self.diff.leaf(*leaf_index);
                                // TODO #800: unmerged leaves should be checked
                                if let Some(leaf_node) = leaf.node() {
                                    resolution.push((
                                        TreeNodeIndex::Leaf(*leaf_index),
                                        NodeReference::Leaf(leaf_node),
                                    ))
                                } else {
                                    debug_assert!(false, "Unmerged leaves should not be blank.");
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
    ) -> Vec<Vec<(TreeNodeIndex, NodeReference)>> {
        // If we're the only node in the tree, there's no copath.
        if self.diff.leaf_count() == MIN_TREE_SIZE {
            return vec![];
        }

        // Get the copath of the given leaf index and compute the resolution of
        // each node.
        self.diff
            .copath(leaf_index)
            .into_iter()
            .map(|node_index| self.resolution(node_index, &HashSet::new()))
            .collect()
    }

    /// Compute the copath resolutions, but leave out empty resolutions.
    /// Additionally, resolutions are filtered by the given exclusion list.
    pub(super) fn filtered_copath_resolutions(
        &self,
        leaf_index: LeafNodeIndex,
        exclusion_list: &HashSet<&LeafNodeIndex>,
    ) -> Vec<Vec<(TreeNodeIndex, NodeReference)>> {
        // If we're the only node in the tree, there's no copath.
        if self.diff.leaf_count() == 1 {
            return vec![];
        }

        let mut copath_resolutions = Vec::new();
        for node_index in self.diff.copath(leaf_index) {
            let resolution = self.resolution(node_index, &HashSet::new());
            if !resolution.is_empty() {
                let filtered_resolution = resolution
                    .into_iter()
                    .filter_map(|(index, node)| {
                        if let TreeNodeIndex::Leaf(leaf_index) = index {
                            if exclusion_list.contains(&leaf_index) {
                                None
                            } else {
                                Some((TreeNodeIndex::Leaf(leaf_index), node))
                            }
                        } else {
                            Some((index, node))
                        }
                    })
                    .collect();
                copath_resolutions.push(filtered_resolution);
            }
        }
        copath_resolutions
    }

    /// Verify the parent hashes of all parent nodes in the tree.
    ///
    /// Returns an error if one of the parent nodes in the tree has an invalid
    /// parent hash.
    pub(super) fn verify_parent_hashes(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<(), TreeSyncParentHashError> {
        // We traverse the tree by iterating over all parent nodes. For each
        // parent node, we compute the parent hash and compare it to the parent
        // hash in its descendants.
        //
        // We need to consider all nodes in the the descendants list (the
        // resolution), since we cannot determine which descedant was the
        // previous one in the update path when the original commit occurred.
        //
        // We look at both righ & left subtree of a give node separately and
        // compute the original sibling tree hash for the sibling of the subtree
        // root.
        //
        // The parent hash for a given node is valid, when exactly one descendant
        // carries the parent hash it its parent hash field.
        for (parent_index, tree_sync_parent_node) in self.diff.parents() {
            if let Some(parent_node) = tree_sync_parent_node.node() {
                // We consider both children of the parent node. One of them
                // takes the role of the descendant, whose resolution carries
                // the parent hash. The other one is the descendants sibling,
                // whose original tree hash is used to compute the parent hash.
                let left_child = self.diff.left_child(parent_index);
                let right_child = self.diff.right_child(parent_index);

                // We exclude the unmerged leaves from the parent node for the
                // following computations. Those leaves were obviously addede
                // after the parent node was populated during a commit and must
                // therefore be removed to recreate the tree state at the time
                // of the commit.
                let exclusion_list = HashSet::from_iter(parent_node.unmerged_leaves().iter());

                // Compute the original tree hash (oth) for the left and right child.
                let oth_left =
                    self.compute_tree_hash(backend, ciphersuite, left_child, &exclusion_list)?;

                let oth_right =
                    self.compute_tree_hash(backend, ciphersuite, right_child, &exclusion_list)?;

                // Compute the parent hash for both child roles.
                let parent_hash_left =
                    parent_node.compute_parent_hash(backend, ciphersuite, &oth_right)?;

                let parent_hash_right =
                    parent_node.compute_parent_hash(backend, ciphersuite, &oth_left)?;

                // Compute the resolution for both children.
                let left_resolution = self.resolution(left_child, &exclusion_list);

                let right_resolution = self.resolution(right_child, &exclusion_list);

                // Find parent hash in the left resolution.
                let left_descendant = left_resolution.iter().find(|(_, node)| match node {
                    NodeReference::Leaf(leaf) => leaf
                        .leaf_node
                        .parent_hash()
                        .map(|parent_hash| parent_hash == parent_hash_left)
                        .unwrap_or(false),
                    NodeReference::Parent(parent) => parent.parent_hash() == parent_hash_left,
                });

                // Find parent hash in the right resolution.
                let right_descendant = right_resolution.iter().find(|(_, node)| match node {
                    NodeReference::Leaf(leaf) => leaf
                        .leaf_node
                        .parent_hash()
                        .map(|parent_hash| parent_hash == parent_hash_right)
                        .unwrap_or(false),
                    NodeReference::Parent(parent) => parent.parent_hash() == parent_hash_right,
                });

                // If one of the parent hashes is in the resolution of the
                // other child, the parent hash is valid.
                if left_descendant.is_none() ^ right_descendant.is_some() {
                    return Err(TreeSyncParentHashError::InvalidParentHash);
                } else {
                }
            }
        }
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
    /// all nodes below it in the tree. The leaf nodes in `exclusion_list` are
    /// not included in the tree hash.
    fn compute_tree_hash(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        node_index: TreeNodeIndex,
        exclusion_list: &HashSet<&LeafNodeIndex>,
    ) -> Result<Vec<u8>, LibraryError> {
        match node_index {
            TreeNodeIndex::Leaf(leaf_index) => {
                let leaf = self.diff.leaf(leaf_index);

                if exclusion_list.contains(&leaf_index) {
                    TreeSyncLeafNode::blank().compute_tree_hash(backend, ciphersuite, leaf_index)
                } else {
                    leaf.compute_tree_hash(backend, ciphersuite, leaf_index)
                }
            }
            TreeNodeIndex::Parent(parent_index) => {
                // Compute left hash.
                let left_child = self.diff.left_child(parent_index);
                let left_hash =
                    self.compute_tree_hash(backend, ciphersuite, left_child, exclusion_list)?;
                // Compute right hash.
                let right_child = self.diff.right_child(parent_index);
                let right_hash =
                    self.compute_tree_hash(backend, ciphersuite, right_child, exclusion_list)?;

                let node = self.diff.parent(parent_index);

                node.compute_tree_hash(backend, ciphersuite, left_hash, right_hash, exclusion_list)
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
        self.compute_tree_hash(backend, ciphersuite, self.diff.root(), &HashSet::new())
    }

    /// Returns the position of the subtree root shared by both given indices in
    /// the direct path of `leaf_index_1`.
    ///
    /// Returns a [LibraryError] if there's an error in the tree math computation.
    pub(super) fn subtree_root_position(
        &self,
        leaf_index_1: LeafNodeIndex,
        leaf_index_2: LeafNodeIndex,
    ) -> Result<usize, TreeSyncDiffError> {
        let subtree_root_node_index = self.diff.lowest_common_ancestor(leaf_index_1, leaf_index_2);
        let leaf_index_1_direct_path = self.filtered_direct_path(leaf_index_1);

        leaf_index_1_direct_path
            .iter()
            .position(|&direct_path_node_index| direct_path_node_index == subtree_root_node_index)
            // The shared subtree root has to be in the direct path of both nodes.
            .ok_or_else(|| LibraryError::custom("index should be in the direct path").into())
    }

    /// Compute the position of the highest node in the tree in the filtered
    /// copath resolution of the given `sender_leaf_index` that we have a
    /// private key for.
    ///
    /// Returns the resulting position, as well as the private key of the node
    /// corresponding to that node private key. Returns an error if the given
    /// `sender_leaf_index` is outside of the tree.
    pub(crate) fn decryption_key<'private_key>(
        &self,
        sender_leaf_index: LeafNodeIndex,
        excluded_indices: &HashSet<&LeafNodeIndex>,
        owned_keys: &'private_key [&EncryptionKeyPair],
    ) -> Result<(&'private_key EncryptionPrivateKey, usize), TreeSyncDiffError> {
        // Get the copath node of the sender that is in our direct path, as well
        // as its position in our direct path.
        let subtree_root_copath_node_id = self
            .diff
            .subtree_root_copath_node(sender_leaf_index, self.own_leaf_index);

        let sender_copath_resolution: Vec<EncryptionKey> = self
            .resolution(subtree_root_copath_node_id, excluded_indices)
            .into_iter()
            .map(|(_, node_ref)| match node_ref {
                NodeReference::Leaf(leaf) => leaf.encryption_key().clone(),
                NodeReference::Parent(parent) => parent.encryption_key().clone(),
            })
            .collect();

        // TODO: REMOVE BEFORE MERGING PR.
        let position = sender_copath_resolution
            .iter()
            .position(|pk| {
                owned_keys
                    .iter()
                    .any(|owned_keypair| owned_keypair.public_key() == pk)
            })
            .unwrap();

        if let Some((resolution_position, private_key)) = sender_copath_resolution
            .iter()
            .enumerate()
            .filter_map(|(position, pk)| {
                owned_keys
                    .iter()
                    .find(|&owned_keypair| owned_keypair.public_key() == pk)
                    .map(|keypair| (position, keypair.private_key()))
            })
            .next()
        {
            debug_assert_eq!(position, resolution_position);
            return Ok((private_key, resolution_position));
        };
        Err(TreeSyncDiffError::NoPrivateKeyFound)
    }

    /// Returns a vector of all nodes in the tree resulting from merging this
    /// diff.
    pub(crate) fn export_nodes(&self) -> Vec<Option<Node>> {
        let mut nodes = Vec::new();

        // Determine the index of the rightmost full leaf.
        let max_length = self.rightmost_full_leaf();

        // We take all the leaves including the rightmost full leaf, blank
        // leaves beyond that are trimmed.
        let mut leaves = self
            .diff
            .leaves()
            .map(|(_, leaf)| leaf)
            .take(max_length.usize() + 1);

        // Get the first leaf.
        if let Some(leaf) = leaves.next() {
            nodes.push(leaf.node().clone().map(Node::LeafNode));
        } else {
            // The tree was empty.
            return vec![];
        }

        // Blank parent node used for padding
        let default_parent = TreeSyncParentNode::default();

        // Get the parents.
        let parents = self
            .diff
            .parents()
            // Drop the index
            .map(|(_, parent)| parent)
            // Take the parents up to the max length
            .take(max_length.usize())
            // Pad the parents with blank nodes if needed
            .chain(
                (self.diff.parents().count()..self.diff.leaves().count() - 1)
                    .map(|_| &default_parent),
            );

        // Interleave the leaves and parents.
        for (leaf, parent) in leaves.zip(parents) {
            nodes.push(parent.node().clone().map(Node::ParentNode));
            nodes.push(leaf.node().clone().map(Node::LeafNode));
        }

        nodes
    }

    /// Returns the filtered common path two leaf nodes share. If the leaves are
    /// identical, the common path is the leaf's direct path.
    pub(super) fn filtered_common_direct_path(
        &self,
        leaf_index_1: LeafNodeIndex,
        leaf_index_2: LeafNodeIndex,
    ) -> Vec<ParentNodeIndex> {
        let mut x_path = self.filtered_direct_path(leaf_index_1);
        let mut y_path = self.filtered_direct_path(leaf_index_2);
        x_path.reverse();
        y_path.reverse();

        let mut common_path = vec![];

        for (x, y) in x_path.iter().zip(y_path.iter()) {
            if x == y {
                common_path.push(*x);
            } else {
                break;
            }
        }

        common_path.reverse();
        common_path
    }

    /// Return an iterator over references to all [`HpkePublicKey`]s for which
    /// we should have the corresponding private keys.
    pub(crate) fn owned_encryption_keys(&self) -> impl Iterator<Item = &EncryptionKey> {
        let encryption_keys = if let Some(leaf) = self.diff.leaf(self.own_leaf_index).node() {
            vec![leaf.encryption_key()]
        } else {
            // If our own leaf is empty, we don't expect to own any other keys.
            vec![]
        };
        encryption_keys.into_iter().chain(
            self.filtered_direct_path(self.own_leaf_index())
                .into_iter()
                .filter_map(|parent_index| {
                    // Filter out all blanks.
                    if let Some(node) = self.diff.parent(parent_index).node().as_ref() {
                        // Filter all nodes where our leaf is an unmerged leaf.
                        if !node.unmerged_leaves().contains(&self.own_leaf_index) {
                            Some(node.encryption_key())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .into_iter(),
        )
    }
}
