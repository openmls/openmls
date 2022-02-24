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
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};

use std::{collections::HashSet, convert::TryFrom};

use super::{
    errors::*,
    node::{
        leaf_node::LeafNode,
        parent_node::{ParentNode, PathDerivationResult, PlainUpdatePathNode},
        Node,
    },
    treesync_node::TreeSyncNode,
    TreeSync, TreeSyncParentHashError, TreeSyncSetPathError,
};

use crate::{
    binary_tree::{
        array_representation::diff::NodeId, LeafIndex, MlsBinaryTreeDiff, StagedMlsBinaryTreeDiff,
    },
    ciphersuite::{
        hash_ref::KeyPackageRef, signable::Signable, HpkePrivateKey, HpkePublicKey, Secret,
    },
    credentials::CredentialBundle,
    error::LibraryError,
    extensions::ExtensionType,
    key_packages::{KeyPackage, KeyPackageBundlePayload},
    messages::PathSecret,
    schedule::CommitSecret,
};

pub(crate) type UpdatePathResult = (KeyPackage, Vec<PlainUpdatePathNode>, CommitSecret);

/// The [`StagedTreeSyncDiff`] can be created from a [`TreeSyncDiff`], examined
/// and later merged into a [`TreeSync`] instance.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StagedTreeSyncDiff {
    own_leaf_index: LeafIndex,
    diff: StagedMlsBinaryTreeDiff<TreeSyncNode>,
    new_tree_hash: Vec<u8>,
}

impl StagedTreeSyncDiff {
    pub(super) fn into_parts(self) -> (LeafIndex, StagedMlsBinaryTreeDiff<TreeSyncNode>, Vec<u8>) {
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
    diff: MlsBinaryTreeDiff<'a, TreeSyncNode>,
    own_leaf_index: LeafIndex,
}

impl<'a> TryFrom<&'a TreeSync> for TreeSyncDiff<'a> {
    type Error = TreeSyncDiffError;

    fn try_from(tree_sync: &'a TreeSync) -> Result<Self, Self::Error> {
        Ok(TreeSyncDiff {
            diff: tree_sync.tree.empty_diff()?,
            own_leaf_index: tree_sync.own_leaf_index,
        })
    }
}

impl<'a> TreeSyncDiff<'a> {
    /// Check if the right-most leaf and its parent are blank. If that is the
    /// case, remove the right-most leaf and its parent until either the
    /// right-most leaf or its parent are not blank anymore. This behaviour
    /// differs from that in the MLS spec. This is because there is a suspected
    /// bug in the trimming algorithm in the spec, which is currently under
    /// discussion.
    pub(crate) fn trim_tree(&mut self) -> Result<(), TreeSyncDiffError> {
        // Nothing to trim if there's only one leaf left.
        if self.leaf_count() == 1 {
            return Ok(());
        }
        let mut leaf_id = self.diff.leaf(self.leaf_count() - 1)?;
        let mut parent_id = self.diff.parent(leaf_id)?;
        // Trim only if the parent node is blank as well;.
        while self.diff.node(leaf_id)?.node().is_none()
            && self.diff.node(parent_id)?.node().is_none()
        {
            self.diff.remove_leaf()?;
            // If there's only one leaf left, it won't have a parent, so we'll
            // have to stop here.
            if self.leaf_count() == 1 {
                return Ok(());
            }
            leaf_id = self.diff.leaf(self.leaf_count() - 1)?;
            parent_id = self.diff.parent(leaf_id)?;
        }
        Ok(())
    }

    /// Returns the number of leaves in the tree that would result from merging
    /// this diff.
    pub(crate) fn leaf_count(&self) -> LeafIndex {
        self.diff.leaf_count()
    }

    /// Updates an existing leaf node and blanks the nodes in the updated leaf's
    /// direct path.
    ///
    /// Returns an error if the target leaf is blank or outside of the tree.
    pub(crate) fn update_leaf(
        &mut self,
        leaf_node: impl Into<LeafNode>,
        leaf_index: LeafIndex,
    ) -> Result<(), TreeSyncDiffError> {
        let node = Node::LeafNode(leaf_node.into());
        self.diff.replace_leaf(leaf_index, node.into())?;
        // This effectively wipes the tree hashes in the direct path.
        self.diff
            .set_direct_path_to_node(leaf_index, &TreeSyncNode::blank())?;
        Ok(())
    }

    /// Find and return the index of either the left-most blank leaf, or, if
    /// there are no blank leaves, the leaf count.
    pub(crate) fn free_leaf_index(&self) -> Result<LeafIndex, LibraryError> {
        // Find a free leaf and fill it with the new key package.
        let leaf_ids = self.diff.leaves()?;
        let mut leaf_index_option = None;
        for (leaf_index, leaf_id) in leaf_ids.iter().enumerate() {
            let leaf_index: LeafIndex = u32::try_from(leaf_index)
                .map_err(|_| LibraryError::custom("Could not convert index"))?;
            // The leaf ID must be valid, since it is one of the leaves of the tree
            if self
                .diff
                .node(*leaf_id)
                .map_err(|_| LibraryError::custom("Expected a valid leaf ID"))?
                .node()
                .is_none()
            {
                leaf_index_option = Some(leaf_index);
                break;
            }
        }
        // If we found a free leaf, replace it with the new one, otherwise
        // extend the tree.
        Ok(leaf_index_option.unwrap_or_else(|| self.leaf_count()))
    }

    /// Adds a new leaf to the tree either by filling a blank leaf or by
    /// extending the tree to the right to create a new leaf, inserting
    /// intermediate blanks as necessary. This also adds the leaf_index of the
    /// new leaf to the `unmerged_leaves` of the parent nodes in its direct
    /// path.
    ///
    /// Returns the LeafIndex of the new leaf.
    pub(crate) fn add_leaf(
        &mut self,
        leaf_node: KeyPackage,
        backend: &impl OpenMlsCrypto,
    ) -> Result<LeafIndex, TreeSyncAddLeaf> {
        let node = Node::LeafNode(LeafNode::new(leaf_node, backend)?);
        // Find a free leaf and fill it with the new key package.
        let leaf_index = self.free_leaf_index()?;
        // If the free leaf index is within the tree, put the new leaf there,
        // otherwise extend the tree.
        if leaf_index < self.leaf_count() {
            self.diff
                .replace_leaf(leaf_index, node.into())
                // We know the leaf index is in the tree, so replacing it should not fail
                .map_err(|_| LibraryError::custom("Could not replace the leaf"))?;
        } else {
            self.diff
                .add_leaf(TreeSyncNode::blank(), node.into())
                .map_err(|_| TreeSyncAddLeaf::TreeFull)?;
        }
        // Add new unmerged leaves entry to all nodes in direct path. Also, wipe
        // the cached tree hash.
        for node_id in self
            .diff
            .direct_path(leaf_index)
            // We checked the leaf index is in the tree
            .map_err(|_| LibraryError::custom("Expected leaf index to be in tree"))?
        {
            // We know that the nodes from the direct path are in the tree
            let tsn = self
                .diff
                .node_mut(node_id)
                .map_err(|_| LibraryError::custom("Expected a node"))?;
            if let Some(ref mut node) = tsn.node_mut() {
                // We know that nodes in the direct path are always parent nodes
                let pn = node
                    .as_parent_node_mut()
                    .map_err(|_| LibraryError::custom("Expected a parent node"))?;
                pn.add_unmerged_leaf(leaf_index);
            }
            tsn.erase_tree_hash();
        }
        Ok(leaf_index)
    }

    /// Set the `own_leaf_index` to `leaf_index`. This has to be used with
    /// caution, as it can invalidate the [`TreeSync`] invariants.
    pub(crate) fn set_own_index(&mut self, leaf_index: LeafIndex) {
        self.own_leaf_index = leaf_index
    }

    /// Remove a group member by blanking the target leaf and its direct path.
    /// After blanking the leaf and its direct path, the diff is trimmed, i.e.
    /// leaves are removed until the right-most leaf in the tree, as well as its
    /// parent are non-blank.
    ///
    /// Returns an error if the target leaf is outside of the tree.
    pub(crate) fn blank_leaf(&mut self, leaf_index: LeafIndex) -> Result<(), TreeSyncDiffError> {
        self.diff.replace_leaf(leaf_index, TreeSyncNode::blank())?;
        // This also erases any cached tree hash in the direct path.
        self.diff
            .set_direct_path_to_node(leaf_index, &TreeSyncNode::blank())?;
        self.trim_tree()?;
        Ok(())
    }

    /// Derive a new direct path for our own leaf from the given `leaf_secret`.
    ///
    /// Returns an error if the own leaf is not in the tree
    fn derive_path_from_leaf_secret(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        leaf_secret: Secret,
    ) -> Result<PathDerivationResult, LibraryError> {
        let leaf_path_secret = PathSecret::from(leaf_secret);
        let path_secret = leaf_path_secret.derive_path_secret(backend, ciphersuite)?;

        let path_length = self
            .diff
            .direct_path(self.own_leaf_index)
            // We assume the own leaf is in the tree
            .map_err(|_| LibraryError::custom("Own leaf was not in tree"))?
            .len();

        ParentNode::derive_path(backend, ciphersuite, path_secret, path_length)
    }

    /// Given a [`KeyPackageBundlePayload`], use it to create a new path and
    /// apply it to this diff. The given [`CredentialBundle`] reference is used
    /// to sign the [`KeyPackageBundlePayload`] after updating its parent hash.
    ///
    /// Returns the [`CommitSecret`] and the path resulting from the path
    /// derivation, as well as the [`KeyPackage`].
    ///
    /// Returns an error if the own leaf is not in the tree
    pub(crate) fn apply_own_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        mut key_package_bundle_payload: KeyPackageBundlePayload,
        credential_bundle: &CredentialBundle,
    ) -> Result<UpdatePathResult, LibraryError> {
        let leaf_secret = key_package_bundle_payload.leaf_secret().clone();

        let (path, update_path_nodes, commit_secret) =
            self.derive_path_from_leaf_secret(backend, ciphersuite, leaf_secret)?;

        let parent_hash =
            self.process_update_path(backend, ciphersuite, self.own_leaf_index, path)?;

        key_package_bundle_payload.update_parent_hash(&parent_hash);
        let key_package_bundle = key_package_bundle_payload.sign(backend, credential_bundle)?;

        let key_package = key_package_bundle.key_package().clone();
        let node = Node::LeafNode(LeafNode::new_from_bundle(
            key_package_bundle,
            backend.crypto(),
        )?);

        // Replace the leaf.
        self.diff
            .replace_leaf(self.own_leaf_index, node.into())
            // We assume the own leaf is in the tree
            .map_err(|_| LibraryError::custom("Own leaf not in tree"))?;
        Ok((key_package, update_path_nodes, commit_secret))
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
        sender_leaf_index: LeafIndex,
        key_package: KeyPackage,
        path: Vec<ParentNode>,
    ) -> Result<(), ApplyUpdatePathError> {
        let parent_hash =
            self.process_update_path(backend, ciphersuite, sender_leaf_index, path)?;

        // Verify the parent hash.
        let phe = key_package
            .extension_with_type(ExtensionType::ParentHash)
            .ok_or(ApplyUpdatePathError::MissingParentHash)?;
        let key_package_parent_hash = phe
            .as_parent_hash_extension()
            .map_err(|_| LibraryError::custom("no parent hash extension"))?
            .parent_hash();
        if key_package_parent_hash != parent_hash {
            return Err(ApplyUpdatePathError::ParentHashMismatch);
        };

        // Replace the leaf.
        let node = Node::LeafNode(LeafNode::new(key_package, backend.crypto())?);
        self.diff
            .replace_leaf(sender_leaf_index, node.into())
            // We assume the sender leaf is in the tree
            .map_err(|_| LibraryError::custom("Expected sender leaf to be in the tree"))?;
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
        leaf_index: LeafIndex,
        mut path: Vec<ParentNode>,
    ) -> Result<Vec<u8>, LibraryError> {
        // Compute the parent hash.
        let parent_hash = self.set_parent_hashes(backend, ciphersuite, &mut path, leaf_index)?;
        let direct_path: Vec<TreeSyncNode> = path
            .into_iter()
            .map(|parent_node| Node::ParentNode(parent_node).into())
            .collect();

        // Set the direct path. Note, that the nodes here don't have a tree hash
        // TODO #804
        // set.
        self.diff
            .set_direct_path(leaf_index, direct_path)
            .map_err(|_| LibraryError::custom("Expected the leaf index to be in the tree"))?;
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
        sender_index: LeafIndex,
    ) -> Result<CommitSecret, TreeSyncSetPathError> {
        // We assume both nodes are in the tree, since the sender_index must be in the tree
        let subtree_path = self
            .diff
            .subtree_path(self.own_leaf_index, sender_index)
            .map_err(|_| LibraryError::custom("Expected both nodes to be in the tree"))?;
        for node_id in subtree_path {
            // We know the node is in the diff, since it is in the subtree path
            let tsn = self
                .diff
                .node_mut(node_id)
                .map_err(|_| LibraryError::custom("Expected the node to be in the diff"))?;
            // We only care about non-blank nodes.
            if let Some(ref mut node) = tsn.node_mut() {
                // This has to be a parent node.
                let pn = node
                    .as_parent_node_mut()
                    .map_err(|_| LibraryError::custom("Expected a parent node"))?;
                // If our own leaf index is not in the list of unmerged leaves
                // then we should have the secret for this node.
                if !pn.unmerged_leaves().contains(&self.own_leaf_index) {
                    let (public_key, private_key) =
                        path_secret.derive_key_pair(backend, ciphersuite)?;
                    // The derived public key should match the one in the node.
                    // If not, the tree is corrupt.
                    if pn.public_key() != &public_key {
                        return Err(TreeSyncSetPathError::PublicKeyMismatch);
                    } else {
                        // If everything is ok, set the private key and derive
                        // the next path secret.
                        pn.set_private_key(private_key);
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
    fn filter_resolution(
        &self,
        parent_node: &ParentNode,
        resolution: &mut Vec<HpkePublicKey>,
    ) -> Result<(), LibraryError> {
        for leaf_index in parent_node.unmerged_leaves() {
            let leaf_id = self
                .diff
                .leaf(*leaf_index)
                .map_err(|_| LibraryError::custom("Unmerged leaf not in tree"))?;
            let leaf = self
                .diff
                .node(leaf_id)
                .map_err(|_| LibraryError::custom("Unmerged leaf not in tree"))?;
            // All unmerged leaves should be non-blank.
            let leaf_node = leaf
                .node()
                .as_ref()
                .ok_or_else(|| LibraryError::custom("Node was empty."))?;
            let leaf = leaf_node
                .as_leaf_node()
                .map_err(|_| LibraryError::custom("Unmerged leaf not a leaf"))?;
            if let Some(position) = resolution
                .iter()
                .position(|bytes| bytes == leaf.public_key())
            {
                resolution.remove(position);
            };
        }
        Ok(())
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
        leaf_index: LeafIndex,
    ) -> Result<Vec<u8>, LibraryError> {
        // If the path is empty, return a zero-length string. This is the case
        // when the tree has only one leaf.
        if path.is_empty() {
            return Ok(Vec::new());
        }

        // Get the resolutions of the copath nodes (i.e. the original child
        // resolutions).
        let mut copath_resolutions = self.copath_resolutions(leaf_index, &HashSet::new())?;
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
            self.filter_resolution(path_node, resolution)?;
            let parent_hash = path_node.compute_parent_hash(
                backend,
                ciphersuite,
                path_node.parent_hash(),
                resolution,
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
        node_id: NodeId,
        excluded_indices: &HashSet<&LeafIndex>,
    ) -> Result<Vec<HpkePublicKey>, LibraryError> {
        // First, check if the node is blank or not.
        if let Some(node) = self
            .diff
            .node(node_id)
            .map_err(|_| LibraryError::custom("Expected node to be in the tree"))?
            .node()
        {
            // If it's a full node, check if it's a leaf.
            if let Some(leaf_index) = self.diff.leaf_index(node_id) {
                // If the node is a leaf, check if it is in the exclusion list.
                if excluded_indices.contains(&leaf_index) {
                    Ok(vec![])
                } else {
                    // If it's not, return its public key as its resolution.
                    Ok(vec![node.public_key().clone()])
                }
            } else {
                // If it's a parent node, get the unmerged leaves, exclude them
                // as necessary and add their public keys to the resulting
                // resolution.
                let mut resolution = vec![node.public_key().clone()];
                for leaf_index in node
                    .as_parent_node()
                    .map_err(|_| LibraryError::custom("Expected a parent node"))?
                    .unmerged_leaves()
                {
                    if !excluded_indices.contains(leaf_index) {
                        let leaf_id = self
                            .diff
                            .leaf(*leaf_index)
                            .map_err(|_| LibraryError::custom("Expected leaf to be in the tree"))?;
                        let leaf = self
                            .diff
                            .node(leaf_id)
                            .map_err(|_| LibraryError::custom("Expected node to be in the tree"))?;
                        // TODO #800: unmerged leaves should be checked
                        let leaf_node = leaf
                            .node()
                            .as_ref()
                            .ok_or_else(|| LibraryError::custom("Found a blank unmerged leaf"))?;
                        resolution.push(leaf_node.public_key().clone())
                    }
                }
                Ok(resolution)
            }
        } else {
            // If it's a blank, also check if it's a leaf
            if self.diff.is_leaf(node_id) {
                // If it is, just return an empty vector.
                Ok(vec![])
            } else {
                // If not, continue resolving down the tree.
                let mut resolution = Vec::new();
                let left_child = self
                    .diff
                    .left_child(node_id)
                    .map_err(|_| LibraryError::custom("Expected a parent node"))?;
                let right_child = self
                    .diff
                    .right_child(node_id)
                    .map_err(|_| LibraryError::custom("Expected a parent node"))?;
                resolution.append(&mut self.resolution(left_child, excluded_indices)?);
                resolution.append(&mut self.resolution(right_child, excluded_indices)?);
                Ok(resolution)
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
        leaf_index: LeafIndex,
        excluded_indices: &HashSet<&LeafIndex>,
    ) -> Result<Vec<Vec<HpkePublicKey>>, LibraryError> {
        let leaf = self
            .diff
            .leaf(leaf_index)
            .map_err(|_| LibraryError::custom("Expected leaf to be in tree"))?;

        // If we're the only node in the tree, there's no copath.
        if leaf == self.diff.root() {
            return Ok(vec![]);
        }

        // We want the full path here, including the leaf itself, but not the
        // root.
        let mut full_path = vec![leaf];
        let mut direct_path = self
            .diff
            .direct_path(leaf_index)
            // We know the leaf index is in the tree
            .map_err(|_| LibraryError::custom("Expected leaf index to be in tree"))?;
        if !direct_path.is_empty() {
            // Remove root
            direct_path.pop();
        }
        full_path.append(&mut direct_path);

        let mut copath_resolutions = Vec::new();
        for node_id in &full_path {
            // If sibling is not a blank, return its HpkePublicKey.
            let sibling_id = self
                .diff
                .sibling(*node_id)
                // The root should not be there anymore, hence sibling cannot fail
                .map_err(|_| LibraryError::custom("Expected root to be removed"))?;
            let resolution = self.resolution(sibling_id, excluded_indices)?;
            copath_resolutions.push(resolution);
        }
        Ok(copath_resolutions)
    }

    /// Verify the parent hashes of all nodes in the tree.
    ///
    /// Returns TreeSyncParentHashError::InvalidParentHash if a
    /// mismatching parent hash is found or a LibraryError if the
    /// tree is malformed.
    pub(crate) fn verify_parent_hashes(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<(), TreeSyncParentHashError> {
        for node_id in self.diff.iter() {
            // Continue early if node is blank.
            if let Some(Node::ParentNode(parent_node)) = self
                .diff
                .node(node_id)
                .map_err(|_| LibraryError::custom("Node not in tree"))?
                .node()
            {
                // We don't care about leaf nodes.
                let left_child_id = self
                    .diff
                    .left_child(node_id)
                    .map_err(|_| LibraryError::custom("Expected parent node"))?;
                let mut right_child_id = self
                    .diff
                    .right_child(node_id)
                    .map_err(|_| LibraryError::custom("Expected parent node"))?;
                // If the left child is blank, we continue with the next step
                // in the verification algorithm.
                if let Some(left_child) = self
                    .diff
                    .node(left_child_id)
                    .map_err(|_| LibraryError::custom("Node not in tree"))?
                    .node()
                {
                    let mut right_child_resolution =
                        self.resolution(right_child_id, &HashSet::new())?;
                    // Filter unmerged leaves from resolution.
                    self.filter_resolution(parent_node, &mut right_child_resolution)?;
                    let node_hash = parent_node.compute_parent_hash(
                        backend,
                        ciphersuite,
                        parent_node.parent_hash(),
                        &right_child_resolution,
                    )?;
                    if let Some(left_child_parent_hash) = left_child.parent_hash()? {
                        if node_hash == left_child_parent_hash {
                            // If the hashes match, we continue with the next node.
                            continue;
                        };
                    }
                }

                // If the right child is blank, replace it with its left child
                // until it's non-blank or a leaf.
                while self
                    .diff
                    .node(right_child_id)
                    .map_err(|_| LibraryError::custom("Node not in tree"))?
                    .node()
                    .is_none()
                    && !self.diff.is_leaf(right_child_id)
                {
                    right_child_id = self
                        .diff
                        .left_child(right_child_id)
                        .map_err(|_| LibraryError::custom("Expected parent node"))?;
                }
                // If the "right child" is a non-blank node, we continue,
                // otherwise it has to be a blank leaf node and the check
                // fails.
                if let Some(right_child) = self
                    .diff
                    .node(right_child_id)
                    .map_err(|_| LibraryError::custom("Node not in tree"))?
                    .node()
                {
                    // Perform the check with the parent hash of the "right
                    // child" and the left child resolution.
                    let mut left_child_resolution =
                        self.resolution(left_child_id, &HashSet::new())?;
                    // Filter unmerged leaves from resolution.
                    self.filter_resolution(parent_node, &mut left_child_resolution)?;
                    let node_hash = parent_node.compute_parent_hash(
                        backend,
                        ciphersuite,
                        parent_node.parent_hash(),
                        &left_child_resolution,
                    )?;
                    if let Some(right_child_parent_hash) = right_child.parent_hash()? {
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
            } else {
                continue;
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
    /// all nodes below it in the tree. This function respects cached tree hash
    /// values. If a cached value is found it is returned without further
    /// computation of hashes of the node or the nodes below it.
    fn compute_tree_hash(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        node_id: NodeId,
    ) -> Result<Vec<u8>, LibraryError> {
        // Check if this is a leaf.
        if let Some(leaf_index) = self.diff.leaf_index(node_id) {
            let leaf = self
                .diff
                .node_mut(node_id)
                .map_err(|_| LibraryError::custom("Expected node to be in tree"))?;
            let tree_hash =
                // Giving 0 as a node index here for now. See comment in the
                // function for context.
                leaf.compute_tree_hash(backend, ciphersuite, Some(leaf_index), 0,vec![], vec![])?;
            return Ok(tree_hash);
        }
        // Return early if there's already a cached tree hash.
        let node = self
            .diff
            .node(node_id)
            .map_err(|_| LibraryError::custom("Expected node to be in tree"))?;
        if let Some(tree_hash) = node.tree_hash() {
            return Ok(tree_hash.to_vec());
        }
        // Compute left hash.
        let left_child = self
            .diff
            .left_child(node_id)
            .map_err(|_| LibraryError::custom("Expected node to be in tree"))?;
        let left_hash = self.compute_tree_hash(backend, ciphersuite, left_child)?;
        // Compute right hash.
        let right_child = self
            .diff
            .right_child(node_id)
            .map_err(|_| LibraryError::custom("Expected node to be in tree"))?;
        let right_hash = self.compute_tree_hash(backend, ciphersuite, right_child)?;

        let node = self
            .diff
            .node_mut(node_id)
            .map_err(|_| LibraryError::custom("Expected node to be in tree"))?;
        let node_index = node_id.node_index();
        let tree_hash = node.compute_tree_hash(
            backend,
            ciphersuite,
            None,
            node_index,
            left_hash,
            right_hash,
        )?;

        Ok(tree_hash)
    }

    /// Return the own leaf index.
    pub(crate) fn own_leaf_index(&self) -> LeafIndex {
        self.own_leaf_index
    }

    /// Return a reference to our own leaf.
    pub(crate) fn own_leaf(&self) -> Result<&LeafNode, TreeSyncDiffError> {
        let leaf_id = self.diff.leaf(self.own_leaf_index)?;
        let node = self.diff.node(leaf_id)?;
        match node.node() {
            Some(node) => Ok(node.as_leaf_node()?),
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
        leaf_index_1: LeafIndex,
        leaf_index_2: LeafIndex,
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
        sender_leaf_index: LeafIndex,
        excluded_indices: &HashSet<&LeafIndex>,
    ) -> Result<(&HpkePrivateKey, usize), TreeSyncDiffError> {
        // Get the copath node of the sender that is in our direct path, as well
        // as its position in our direct path.
        let subtree_root_copath_node_id = self
            .diff
            .subtree_root_copath_node(sender_leaf_index, self.own_leaf_index)?;

        let sender_copath_resolution =
            self.resolution(subtree_root_copath_node_id, excluded_indices)?;

        // Get all of the public keys that we have secret keys for, i.e. our own
        // leaf pk, as well as potentially a number of public keys from our
        // direct path.
        let mut own_node_ids = vec![self.diff.leaf(self.own_leaf_index)?];

        own_node_ids.append(&mut self.diff.direct_path(self.own_leaf_index)?);
        for node_id in own_node_ids {
            let node_tsn = self.diff.node(node_id)?;
            // If the node is blank, skip it.
            if let Some(node) = node_tsn.node() {
                // If we don't have the private key, skip it.
                if let Some(private_key) = node.private_key() {
                    // If we do have the private key, check if the key is in the
                    // resolution.
                    if let Some(resolution_position) = sender_copath_resolution
                        .iter()
                        .position(|pk| pk == node.public_key())
                    {
                        return Ok((private_key, resolution_position));
                    };
                }
            }
        }
        Err(TreeSyncDiffError::NoPrivateKeyFound)
    }

    /// Returns a vector of all nodes in the tree resulting from merging this
    /// diff.
    pub(crate) fn export_nodes(&self) -> Result<Vec<Option<Node>>, LibraryError> {
        let nodes = self
            .diff
            .export_nodes()?
            .into_iter()
            .map(|ts_node| ts_node.node().to_owned())
            .collect();
        Ok(nodes)
    }

    /// Returns the [`KeyPackageRef`] for the own leaf in the tree resulting from
    /// merging this diff.
    ///
    /// Returns an error if the own leaf is not in the tree.
    pub(crate) fn hash_ref(&self) -> Result<&KeyPackageRef, LibraryError> {
        let node = self
            .diff
            .node(
                self.diff
                    .leaf(self.own_leaf_index)
                    .map_err(|_| LibraryError::custom("Expected own leaf to be in the tree"))?,
            )
            .map_err(|_| LibraryError::custom("Expected own leaf to be in the tree"))?;
        if let Some(Node::LeafNode(node)) = node.node() {
            node.key_package_ref()
                .ok_or_else(|| LibraryError::custom("missing key package ref"))
        } else {
            Err(LibraryError::custom("missing leaf node"))
        }
    }

    /// Get the length of the direct path of the given [`LeafIndex`].
    pub(super) fn direct_path_len(&self, leaf_index: LeafIndex) -> Result<usize, OutOfBoundsError> {
        Ok(self.diff.direct_path(leaf_index)?.len())
    }
}
