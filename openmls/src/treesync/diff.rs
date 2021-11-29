use openmls_traits::OpenMlsCryptoProvider;

use std::{collections::HashSet, convert::TryFrom};

use super::{
    node::{
        parent_node::{ParentNode, ParentNodeError, PlainUpdatePathNode},
        Node, TreeSyncNode, TreeSyncNodeError,
    },
    TreeSync,
};

use crate::{
    binary_tree::{
        array_representation::diff::NodeReference, LeafIndex, MlsBinaryTreeDiff,
        MlsBinaryTreeDiffError, StagedMlsBinaryTreeDiff,
    },
    ciphersuite::{signable::Signable, Ciphersuite, CryptoError, HpkePrivateKey, HpkePublicKey},
    credentials::{CredentialBundle, CredentialError},
    extensions::ExtensionType,
    messages::{PathSecret, PathSecretError},
    prelude::{KeyPackage, KeyPackageBundle, KeyPackageBundlePayload},
    schedule::CommitSecret,
};

pub(crate) type UpdatePathResult = (KeyPackageBundle, Vec<PlainUpdatePathNode>, CommitSecret);

#[derive(Debug)]
pub(crate) struct StagedTreeSyncDiff {
    diff: StagedMlsBinaryTreeDiff<TreeSyncNode>,
    new_tree_hash: Vec<u8>,
}

impl StagedTreeSyncDiff {
    pub(super) fn into_parts(self) -> (StagedMlsBinaryTreeDiff<TreeSyncNode>, Vec<u8>) {
        (self.diff, self.new_tree_hash)
    }
}

pub(crate) struct TreeSyncDiff<'a> {
    diff: MlsBinaryTreeDiff<'a, TreeSyncNode>,
    own_leaf_index: LeafIndex,
    node_keys: HashSet<HpkePublicKey>,
}

impl<'a> TryFrom<&'a TreeSync> for TreeSyncDiff<'a> {
    type Error = TreeSyncDiffError;

    fn try_from(tree_sync: &'a TreeSync) -> Result<Self, Self::Error> {
        Ok(TreeSyncDiff {
            diff: MlsBinaryTreeDiff::try_from(&tree_sync.tree)?,
            node_keys: HashSet::new(),
            own_leaf_index: tree_sync.own_leaf_index,
        })
    }
}

// We want to enforce a few invariants on the tree that should be explicitly
// checked before making a Diff a StagedDiff and before creating an actual tree
// from a vector of nodes.

// * Private keys should only be in our own leaf and in the direct path.
// * unmerged leaf indices should only point to non-blank leaf nodes

/// Note: Any function that modifies a node should erase the tree hash of every
/// node in its direct path. FIXME: We currently don't guarantee that we fail
/// before changing the state of the diff. E.g., if a parent hash is invalid,
/// the diff is corrupted. Is that a problem?
impl<'a> TreeSyncDiff<'a> {
    /// Check if the right-most leaf is blank. If that is the case, remove the
    /// right-most leaf until the right-most leaf is not blank anymore.
    pub(crate) fn trim_tree(&mut self) -> Result<(), TreeSyncDiffError> {
        let mut leaf_ref = self.diff.leaf(self.leaf_count() - 1)?;
        while self.diff.try_deref(leaf_ref)?.node().is_none() {
            self.diff.remove_leaf()?;
            leaf_ref = self.diff.leaf(self.leaf_count() - 1)?;
        }
        Ok(())
    }

    fn unique_key(&self, node: &Node) -> Result<(), TreeSyncDiffError> {
        if self.node_keys.contains(node.public_key()) {
            Err(TreeSyncDiffError::PublicKeyCollision)
        } else {
            Ok(())
        }
    }

    pub(crate) fn leaf_count(&self) -> LeafIndex {
        self.diff.leaf_count()
    }

    /// Update an existing leaf node and blank the nodes in the updated leaf's
    /// direct path. Returns an error if the target leaf is blank.
    pub(crate) fn update_leaf(
        &mut self,
        leaf_node: KeyPackage,
        leaf_index: LeafIndex,
    ) -> Result<(), TreeSyncDiffError> {
        let node = Node::LeafNode(leaf_node.into());
        // Check if the key of the new leaf is unique in the
        // tree.
        self.unique_key(&node)?;

        // Add the new key to the key map and remove the old one.
        self.node_keys.insert(node.public_key().clone());
        let node_ref = self.diff.leaf(leaf_index)?;
        // Can't update a blank leaf.
        let old_leaf = self
            .diff
            .try_deref(node_ref)?
            .node()
            .as_ref()
            .ok_or(TreeSyncDiffError::UpdateBlank)?;
        let removed = self.node_keys.remove(old_leaf.public_key());
        // The old key has to have been in the node map.
        debug_assert!(removed);

        self.diff.replace_leaf(leaf_index, node.into())?;
        // This effectively wipes the tree hashes in the direct path.
        self.diff
            .set_direct_path_to_node(leaf_index, &TreeSyncNode::blank())?;
        Ok(())
    }

    /// Adds a new leaf to the tree either by filling a blank leaf or by
    /// creating a new leaf, inserting intermediate blanks as necessary. This
    /// also adds the leaf_index of the new leaf to the `unmerged_leaves` state
    /// of the parent nodes in its direct path. Returns the LeafIndex of the new
    /// leaf.
    pub(crate) fn add_leaf(
        &mut self,
        leaf_node: KeyPackage,
    ) -> Result<LeafIndex, TreeSyncDiffError> {
        let node = Node::LeafNode(leaf_node.into());
        // Check if the key of the new leaf is unique in the
        // tree.
        self.unique_key(&node)?;

        self.node_keys.insert(node.public_key().clone());

        // Find a free leaf and fill it with the new key package.
        let leaf_refs = self.diff.leaves()?;
        let mut leaf_index_option = None;
        for (leaf_index, leaf_ref) in leaf_refs.iter().enumerate() {
            let leaf_index: LeafIndex =
                u32::try_from(leaf_index).map_err(|_| TreeSyncDiffError::LibraryError)?;
            if self.diff.try_deref(*leaf_ref)?.node().is_none() {
                leaf_index_option = Some(leaf_index);
                continue;
            }
        }
        // If we found a free leaf, replace it with the new one, otherwise
        // extend the tree.
        let leaf_index = if let Some(leaf_index) = leaf_index_option {
            self.diff.replace_leaf(leaf_index, node.into())?;
            leaf_index
        } else {
            self.diff.add_leaf(TreeSyncNode::blank(), node.into())?
        };
        // Add new unmerged leaves entry to all nodes in direct path. Also, wipe
        // the cached tree hash.
        for node_ref in self.diff.direct_path(leaf_index)? {
            let tsn = self.diff.try_deref_mut(node_ref)?;
            if let Some(ref mut node) = tsn.node_mut() {
                let pn = node.as_parent_node_mut()?;
                pn.add_unmerged_leaf(leaf_index);
            }
            tsn.erase_tree_hash();
        }
        Ok(leaf_index)
    }

    /// Remove a group member by blanking the target leaf and its direct path.
    /// After blanking the leaf and its direct path, the diff is trimmed, i.e.
    /// leafs are removed until the right-most leaf in the tree is non-blank.
    pub(crate) fn blank_leaf(&mut self, leaf_index: LeafIndex) -> Result<(), TreeSyncDiffError> {
        let node_ref = self.diff.leaf(leaf_index)?;
        let old_leaf = self
            .diff
            .try_deref(node_ref)?
            .node()
            .as_ref()
            .ok_or(TreeSyncDiffError::RedundantBlank)?;
        let removed = self.node_keys.remove(old_leaf.public_key());
        // The old key has to have been in the node map.
        debug_assert!(removed);

        self.diff.replace_leaf(leaf_index, TreeSyncNode::blank())?;
        // This also erases any cached tree hash in the direct path.
        self.diff
            .set_direct_path_to_node(leaf_index, &TreeSyncNode::blank())?;
        self.trim_tree()?;
        Ok(())
    }

    /// Given a [`KeyPackageBundle`], use it to re-create a path in the course
    /// of applying our own commit.
    pub(crate) fn re_apply_own_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        key_package_bundle: &KeyPackageBundle,
    ) -> Result<CommitSecret, TreeSyncDiffError> {
        let leaf_secret = key_package_bundle.leaf_secret();
        let leaf_path_secret = PathSecret::from(leaf_secret.clone());

        let path_secret = leaf_path_secret.derive_path_secret(backend, ciphersuite)?;

        let path_length = self.diff.direct_path(self.own_leaf_index)?.len();

        // The `update_path_nodes` are not needed here, because we're applying
        // our own commit rather then creating one, for which we would have to
        // encrypt the update path nodes returned here.
        let (path, _update_path_nodes, commit_secret) =
            ParentNode::derive_path(backend, ciphersuite, path_secret, path_length)?;

        // This also adds the public keys to the diff's key map.
        let parent_hash =
            self.process_update_path(backend, ciphersuite, self.own_leaf_index, path)?;

        let parent_hash_ext = key_package_bundle
            .key_package()
            .extension_with_type(ExtensionType::ParentHash)
            .ok_or(TreeSyncDiffError::MissingParentHash)?;

        // We just filtered by extensiontype, so this should be a parrent hash extension.
        let kpb_parent_hash = parent_hash_ext
            .as_parent_hash_extension()
            .map_err(|_| TreeSyncDiffError::LibraryError)?
            .parent_hash();

        // Double-check that the computed parent hash and that of the given KPB
        // match.
        if kpb_parent_hash != parent_hash {
            return Err(TreeSyncDiffError::ParentHashMismatch);
        }

        let node = Node::LeafNode(key_package_bundle.key_package().clone().into());
        // Check if the key of the new leaf is unique in the
        // tree.
        self.unique_key(&node)?;

        // Remove the key of the old leaf from the key map.
        let node_ref = self.diff.leaf(self.own_leaf_index)?;
        let old_leaf = self
            .diff
            .try_deref(node_ref)?
            .node()
            .as_ref()
            .ok_or(TreeSyncDiffError::RedundantBlank)?;
        let removed = self.node_keys.remove(old_leaf.public_key());
        // The old key has to have been in the node map.
        debug_assert!(removed);

        // Replace the leaf.
        self.diff.replace_leaf(self.own_leaf_index, node.into())?;
        Ok(commit_secret)
    }

    /// Given a [`KeyPackageBundlePayload`], use it to create a new path and
    /// apply it to this diff. The given [`CredentialBundle`] reference is used
    /// to sign the [`KeyPackageBundlePayload`], which is returned for later use
    /// with [`Self::re_apply_own_update_path`].
    pub(crate) fn apply_own_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        mut key_package_bundle_payload: KeyPackageBundlePayload,
        credential_bundle: &CredentialBundle,
    ) -> Result<UpdatePathResult, TreeSyncDiffError> {
        let leaf_secret = key_package_bundle_payload.leaf_secret();
        let leaf_path_secret = PathSecret::from(leaf_secret.clone());

        let path_secret = leaf_path_secret.derive_path_secret(backend, ciphersuite)?;

        let path_length = self.diff.direct_path(self.own_leaf_index)?.len();

        let (path, update_path_nodes, commit_secret) =
            ParentNode::derive_path(backend, ciphersuite, path_secret, path_length)?;

        // This also adds the public keys to the diff's key map.
        let parent_hash =
            self.process_update_path(backend, ciphersuite, self.own_leaf_index, path)?;

        key_package_bundle_payload.update_parent_hash(&parent_hash);
        let key_package_bundle = key_package_bundle_payload.sign(backend, credential_bundle)?;

        let node = Node::LeafNode(key_package_bundle.key_package().clone().into());
        // Check if the key of the new leaf is unique in the
        // tree.
        self.unique_key(&node)?;

        // Remove the key of the old leaf from the key map.
        let node_ref = self.diff.leaf(self.own_leaf_index)?;
        let old_leaf = self
            .diff
            .try_deref(node_ref)?
            .node()
            .as_ref()
            .ok_or(TreeSyncDiffError::RedundantBlank)?;
        let removed = self.node_keys.remove(old_leaf.public_key());
        // The old key has to have been in the node map.
        debug_assert!(removed);

        // Replace the leaf.
        self.diff.replace_leaf(self.own_leaf_index, node.into())?;
        Ok((key_package_bundle, update_path_nodes, commit_secret))
    }

    /// The given path of ParentNodes should already include any potential path
    /// secrets. FIXME: I might want to change this API, because it's slightly
    /// asymmetrical as compared to re-applying one's own update path: Here, the
    /// CommitSecret falls out of the decryption process, whereas in the other
    /// case, the commit_secret falls out of the path-application process.
    pub(crate) fn apply_received_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        sender_leaf_index: LeafIndex,
        key_package: &KeyPackage,
        path: Vec<ParentNode>,
    ) -> Result<(), TreeSyncDiffError> {
        let node = Node::LeafNode(key_package.clone().into());
        // Check if the key of the new leaf is unique in the
        // tree.
        self.unique_key(&node)?;

        let parent_hash =
            self.process_update_path(backend, ciphersuite, sender_leaf_index, path)?;
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

        // Remove the key of the old leaf from the key map.
        let node_ref = self.diff.leaf(sender_leaf_index)?;
        let old_leaf = self
            .diff
            .try_deref(node_ref)?
            .node()
            .as_ref()
            .ok_or(TreeSyncDiffError::RedundantBlank)?;
        let removed = self.node_keys.remove(old_leaf.public_key());
        // The old key has to have been in the node map.
        debug_assert!(removed);

        // Replace the leaf.
        self.diff.replace_leaf(
            sender_leaf_index,
            Node::LeafNode(key_package.clone().into()).into(),
        )?;
        Ok(())
    }

    /// Process a given update path, consisting of a vector of `Node`. This
    /// function replaces the nodes in the direct path of the given `leaf_index`
    /// with the the ones in `path`
    fn process_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        leaf_index: LeafIndex,
        mut path: Vec<ParentNode>,
    ) -> Result<Vec<u8>, TreeSyncDiffError> {
        // Compute the parent hash.
        let parent_hash = self.set_parent_hashes(backend, ciphersuite, &mut path, leaf_index)?;
        // Check that the public keys are unique in the tree.
        let mut direct_path = Vec::new();
        for node in path {
            let node = Node::ParentNode(node);
            self.unique_key(&node)?;
            direct_path.push(node.into());
        }

        // Remove the keys from the old direct path from the node_map.
        for node_ref in self.diff.direct_path(leaf_index)? {
            if let Some(node) = self.diff.try_deref(node_ref)?.node() {
                let removed = self.node_keys.remove(node.public_key());
                // The old key has to have been in the node map.
                debug_assert!(removed);
            }
        }

        // Set the direct path. Note, that the nodes here don't have a tree hash
        // set.
        self.diff.set_direct_path(leaf_index, direct_path)?;
        Ok(parent_hash)
    }

    /// Sets the path secrets, but doesn't otherwise touch the nodes. This
    /// function also checks that the derived public keys match the existing
    /// public keys.
    pub(super) fn set_path_secrets(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        mut path_secret: PathSecret,
        sender_index: LeafIndex,
    ) -> Result<(), TreeSyncDiffError> {
        let subtree_path = self.diff.subtree_path(self.own_leaf_index, sender_index)?;
        for node_ref in subtree_path {
            let tsn = self.diff.try_deref_mut(node_ref)?;
            // We only care about non-blank nodes.
            if let Some(ref mut node) = tsn.node_mut() {
                // This has to be a parent node.
                let pn = node.as_parent_node_mut()?;
                // If our own leaf index is not in the list of unmerged leaves
                // then we should have the secret for this node.
                if !pn.unmerged_leaves().contains(&self.own_leaf_index) {
                    let (public_key, private_key) =
                        path_secret.derive_key_pair(backend, ciphersuite)?;
                    // The derived public key should match the one in the node.
                    // If not, the tree is corrupt.
                    if pn.public_key() != &public_key {
                        return Err(TreeSyncDiffError::PublicKeyMismatch);
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
        Ok(())
    }

    /// A helper function that filters the unmerged leaves of the given node
    /// from the given resolution.
    fn filter_resolution(
        &self,
        parent_node: &ParentNode,
        resolution: &mut Vec<HpkePublicKey>,
    ) -> Result<(), TreeSyncDiffError> {
        for leaf_index in parent_node.unmerged_leaves() {
            let leaf_ref = self.diff.leaf(*leaf_index)?;
            let leaf = self.diff.try_deref(leaf_ref)?;
            // All unmerged leaves should be non-blank.
            let leaf_node = leaf
                .node()
                .as_ref()
                .ok_or(TreeSyncDiffError::LibraryError)?;
            let leaf = leaf_node.as_leaf_node()?;
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
        let mut copath_resolutions = self.copath_resolutions(leaf_index, &HashSet::new())?;
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
            self.filter_resolution(path_node, resolution)?;
            let parent_hash = path_node.compute_parent_hash(
                backend,
                ciphersuite,
                &previous_parent_hash,
                resolution,
            )?;
            path_node.set_parent_hash(parent_hash.clone());
            previous_parent_hash = parent_hash
        }
        // The final hash is the one of the leaf's parent.
        Ok(previous_parent_hash)
    }

    /// Helper function computing the resolution of a node with the given index.
    /// If an exclusion list is given, do not add the public keys of the leaves
    /// given in the list.
    fn resolution(
        &self,
        node_ref: NodeReference,
        excluded_indices: &HashSet<&LeafIndex>,
    ) -> Result<Vec<HpkePublicKey>, TreeSyncDiffError> {
        if let Some(node) = self.diff.try_deref(node_ref)?.node() {
            // If the node is a leaf, check if it is in the exclusion list.
            if let Some(leaf_index) = self.diff.leaf_index(node_ref) {
                if excluded_indices.contains(&leaf_index) {
                    return Ok(vec![]);
                }
            }
            return Ok(vec![node.public_key().clone()]);
        }
        let mut resolution = Vec::new();
        let left_child = self.diff.left_child(node_ref)?;
        let right_child = self.diff.right_child(node_ref)?;
        resolution.append(&mut self.resolution(left_child, excluded_indices)?);
        resolution.append(&mut self.resolution(right_child, excluded_indices)?);
        Ok(resolution)
    }

    /// Compute the resolution of the copath of the leaf node corresponding to
    /// the given leaf index. This includes the neighbour of the given leaf. If
    /// an exclusion list is given, do not add the public keys of the leaves
    /// given in the list.
    pub(crate) fn copath_resolutions(
        &self,
        leaf_index: LeafIndex,
        excluded_indices: &HashSet<&LeafIndex>,
    ) -> Result<Vec<Vec<HpkePublicKey>>, TreeSyncDiffError> {
        let leaf = self.diff.leaf(leaf_index)?;
        let mut full_path = vec![leaf];
        let mut direct_path = self.diff.direct_path(leaf_index)?;
        full_path.append(&mut direct_path);

        let mut copath_resolutions = Vec::new();
        for node_ref in &full_path {
            // If sibling is not a blank, return its HpkePublicKey.
            let sibling_ref = self.diff.sibling(*node_ref)?;
            let resolution = self.resolution(sibling_ref, excluded_indices)?;
            copath_resolutions.push(resolution);
        }
        Ok(copath_resolutions)
    }

    pub(crate) fn verify_parent_hashes(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
    ) -> Result<(), TreeSyncDiffError> {
        for node_ref in self.diff.iter() {
            // Continue early if node is blank.
            if let Some(Node::ParentNode(parent_node)) = self.diff.try_deref(node_ref)?.node() {
                // We don't care about leaf nodes.
                let left_child_ref = self.diff.left_child(node_ref)?;
                let mut right_child_ref = self.diff.right_child(node_ref)?;
                // If the left node is blank, we continue with the next step
                // in the verification algorithm.
                if let Some(left_child) = self.diff.try_deref(left_child_ref)?.node() {
                    let mut right_child_resolution =
                        self.resolution(right_child_ref, &HashSet::new())?;
                    // Filter unmerged leaves from resolution.
                    self.filter_resolution(parent_node, &mut right_child_resolution)?;
                    let node_hash = parent_node.compute_parent_hash(
                        backend,
                        ciphersuite,
                        parent_node.parent_hash(),
                        &right_child_resolution,
                    )?;
                    if node_hash == left_child.parent_hash()? {
                        continue;
                    } else {
                        return Err(TreeSyncDiffError::InvalidParentHash);
                    };
                }

                // If the right child is blank, replace it with its left child
                // until it's non-blank or a leaf.
                while self.diff.try_deref(right_child_ref)?.node().is_none()
                    && !self.diff.is_leaf(right_child_ref)
                {
                    right_child_ref = self.diff.left_child(right_child_ref)?;
                }
                // If the "right child" is a non-blank node, we continue,
                // otherwise it has to be a blank leaf node and the check
                // fails.
                if let Some(right_child) = self.diff.try_deref(right_child_ref)?.node() {
                    // Perform the check with the parent hash of the "right
                    // child" and the left child resolution.
                    let mut left_child_resolution =
                        self.resolution(left_child_ref, &HashSet::new())?;
                    // Filter unmerged leaves from resolution.
                    self.filter_resolution(parent_node, &mut left_child_resolution)?;
                    let node_hash = parent_node.compute_parent_hash(
                        backend,
                        ciphersuite,
                        parent_node.parent_hash(),
                        &left_child_resolution,
                    )?;
                    if node_hash == right_child.parent_hash()? {
                        continue;
                    } else {
                        return Err(TreeSyncDiffError::InvalidParentHash);
                    };
                } else {
                    return Err(TreeSyncDiffError::InvalidParentHash);
                }
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
        ciphersuite: &Ciphersuite,
    ) -> Result<StagedTreeSyncDiff, TreeSyncDiffError> {
        let new_tree_hash = self.compute_tree_hash(backend, ciphersuite)?;
        Ok(StagedTreeSyncDiff {
            diff: self.diff.into(),
            new_tree_hash,
        })
    }

    fn set_tree_hash(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        node_ref: NodeReference,
    ) -> Result<Vec<u8>, TreeSyncDiffError> {
        // Check if this is a leaf.
        if let Some(leaf_index) = self.diff.leaf_index(node_ref) {
            let leaf = self.diff.try_deref_mut(node_ref)?;
            let tree_hash =
                leaf.compute_tree_hash(backend, ciphersuite, Some(leaf_index), vec![], vec![])?;
            return Ok(tree_hash);
        }
        // Return early if there's already a cached tree hash.
        let node = self.diff.try_deref(node_ref)?;
        if let Some(tree_hash) = node.tree_hash() {
            return Ok(tree_hash.to_vec());
        }
        // Compute left hash.
        let left_child = self.diff.left_child(node_ref)?;
        let left_hash = self.set_tree_hash(backend, ciphersuite, left_child)?;
        // Compute right hash.
        let right_child = self.diff.right_child(node_ref)?;
        let right_hash = self.set_tree_hash(backend, ciphersuite, right_child)?;

        let node = self.diff.try_deref_mut(node_ref)?;
        let tree_hash =
            node.compute_tree_hash(backend, ciphersuite, None, left_hash, right_hash)?;

        Ok(tree_hash)
    }

    pub(crate) fn compute_tree_hash(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
    ) -> Result<Vec<u8>, TreeSyncDiffError> {
        self.set_tree_hash(backend, ciphersuite, self.diff.root())
    }

    /// Returns the position of the shared subtree root in the direct path of
    /// the given leaf index.
    pub(crate) fn subtree_root_position(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<usize, TreeSyncDiffError> {
        Ok(self
            .diff
            .subtree_root_position(leaf_index, self.own_leaf_index)?)
    }

    /// Returns the positions in the filtered copath resolution (i.e. the
    /// position in the copath, as well as the position in the resolution of the
    /// copath node), as well as the matching private key.
    pub(crate) fn decryption_key(
        &self,
        sender_leaf_index: LeafIndex,
        excluded_indices: &HashSet<&LeafIndex>,
    ) -> Result<(&HpkePrivateKey, usize), TreeSyncDiffError> {
        // Get the copath node of the sender that is in our direct path, as well
        // as its position in our direct path.
        let subtree_root_ref = self
            .diff
            .subtree_root_copath_node(sender_leaf_index, self.own_leaf_index)?;

        let sender_copath_resolution = self.resolution(subtree_root_ref, excluded_indices)?;

        // Get all of the public keys that we have secret keys for, i.e. our own
        // leaf pk, as well as potentially a number of public keys from our
        // direct path.
        let mut own_node_refs = vec![self.diff.leaf(self.own_leaf_index)?];
        own_node_refs.append(&mut self.diff.direct_path(self.own_leaf_index)?);
        // Add our own key package public key.
        for node_ref in own_node_refs {
            let node_tsn = self.diff.try_deref(node_ref)?;
            //let node_tsn = node_ref.try_deref()?;
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

    pub(crate) fn export_nodes(&self) -> Result<Vec<Option<Node>>, TreeSyncDiffError> {
        let nodes = self
            .diff
            .export_nodes()?
            .drain(..)
            .map(|ts_node| ts_node.node().to_owned())
            .collect();
        Ok(nodes)
    }
}

implement_error! {
    pub enum TreeSyncDiffError {
        Simple {
            LibraryError = "An unrecoverable error has occurred.",
            PathLengthError = "The given path does not have the length of the given leaf's direct path.",
            MissingParentHash = "The given key package does not contain a parent hash extension.",
            ParentHashMismatch = "The parent hash of the given key package is invalid.",
            InvalidParentHash = "The parent hash of a node in the given tree is invalid.",
            PublicKeyCollision = "The public key of the new node is not unique in the tree.",
            RedundantBlank = "The leaf we were trying to blank is already blank.",
            UpdateBlank = "The leaf we were trying to update is blank.",
            PublicKeyMismatch = "The derived public key doesn't match the one in the tree.",
            NoPrivateKeyFound = "Couldn't find a fitting private key in the filtered resolution of the given leaf index.",
        }
        Complex {
            TreeSyncNodeError(TreeSyncNodeError) = "We found a node with an unexpected type.",
            TreeDiffError(MlsBinaryTreeDiffError) = "An error occurred while operating on the diff.",
            CredentialError(CredentialError) = "An error occurred while signing a `KeyPackage`.",
            CryptoError(CryptoError) = "An error occurred during key derivation.",
            DerivationError(PathSecretError) = "An error occurred during PathSecret derivation.",
            ParentNodeError(ParentNodeError) = "An error occurred during path derivation.",
        }
    }
}
