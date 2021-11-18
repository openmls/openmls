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
        MlsBinaryTreeDiffError, MlsBinaryTreeError, StagedMlsBinaryTreeDiff,
    },
    ciphersuite::{signable::Signable, Ciphersuite, CryptoError, HpkePrivateKey, HpkePublicKey},
    credentials::{CredentialBundle, CredentialError},
    extensions::ExtensionType,
    messages::{PathSecret, PathSecretError},
    prelude::{KeyPackage, KeyPackageBundlePayload},
    schedule::CommitSecret,
};

pub(crate) struct StagedTreeSyncDiff {
    diff: StagedMlsBinaryTreeDiff<TreeSyncNode>,
    new_tree_hash: Vec<u8>,
}

impl StagedTreeSyncDiff {
    pub(super) fn into_parts(self) -> (StagedMlsBinaryTreeDiff<TreeSyncNode>, Vec<u8>) {
        (self.diff, self.new_tree_hash)
    }

    pub(crate) fn new_tree_hash(&self) -> &[u8] {
        &self.new_tree_hash
    }
}

pub(crate) struct TreeSyncDiff<'a> {
    diff: MlsBinaryTreeDiff<'a, TreeSyncNode>,
    own_leaf_index: LeafIndex,
    node_keys: HashSet<HpkePublicKey>,
}

impl<'a> From<&'a TreeSync> for TreeSyncDiff<'a> {
    fn from(tree_sync: &'a TreeSync) -> Self {
        TreeSyncDiff {
            diff: MlsBinaryTreeDiff::from(&tree_sync.tree),
            node_keys: HashSet::new(),
            own_leaf_index: tree_sync.own_leaf_index,
        }
    }
}

/// Note: Any function that modifies a node should erase the tree hash of every
/// node in its direct path. FIXME: We currently don't guarantee that we fail
/// before changing the state of the diff. E.g., if a parent hash is invalid,
/// the diff is corrupted. Is that a problem?
impl<'a> TreeSyncDiff<'a> {
    fn unique_key(&self, node: &Node) -> Result<(), TreeSyncDiffError> {
        if self.node_keys.contains(node.public_key()) {
            Err(TreeSyncDiffError::PublicKeyCollision)
        } else {
            Ok(())
        }
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
        let old_leaf = node_ref
            .try_deref()?
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
    /// of the parent nodes in its direct path.
    pub(crate) fn add_leaf(&mut self, leaf_node: KeyPackage) -> Result<(), TreeSyncDiffError> {
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
            if leaf_ref.try_deref()?.node().is_none() {
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
    pub(crate) fn blank_leaf(&mut self, leaf_index: LeafIndex) -> Result<(), TreeSyncDiffError> {
        let node_ref = self.diff.leaf(leaf_index)?;
        let old_leaf = node_ref
            .try_deref()?
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
        Ok(())
    }

    pub(crate) fn apply_own_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        key_package_bundle_payload: KeyPackageBundlePayload,
        credential_bundle: &CredentialBundle,
    ) -> Result<(KeyPackage, Vec<PlainUpdatePathNode>, CommitSecret), TreeSyncDiffError> {
        let (mut key_package_payload, leaf_secret) = key_package_bundle_payload.into_parts();
        let leaf_path_secret = PathSecret::from(leaf_secret);

        let path_secret = leaf_path_secret.derive_path_secret(backend, ciphersuite)?;

        let path_length = self.diff.direct_path(self.own_leaf_index)?.len();

        let (path, update_path_nodes, commit_secret) =
            ParentNode::derive_path(backend, ciphersuite, path_secret, path_length)?;

        // This also adds the public keys to the diff's key map.
        let parent_hash =
            self.process_update_path(backend, ciphersuite, self.own_leaf_index, path.clone())?;

        key_package_payload.update_parent_hash(&parent_hash);
        let key_package = key_package_payload.sign(backend, credential_bundle)?;

        let node = Node::LeafNode(key_package.clone().into());
        // Check if the key of the new leaf is unique in the
        // tree.
        self.unique_key(&node)?;

        // Remove the key of the old leaf from the key map.
        let node_ref = self.diff.leaf(self.own_leaf_index)?;
        let old_leaf = node_ref
            .try_deref()?
            .node()
            .as_ref()
            .ok_or(TreeSyncDiffError::RedundantBlank)?;
        let removed = self.node_keys.remove(old_leaf.public_key());
        // The old key has to have been in the node map.
        debug_assert!(removed);

        // Replace the leaf.
        self.diff.replace_leaf(self.own_leaf_index, node.into())?;
        Ok((key_package, update_path_nodes, commit_secret))
    }

    pub(crate) fn apply_received_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        sender_leaf_index: LeafIndex,
        key_package: &KeyPackage,
        path: Vec<ParentNode>,
        path_secret: PathSecret,
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

        // Set the path secrets using the given path secret.
        self.set_path_secrets(backend, ciphersuite, path_secret, sender_leaf_index)?;

        // Remove the key of the old leaf from the key map.
        let node_ref = self.diff.leaf(sender_leaf_index)?;
        let old_leaf = node_ref
            .try_deref()?
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
            if let Some(node) = node_ref.try_deref()?.node() {
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

    /// Sets the path secrets, but doesn't otherwise touch the nodes.
    pub(super) fn set_path_secrets(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        mut path_secret: PathSecret,
        sender_index: LeafIndex,
    ) -> Result<(), TreeSyncDiffError> {
        let set_path_secret = |tsn: &mut TreeSyncNode| -> Result<(), TreeSyncDiffError> {
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
            Ok(())
        };
        self.diff
            .apply_to_subtree_path(self.own_leaf_index, sender_index, set_path_secret)?;
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
            let leaf = leaf_ref.try_deref()?;
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
        let mut copath_resolutions = self.copath_resolutions(leaf_index, &[])?;
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
        node_ref: NodeReference<'a, TreeSyncNode>,
        exclusion_list: &[LeafIndex],
    ) -> Result<Vec<HpkePublicKey>, TreeSyncDiffError> {
        if let Some(node) = node_ref.try_deref()?.node() {
            // If the node is a leaf, check if it is in the exclusion list.
            if let Some(leaf_index) = node_ref.leaf_index() {
                if exclusion_list.contains(&leaf_index) {
                    return Ok(vec![]);
                }
            }
            return Ok(vec![node.public_key().clone()]);
        }
        let mut resolution = Vec::new();
        // FIXME: I don't quite understand why I have to clone here.
        // NodeReference should implement the Copy trait.
        let left_child = node_ref.clone().left_child()?;
        let right_child = node_ref.right_child()?;
        resolution.append(&mut self.resolution(left_child, exclusion_list)?);
        resolution.append(&mut self.resolution(right_child, exclusion_list)?);
        Ok(resolution)
    }

    /// Compute the resolution of the copath of the leaf node corresponding to
    /// the given leaf index. This includes the neighbour of the given leaf. If
    /// an exclusion list is given, do not add the public keys of the leaves
    /// given in the list.
    pub(crate) fn copath_resolutions(
        &self,
        leaf_index: LeafIndex,
        exclusion_list: &[LeafIndex],
    ) -> Result<Vec<Vec<HpkePublicKey>>, TreeSyncDiffError> {
        let leaf = self.diff.leaf(leaf_index)?;
        let mut full_path = vec![leaf];
        let mut direct_path = self.diff.direct_path(leaf_index)?;
        full_path.append(&mut direct_path);

        let mut copath_resolutions = Vec::new();
        for node_ref in &full_path {
            // If sibling is not a blank, return its HpkePublicKey.
            // FIXME: I don't quite understand why I have to clone here.
            // NodeReference should implement the Copy trait.
            let sibling_ref = node_ref.clone().sibling()?;
            let resolution = self.resolution(sibling_ref, &[])?;
            copath_resolutions.push(resolution);
        }
        Ok(copath_resolutions)
    }

    pub(crate) fn verify_parent_hashes(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
    ) -> Result<(), TreeSyncDiffError> {
        let node_refs = self.diff.all_nodes();
        for node_ref in &node_refs {
            // Continue early if node is blank.
            if let Some(node) = node_ref.try_deref()?.node() {
                // We don't care about leaf nodes.
                if let Node::ParentNode(parent_node) = node {
                    let left_child_ref = node_ref.clone().left_child()?;
                    let mut right_child_ref = node_ref.clone().right_child()?;
                    // If the left node is blank, we continue with the next step
                    // in the verification algorithm.
                    if let Some(left_child) = left_child_ref.try_deref()?.node() {
                        let mut right_child_resolution =
                            self.resolution(right_child_ref.clone(), &[])?;
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
                    while right_child_ref.try_deref()?.node().is_none()
                        && !right_child_ref.is_leaf()
                    {
                        right_child_ref = right_child_ref.left_child()?;
                    }
                    // If the "right child" is a non-blank node, we continue,
                    // otherwise it has to be a blank leaf node and the check
                    // fails.
                    if let Some(right_child) = right_child_ref.try_deref()?.node() {
                        // Perform the check with the parent hash of the "right
                        // child" and the left child resolution.
                        let mut left_child_resolution =
                            self.resolution(left_child_ref.clone(), &[])?;
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
            } else {
                continue;
            }
        }
        Ok(())
    }

    /// This turns the diff into a staged diff. In the process, the diff
    /// computes and sets the new tree hash.
    pub(crate) fn to_staged_diff(
        mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
    ) -> Result<StagedTreeSyncDiff, TreeSyncDiffError> {
        let new_tree_hash = self.set_tree_hashes(backend, ciphersuite)?;
        Ok(StagedTreeSyncDiff {
            diff: self.diff.into(),
            new_tree_hash,
        })
    }

    fn set_tree_hashes(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
    ) -> Result<Vec<u8>, TreeSyncDiffError> {
        let compute_tree_hash = |node: &mut TreeSyncNode,
                                 leaf_index_option: Option<LeafIndex>,
                                 left_hash: Vec<u8>,
                                 right_hash: Vec<u8>|
         -> Result<Vec<u8>, TreeSyncNodeError> {
            node.compute_tree_hash(
                backend,
                ciphersuite,
                leaf_index_option,
                left_hash,
                right_hash,
            )
        };

        Ok(self.diff.fold_tree(compute_tree_hash)?)
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
        exclusion_list: &[LeafIndex],
    ) -> Result<(&HpkePrivateKey, usize), TreeSyncDiffError> {
        // Get the copath node of the sender that is in our direct path, as well
        // as its position in our direct path.
        let subtree_root_ref = self
            .diff
            .subtree_root_copath_node(sender_leaf_index, self.own_leaf_index)?;

        let sender_copath_resolution = self.resolution(subtree_root_ref, exclusion_list)?;

        // Get all of the public keys that we have secret keys for, i.e. our own
        // leaf pk, as well as potentially a number of public keys from our
        // direct path.
        let mut own_node_refs = vec![self.diff.leaf(self.own_leaf_index)?];
        own_node_refs.append(&mut self.diff.direct_path(self.own_leaf_index)?);
        // Add our own key package public key.
        for node_ref in own_node_refs {
            let node_tsn = self.diff.dereference(node_ref)?;
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
