use crate::ciphersuite::*;
use crate::codec::*;
use crate::config::Config;
use crate::credentials::*;
use crate::key_packages::*;
use crate::messages::proposals::*;

// Tree modules
pub(crate) mod codec;
pub mod errors;
pub(crate) mod hashes;
pub mod index;
pub mod node;
pub(crate) mod path_keys;
pub(crate) mod private_tree;
pub(crate) mod secret_tree;
pub(crate) mod sender_ratchet;
pub(crate) mod treemath;

pub(crate) use errors::*;
pub use hashes::*;
use index::*;
use node::*;
use private_tree::PrivateTree;

use crate::schedule::CommitSecret;
pub(crate) use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};

use std::collections::HashSet;
use std::convert::TryInto;

#[cfg(test)]
mod tests;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
/// The ratchet tree.
pub struct RatchetTree {
    /// The ciphersuite used in this tree.
    ciphersuite: &'static Ciphersuite,

    /// All nodes in the tree.
    /// Note that these only hold public values.
    /// Private values are stored in the `private_tree`.
    pub nodes: Vec<Node>,

    /// This holds all private values in the tree.
    /// See `PrivateTree` for details.
    private_tree: PrivateTree,
}

implement_persistence!(RatchetTree, nodes, private_tree);

impl RatchetTree {
    /// Create a new empty `RatchetTree`.
    pub(crate) fn new(ciphersuite: &'static Ciphersuite, kpb: KeyPackageBundle) -> RatchetTree {
        let nodes = vec![Node {
            node_type: NodeType::Leaf,
            key_package: Some(kpb.key_package().clone()),
            node: None,
        }];
        let private_tree = PrivateTree::from_key_package_bundle(LeafIndex::from(0u32), &kpb);

        RatchetTree {
            ciphersuite,
            nodes,
            private_tree,
        }
    }

    /// Create a new `RatchetTree` by cloning the public tree nodes from another
    /// tree and an empty `PrivateTree`
    pub(crate) fn new_from_public_tree(ratchet_tree: &RatchetTree) -> Self {
        RatchetTree {
            ciphersuite: ratchet_tree.ciphersuite,
            nodes: ratchet_tree.nodes.clone(),
            private_tree: PrivateTree::new(ratchet_tree.private_tree.leaf_index()),
        }
    }

    /// Generate a new `RatchetTree` from `Node`s with the client's key package
    /// bundle `kpb`.
    pub(crate) fn new_from_nodes(
        ciphersuite: &'static Ciphersuite,
        kpb: KeyPackageBundle,
        node_options: &[Option<Node>],
    ) -> Result<RatchetTree, TreeError> {
        fn find_kp_in_tree(
            key_package: &KeyPackage,
            nodes: &[Option<Node>],
        ) -> Result<LeafIndex, TreeError> {
            // Only search in leaf nodes
            for (i, node_option) in nodes.iter().enumerate().step_by(2) {
                if let Some(node) = node_option {
                    if let Some(kp) = &node.key_package {
                        if kp == key_package {
                            // Unwrapping here is safe, because we know it is a leaf node
                            return Ok(NodeIndex::from(i).try_into().unwrap());
                        }
                    }
                }
            }
            Err(TreeError::InvalidArguments)
        }

        // Find the own node in the list of nodes.
        let own_node_index = find_kp_in_tree(kpb.key_package(), node_options)?;

        // Build a full set of nodes for the tree based on the potentially incomplete
        // input nodes.
        let mut nodes = Vec::with_capacity(node_options.len());
        for (i, node_option) in node_options.iter().enumerate() {
            if let Some(node) = node_option.clone() {
                nodes.push(node);
            } else if NodeIndex::from(i).is_leaf() {
                nodes.push(Node::new_leaf(None));
            } else {
                nodes.push(Node::new_blank_parent_node());
            }
        }

        // Build private tree
        let private_tree = PrivateTree::from_key_package_bundle(own_node_index, &kpb);

        // Build tree.
        Ok(RatchetTree {
            ciphersuite,
            nodes,
            private_tree,
        })
    }

    /// Return a mutable reference to the `PrivateTree`.
    pub(crate) fn private_tree_mut(&mut self) -> &mut PrivateTree {
        &mut self.private_tree
    }

    /// Return a reference to the `PrivateTree`.
    pub(crate) fn private_tree(&self) -> &PrivateTree {
        &self.private_tree
    }

    fn tree_size(&self) -> NodeIndex {
        NodeIndex::from(self.nodes.len())
    }

    /// Get a vector with all nodes in the tree, containing `None` for blank
    /// nodes.
    pub fn public_key_tree(&self) -> Vec<Option<&Node>> {
        let mut tree = vec![];
        for node in self.nodes.iter() {
            if node.is_blank() {
                tree.push(None)
            } else {
                tree.push(Some(node))
            }
        }
        tree
    }

    /// Get a vector with a copy of all nodes in the tree, containing `None` for
    /// blank nodes.
    pub fn public_key_tree_copy(&self) -> Vec<Option<Node>> {
        self.public_key_tree()
            .iter()
            .map(|&n| match n {
                Some(v) => Some(v.clone()),
                None => None,
            })
            .collect()
    }

    /// Returns the number of leaves in a tree
    pub fn leaf_count(&self) -> LeafIndex {
        treemath::leaf_count(self.tree_size())
    }

    /// Compute the resolution for a given node index. Nodes listed in the
    /// `exclusion_list` are substracted from the final resolution.
    fn resolve(&self, index: NodeIndex, exclusion_list: &HashSet<&NodeIndex>) -> Vec<NodeIndex> {
        let size = self.leaf_count();

        // We end the recursion at leaf level
        if self.nodes[index].node_type == NodeType::Leaf {
            if self.nodes[index].is_blank() || exclusion_list.contains(&index) {
                return vec![];
            } else {
                return vec![index];
            }
        }

        // If a node is not blank, we only return the unmerged leaves of that node
        if !self.nodes[index].is_blank() {
            let mut unmerged_leaves = vec![index];
            let node = &self.nodes[index].node.as_ref();
            unmerged_leaves.extend(
                node.unwrap()
                    .unmerged_leaves()
                    .iter()
                    .map(|n| NodeIndex::from(*n)),
            );
            unmerged_leaves
        } else {
            // Otherwise we take the resolution of the children
            // Unwrapping here is safe, since parent nodes always have children
            let mut left = self.resolve(treemath::left(index).unwrap(), exclusion_list);
            let right = self.resolve(treemath::right(index, size).unwrap(), exclusion_list);
            // We concatenate the resolution and return it
            left.extend(right);
            left
        }
    }

    /// Get the index of the own node.
    pub(crate) fn own_node_index(&self) -> LeafIndex {
        self.private_tree.leaf_index()
    }

    /// Get a reference to the own key package.
    pub fn own_key_package(&self) -> &KeyPackage {
        let own_node = &self.nodes[self.own_node_index()];
        own_node.key_package.as_ref().unwrap()
    }

    /// Get a mutable reference to the own key package.
    fn own_key_package_mut(&mut self) -> &mut KeyPackage {
        let own_node = self
            .nodes
            .get_mut(NodeIndex::from(self.private_tree.leaf_index()).as_usize())
            .unwrap();
        own_node.key_package_mut().unwrap()
    }

    /// Blanks all the nodes in the direct path of a member
    fn blank_member(&mut self, index: LeafIndex) {
        let size = self.leaf_count();
        self.nodes[index].blank();
        self.nodes[treemath::root(size)].blank();
        // Unwrapping here is safe, because we start at the leaf level
        for index in treemath::leaf_direct_path(index, size).unwrap() {
            self.nodes[index].blank();
        }
    }

    /// Returns the list of blank leaves within the tree
    fn free_leaves(&self) -> Vec<LeafIndex> {
        let mut free_leaves = vec![];
        for i in 0..self.leaf_count().as_usize() {
            // TODO use an iterator instead
            let leaf_index = LeafIndex::from(i);
            if self.nodes[leaf_index].is_blank() {
                free_leaves.push(leaf_index);
            }
        }
        free_leaves
    }

    /// 7.7. Update Paths
    ///
    /// Update the path for incoming commits.
    ///
    /// > The path contains a public key and encrypted secret value for all
    /// > intermediate nodes in the path above the leaf. The path is ordered
    /// > from the closest node to the leaf to the root; each node MUST be the
    /// > parent of its predecessor.
    pub(crate) fn update_path(
        &mut self,
        sender: LeafIndex,
        update_path: &UpdatePath,
        group_context: &[u8],
        new_leaves_indexes: HashSet<&NodeIndex>,
    ) -> Result<&CommitSecret, TreeError> {
        let own_index = NodeIndex::from(self.own_node_index());

        // Find common ancestor of own leaf and sender leaf
        let common_ancestor_index =
            treemath::common_ancestor_index(NodeIndex::from(sender), own_index);

        // Calculate sender direct path & co-path, common path
        let sender_direct_path = treemath::leaf_direct_path(sender, self.leaf_count())
            .expect("update_path: Error when computing direct path.");
        let sender_co_path = treemath::copath(sender, self.leaf_count())
            .expect("update_path: Error when computing copath.");

        // Find the position of the common ancestor in the sender's direct path
        let common_ancestor_sender_dirpath_index = &sender_direct_path
            .iter()
            .position(|&x| x == common_ancestor_index)
            .unwrap();
        let common_ancestor_copath_index =
            match sender_co_path.get(*common_ancestor_sender_dirpath_index) {
                Some(i) => *i,
                None => return Err(TreeError::InvalidArguments),
            };

        // We can unwrap here, because own index is always within the tree.
        let own_direct_path =
            treemath::leaf_direct_path(self.own_node_index(), self.leaf_count()).unwrap();

        // Resolve the node of that co-path index
        let resolution = self.resolve(common_ancestor_copath_index, &new_leaves_indexes);

        // Figure out the position in the resolution of the node that is either
        // our own leaf node or a node in our direct path.
        let position_in_resolution = resolution
            .iter()
            .position(|&x| own_direct_path.contains(&x) || own_index == x)
            // We can unwrap here, because regardless of what the resolution
            // looks like, there has to be a an entry in the resolution that
            // corresponds to either the own leaf or a node in the direct path.
            .unwrap();

        // Decrypt the ciphertext of that node
        let common_ancestor_node =
            match update_path.nodes.get(*common_ancestor_sender_dirpath_index) {
                Some(node) => node,
                None => return Err(TreeError::InvalidArguments),
            };
        debug_assert_eq!(
            resolution.len(),
            common_ancestor_node.encrypted_path_secret.len()
        );
        if resolution.len() != common_ancestor_node.encrypted_path_secret.len() {
            return Err(TreeError::InvalidUpdatePath);
        }
        let hpke_ciphertext = &common_ancestor_node.encrypted_path_secret[position_in_resolution];

        // Get the HPKE private key.
        // It's either the own key or must be in the path of the private tree.
        let private_key = if resolution[position_in_resolution] == own_index {
            self.private_tree.hpke_private_key()
        } else {
            match self
                .private_tree
                .path_keys()
                .get(resolution[position_in_resolution])
            {
                Some(k) => k,
                None => return Err(TreeError::InvalidArguments),
            }
        };

        // Compute the common path between the common ancestor and the root
        let common_path = treemath::parent_direct_path(common_ancestor_index, self.leaf_count())
            .expect("update_path: Error when computing direct path.");

        debug_assert!(
            sender_direct_path.len() >= common_path.len(),
            "Library error. Direct path cannot be shorter than common path."
        );

        // Decrypt the secret and derive path secrets
        let secret = Secret::from(self.ciphersuite.hpke_open(
            hpke_ciphertext,
            &private_key,
            group_context,
            &[],
        )?);
        // Derive new path secrets and generate keypairs
        let new_path_public_keys =
            self.private_tree
                .continue_path_secrets(&self.ciphersuite, secret, &common_path);

        // Extract public keys from UpdatePath
        let update_path_public_keys: Vec<HPKEPublicKey> = update_path
            .nodes
            .iter()
            .map(|node| node.public_key.clone())
            .collect();

        // Check that the public keys are consistent with the update path.
        let (_, common_public_keys) =
            update_path_public_keys.split_at(update_path_public_keys.len() - common_path.len());

        if new_path_public_keys != common_public_keys {
            return Err(TreeError::InvalidUpdatePath);
        }

        // Merge new nodes into the tree
        self.merge_direct_path_keys(update_path, sender_direct_path)?;
        self.merge_public_keys(&new_path_public_keys, &common_path)?;
        self.nodes[sender] = Node::new_leaf(Some(update_path.leaf_key_package.clone()));
        // Calculate and set the parent hashes
        self.set_parent_hashes(sender);

        // TODO: Do we really want to return the commit secret here?
        Ok(self.private_tree.commit_secret())
    }

    /// Update the private tree with the new `KeyPackageBundle`.
    pub(crate) fn replace_private_tree(
        &mut self,
        key_package_bundle: &KeyPackageBundle,
        group_context: &[u8],
    ) -> &CommitSecret {
        let _path_option = self.replace_private_tree_(
            key_package_bundle,
            group_context,
            None, /* without update path */
        );
        self.private_tree.commit_secret()
    }

    /// Update the private tree.
    ///
    /// Returns the update path and an updated key package bundle.
    pub(crate) fn refresh_private_tree(
        &mut self,
        credential_bundle: &CredentialBundle,
        group_context: &[u8],
        new_leaves_indexes: HashSet<&NodeIndex>,
    ) -> (UpdatePath, KeyPackageBundle) {
        // Generate new keypair
        let own_index = self.own_node_index();

        // Replace the init key in the current KeyPackage
        let mut key_package_bundle =
            KeyPackageBundle::from_rekeyed_key_package(self.own_key_package());

        // Replace the private tree with a new one based on the new key package
        // bundle and store the key package in the own node.
        let mut path = self
            .replace_private_tree_(
                &key_package_bundle,
                group_context,
                Some(new_leaves_indexes), /* with update path */
            )
            .unwrap();

        // Compute the parent hash extension and update the KeyPackage and sign it
        let parent_hash = self.set_parent_hashes(own_index);
        let key_package = self.own_key_package_mut();
        key_package.update_parent_hash(&parent_hash);
        // Sign the KeyPackage
        key_package.sign(credential_bundle);
        // Store it in the UpdatePath
        path.leaf_key_package = key_package.clone();
        // Update it in the KeyPackageBundle
        key_package_bundle.set_key_package(key_package.clone());

        (path, key_package_bundle)
    }

    /// Replace the private tree with a new one based on the
    /// `key_package_bundle`.
    fn replace_private_tree_(
        &mut self,
        key_package_bundle: &KeyPackageBundle,
        group_context: &[u8],
        new_leaves_indexes_option: Option<HashSet<&NodeIndex>>,
    ) -> Option<UpdatePath> {
        let key_package = key_package_bundle.key_package().clone();
        let ciphersuite = key_package.ciphersuite();
        // Compute the direct path and keypairs along it
        let own_index = self.own_node_index();
        let direct_path_root = treemath::leaf_direct_path(own_index, self.leaf_count())
            .expect("replace_private_tree: Error when computing direct path.");
        // Update private tree and merge corresponding public keys.
        let (private_tree, new_public_keys) = PrivateTree::new_with_keys(
            ciphersuite,
            own_index,
            key_package_bundle,
            &direct_path_root,
        );
        self.private_tree = private_tree;

        self.merge_public_keys(&new_public_keys, &direct_path_root)
            .unwrap();

        // Update own leaf node with the new values
        self.nodes[own_index] = Node::new_leaf(Some(key_package.clone()));
        self.set_parent_hashes(self.own_node_index());
        if let Some(new_leaves_indexes) = new_leaves_indexes_option {
            let update_path_nodes = self
                .encrypt_to_copath(new_public_keys, group_context, new_leaves_indexes)
                .unwrap();
            let update_path = UpdatePath::new(key_package, update_path_nodes);
            Some(update_path)
        } else {
            None
        }
    }

    /// Encrypt the path secrets to the co path and return the update path.
    fn encrypt_to_copath(
        &self,
        public_keys: Vec<HPKEPublicKey>,
        group_context: &[u8],
        new_leaves_indexes: HashSet<&NodeIndex>,
    ) -> Result<Vec<UpdatePathNode>, TreeError> {
        let copath = treemath::copath(self.private_tree.leaf_index(), self.leaf_count())
            .expect("encrypt_to_copath: Error when computing copath.");
        // Return if the length of the copath is zero
        if copath.is_empty() {
            return Ok(vec![]);
        }
        let path_secrets = self.private_tree.path_secrets();

        debug_assert_eq!(path_secrets.len(), copath.len());
        if path_secrets.len() != copath.len() {
            return Err(TreeError::InvalidArguments);
        }
        debug_assert_eq!(public_keys.len(), copath.len());
        if public_keys.len() != copath.len() {
            return Err(TreeError::InvalidArguments);
        }

        let mut direct_path_nodes = vec![];
        let mut ciphertexts = vec![];
        for (path_secret, copath_node) in path_secrets.iter().zip(copath.iter()) {
            let node_ciphertexts: Vec<HpkeCiphertext> = self
                .resolve(*copath_node, &new_leaves_indexes)
                .iter()
                .map(|&index| {
                    let pk = self.nodes[index].public_hpke_key().unwrap();
                    self.ciphersuite
                        .hpke_seal_secret(&pk, group_context, &[], &path_secret)
                })
                .collect();
            // TODO Check that all public keys are non-empty
            // TODO Handle potential errors
            ciphertexts.push(node_ciphertexts);
        }
        for (public_key, node_ciphertexts) in public_keys.iter().zip(ciphertexts.iter()) {
            direct_path_nodes.push(UpdatePathNode {
                // TODO: don't clone ...
                public_key: public_key.clone(),
                encrypted_path_secret: node_ciphertexts.clone(),
            });
        }
        Ok(direct_path_nodes)
    }

    /// Merge public keys from a direct path to this tree along the given path.
    fn merge_direct_path_keys(
        &mut self,
        direct_path: &UpdatePath,
        path: Vec<NodeIndex>,
    ) -> Result<(), TreeError> {
        debug_assert_eq!(direct_path.nodes.len(), path.len());
        if direct_path.nodes.len() != path.len() {
            return Err(TreeError::InvalidArguments);
        }

        for (i, p) in path.iter().enumerate() {
            let public_key = direct_path.nodes[i].clone().public_key;
            let node = ParentNode::new(public_key.clone(), &[], &[]);
            self.nodes[p].node = Some(node);
        }

        Ok(())
    }

    /// Validates that the `public_keys` matches the public keys in the tree
    /// along `path`
    pub(crate) fn validate_public_keys(
        &self,
        public_keys: &[HPKEPublicKey],
        path: &[NodeIndex],
    ) -> Result<(), TreeError> {
        if public_keys.len() != path.len() {
            return Err(TreeError::InvalidArguments);
        }
        for (public_key, node_index) in public_keys.iter().zip(path) {
            if let Some(node) = &self.nodes[node_index].node {
                if node.public_key() != public_key {
                    return Err(TreeError::InvalidArguments);
                }
            } else {
                return Err(TreeError::InvalidArguments);
            }
        }
        Ok(())
    }

    /// Merges `public_keys` into the tree along the `path`
    pub(crate) fn merge_public_keys(
        &mut self,
        public_keys: &[HPKEPublicKey],
        path: &[NodeIndex],
    ) -> Result<(), TreeError> {
        debug_assert_eq!(public_keys.len(), path.len());
        if public_keys.len() != path.len() {
            return Err(TreeError::InvalidArguments);
        }
        for i in 0..path.len() {
            // TODO: drop clone
            let node = ParentNode::new(public_keys[i].clone(), &[], &[]);
            self.nodes[path[i]].node = Some(node);
        }
        Ok(())
    }

    /// Add nodes for the provided key packages.
    pub(crate) fn add_nodes(&mut self, new_kps: &[&KeyPackage]) -> Vec<(NodeIndex, Credential)> {
        let num_new_kp = new_kps.len();
        let mut added_members = Vec::with_capacity(num_new_kp);

        if num_new_kp > (2 * self.leaf_count().as_usize()) {
            self.nodes
                .reserve_exact((2 * num_new_kp) - (2 * self.leaf_count().as_usize()));
        }

        // Add new nodes for key packages into existing free leaves.
        // Note that zip makes it so only the first free_leaves().len() nodes are taken.
        let free_leaves = self.free_leaves();
        let free_leaves_len = free_leaves.len();
        for (new_kp, leaf_index) in new_kps.iter().zip(free_leaves) {
            self.nodes[leaf_index] = Node::new_leaf(Some((*new_kp).clone()));
            let dirpath = treemath::leaf_direct_path(leaf_index, self.leaf_count())
                .expect("add_nodes: Error when computing direct path.");
            for d in dirpath.iter() {
                if !self.nodes[d].is_blank() {
                    let node = &self.nodes[d];
                    let index = d.as_u32();
                    // TODO handle error
                    let mut parent_node = node.node.clone().unwrap();
                    if !parent_node.unmerged_leaves().contains(&index) {
                        parent_node.add_unmerged_leaf(index);
                    }
                    self.nodes[d].node = Some(parent_node);
                }
            }
            added_members.push((NodeIndex::from(leaf_index), new_kp.credential().clone()));
        }
        // Add the remaining nodes.
        let mut new_nodes = Vec::with_capacity(num_new_kp * 2);
        let mut index_counter = self.nodes.len() + 1;
        for add_proposal in new_kps.iter().skip(free_leaves_len) {
            let node_index = NodeIndex::from(index_counter);
            new_nodes.extend(vec![
                Node::new_blank_parent_node(),
                Node::new_leaf(Some((*add_proposal).clone())),
            ]);
            added_members.push((node_index, add_proposal.credential().clone()));
            index_counter += 2;
        }
        self.nodes.extend(new_nodes);
        self.trim_tree();
        added_members
    }

    /// Applies a list of proposals from a Commit to the tree.
    /// `proposal_queue` is the queue of proposals received or sent in the
    /// current epoch `updates_key_package_bundles` is the list of own
    /// KeyPackageBundles corresponding to updates or commits sent in the
    /// current epoch
    pub fn apply_proposals(
        &mut self,
        proposal_queue: ProposalQueue,
        updates_key_package_bundles: &[KeyPackageBundle],
    ) -> Result<ApplyProposalsValues, TreeError> {
        let mut has_updates = false;
        let mut has_removes = false;

        let mut self_removed = false;

        // Process updates first
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Update) {
            has_updates = true;
            let update_proposal = &queued_proposal.proposal().as_update().unwrap();
            let sender_index = queued_proposal.sender().to_leaf_index();
            // Prepare leaf node
            let leaf_node = Node::new_leaf(Some(update_proposal.key_package.clone()));
            // Blank the direct path of that leaf node
            self.blank_member(sender_index);
            // Replace the leaf node
            self.nodes[sender_index] = leaf_node;
            // Check if it is a self-update
            if sender_index == self.own_node_index() {
                let own_kpb = match updates_key_package_bundles
                    .iter()
                    .find(|kpb| kpb.key_package() == &update_proposal.key_package)
                {
                    Some(kpb) => kpb,
                    // We lost the KeyPackageBundle apparently
                    None => return Err(TreeError::InvalidArguments),
                };
                // Update the private tree with new values
                self.private_tree = PrivateTree::from_key_package_bundle(sender_index, &own_kpb);
            }
        }
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Remove) {
            has_removes = true;
            let remove_proposal = &queued_proposal.proposal().as_remove().unwrap();
            let removed = LeafIndex::from(remove_proposal.removed);
            // Check if we got removed from the group
            if removed == self.own_node_index() {
                self_removed = true;
            }
            // Blank the direct path of the removed member
            self.blank_member(removed);
        }

        // Process adds
        let mut invitation_list = Vec::new();
        let add_proposals: Vec<AddProposal> = proposal_queue
            .filtered_by_type(ProposalType::Add)
            .map(|queued_proposal| {
                let proposal = &queued_proposal.proposal();
                proposal.as_add().unwrap()
            })
            .collect();
        let has_adds = !add_proposals.is_empty();
        // Extract KeyPackages from proposals
        let key_packages: Vec<&KeyPackage> = add_proposals.iter().map(|a| &a.key_package).collect();
        // Add new members to tree
        let added_members = self.add_nodes(&key_packages);

        // Prepare invitations
        for (i, added) in added_members.iter().enumerate() {
            invitation_list.push((added.0, add_proposals.get(i).unwrap().clone()));
        }

        // Determine if Commit needs a path field
        let path_required = has_updates || has_removes || !has_adds;

        Ok(ApplyProposalsValues {
            path_required,
            self_removed,
            invitation_list,
        })
    }

    /// Trims the tree from the right when there are empty leaf nodes
    fn trim_tree(&mut self) {
        let mut new_tree_size = 0;

        for i in 0..self.nodes.len() {
            if !self.nodes[i].is_blank() {
                new_tree_size = i + 1;
            }
        }

        if new_tree_size > 0 {
            self.nodes.truncate(new_tree_size);
        }
    }

    /// Get a reference to the commit secret.
    pub(crate) fn commit_secret(&self) -> &CommitSecret {
        self.private_tree.commit_secret()
    }

    /// Get a slice with the path secrets.
    pub(crate) fn path_secrets(&self) -> &[Secret] {
        self.private_tree.path_secrets()
    }
}

/// This struct contain the return vallues of the `apply_proposals()` function
pub struct ApplyProposalsValues {
    pub path_required: bool,
    pub self_removed: bool,
    pub invitation_list: Vec<(NodeIndex, AddProposal)>,
}

impl ApplyProposalsValues {
    /// This function creates a `HashSet` of node indexes of the new nodes that
    /// were added to the tree. The `HashSet` will be querried by the
    /// `resolve()` function to filter out those nodes from the resolution.
    pub fn exclusion_list(&self) -> HashSet<&NodeIndex> {
        // Collect the new leaves' indexes so we can filter them out in the resolution
        // later
        let new_leaves_indexes: HashSet<&NodeIndex> = self
            .invitation_list
            .iter()
            .map(|(index, _)| index)
            .collect();
        new_leaves_indexes
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
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct UpdatePathNode {
    pub public_key: HPKEPublicKey,
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     KeyPackage leaf_key_package;
///     UpdatePathNode nodes<0..2^32-1>;
/// } UpdatePath;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct UpdatePath {
    pub leaf_key_package: KeyPackage,
    pub nodes: Vec<UpdatePathNode>,
}

impl UpdatePath {
    /// Create a new update path.
    fn new(leaf_key_package: KeyPackage, nodes: Vec<UpdatePathNode>) -> Self {
        Self {
            leaf_key_package,
            nodes,
        }
    }
}
