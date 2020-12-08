use crate::ciphersuite::*;
use crate::codec::*;
use crate::config::{Config, ConfigError};
use crate::creds::*;
use crate::key_packages::*;
use crate::messages::proposals::*;

// Tree modules
pub(crate) mod codec;
pub(crate) mod hash_input;
pub mod index;
pub mod node;
pub(crate) mod path_keys;
pub(crate) mod private_tree;
pub(crate) mod secret_tree;
pub(crate) mod sender_ratchet;
pub(crate) mod treemath;

use hash_input::*;
use index::*;
use node::*;
use private_tree::{PathSecrets, PrivateTree};

use self::private_tree::CommitSecret;
pub(crate) use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};

// Internal tree tests
#[cfg(test)]
mod test_path_keys;
#[cfg(test)]
mod test_private_tree;
#[cfg(test)]
mod test_secret_tree;
#[cfg(test)]
mod test_treemath;
#[cfg(test)]
mod test_util;

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
        let private_tree = PrivateTree::from_key_package_bundle(NodeIndex::from(0u32), &kpb);

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
            private_tree: PrivateTree::new(ratchet_tree.private_tree.node_index()),
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
        ) -> Result<NodeIndex, TreeError> {
            for (i, node_option) in nodes.iter().enumerate() {
                if let Some(node) = node_option {
                    if let Some(kp) = &node.key_package {
                        if kp == key_package {
                            return Ok(NodeIndex::from(i));
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
            } else if i % 2 == 0 {
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

    pub fn leaf_count(&self) -> LeafIndex {
        self.tree_size().into()
    }

    fn resolve(&self, index: NodeIndex) -> Vec<NodeIndex> {
        let size = self.leaf_count();

        if self.nodes[index.as_usize()].node_type == NodeType::Leaf {
            if self.nodes[index.as_usize()].is_blank() {
                return vec![];
            } else {
                return vec![index];
            }
        }

        if !self.nodes[index.as_usize()].is_blank() {
            let mut unmerged_leaves = vec![index];
            let node = &self.nodes[index.as_usize()].node.as_ref();
            unmerged_leaves.extend(
                node.unwrap()
                    .unmerged_leaves()
                    .iter()
                    .map(|n| NodeIndex::from(*n)),
            );
            return unmerged_leaves;
        }

        let mut left = self.resolve(
            treemath::left(index).expect("resolve: TreeMath error when computing left child."),
        );
        let right = self.resolve(
            treemath::right(index, size)
                .expect("resolve: TreeMath error when computing right child."),
        );
        left.extend(right);
        left
    }

    /// Get the index of the own node.
    pub(crate) fn own_node_index(&self) -> NodeIndex {
        self.private_tree.node_index()
    }

    /// Get a reference to the own key package.
    pub fn own_key_package(&self) -> &KeyPackage {
        let own_node = &self.nodes[self.own_node_index().as_usize()];
        own_node.key_package.as_ref().unwrap()
    }

    /// Get a mutable reference to the own key package.
    fn own_key_package_mut(&mut self) -> &mut KeyPackage {
        let own_node = self
            .nodes
            .get_mut(self.private_tree.node_index().as_usize())
            .unwrap();
        own_node.key_package_mut().unwrap()
    }

    fn blank_member(&mut self, index: NodeIndex) {
        let size = self.leaf_count();
        self.nodes[index.as_usize()].blank();
        self.nodes[treemath::root(size).as_usize()].blank();
        for index in treemath::direct_path_root(index, size)
            .expect("blank_member: TreeMath error when computing direct path.")
        {
            self.nodes[index.as_usize()].blank();
        }
    }

    fn free_leaves(&self) -> Vec<NodeIndex> {
        let mut free_leaves = vec![];
        for i in 0..self.leaf_count().as_usize() {
            // TODO use an iterator instead
            let leaf_index = LeafIndex::from(i);
            if self.nodes[leaf_index].is_blank() {
                free_leaves.push(NodeIndex::from(leaf_index));
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
    ) -> Result<&CommitSecret, TreeError> {
        let own_index = self.own_node_index();

        // Find common ancestor of own leaf and sender leaf
        let common_ancestor_index =
            treemath::common_ancestor_index(NodeIndex::from(sender), own_index);

        // Calculate sender direct path & co-path, common path
        let sender_direct_path =
            treemath::direct_path_root(NodeIndex::from(sender), self.leaf_count())
                .expect("update_path: Error when computing direct path.");
        let sender_co_path = treemath::copath(NodeIndex::from(sender), self.leaf_count())
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

        // Resolve the node of that co-path index
        let resolution = self.resolve(common_ancestor_copath_index);
        let position_in_resolution = resolution.iter().position(|&x| x == own_index).unwrap_or(0);

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
                .get(common_ancestor_copath_index)
            {
                Some(k) => k,
                None => return Err(TreeError::InvalidArguments),
            }
        };

        // Compute the common path between the common ancestor and the root
        let common_path = treemath::dirpath_long(common_ancestor_index, self.leaf_count())
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
        ));
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
        self.compute_parent_hash(NodeIndex::from(sender));

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
            false, /* without update path */
        );
        self.private_tree.commit_secret()
    }

    /// Update the private tree.
    pub(crate) fn refresh_private_tree(
        &mut self,
        credential_bundle: &CredentialBundle,
        group_context: &[u8],
    ) -> (&CommitSecret, UpdatePath, PathSecrets, KeyPackageBundle) {
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
                true, /* with update path */
            )
            .unwrap();

        // Compute the parent hash extension and update the KeyPackage and sign it
        let parent_hash = self.compute_parent_hash(own_index);
        let key_package = self.own_key_package_mut();
        key_package.update_parent_hash(&parent_hash);
        // Sign the KeyPackage
        key_package.sign(credential_bundle);
        // Store it in the UpdatePath
        path.leaf_key_package = key_package.clone();
        // Update it in the KeyPackageBundle
        key_package_bundle.set_key_package(key_package.clone());

        (
            self.private_tree.commit_secret(),
            path,
            self.private_tree.path_secrets().to_vec(),
            key_package_bundle,
        )
    }

    /// Replace the private tree with a new one based on the
    /// `key_package_bundle`.
    fn replace_private_tree_(
        &mut self,
        key_package_bundle: &KeyPackageBundle,
        group_context: &[u8],
        with_update_path: bool,
    ) -> Option<UpdatePath> {
        let key_package = key_package_bundle.key_package().clone();
        let ciphersuite = key_package.ciphersuite();
        // Compute the direct path and keypairs along it
        let own_index = self.own_node_index();
        let direct_path_root = treemath::direct_path_root(own_index, self.leaf_count())
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
        self.nodes[own_index.as_usize()] = Node::new_leaf(Some(key_package.clone()));
        if with_update_path {
            let update_path_nodes = self
                .encrypt_to_copath(new_public_keys, group_context)
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
    ) -> Result<Vec<UpdatePathNode>, TreeError> {
        let copath = treemath::copath(self.private_tree.node_index(), self.leaf_count())
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
                .resolve(*copath_node)
                .iter()
                .map(|&x| {
                    let pk = self.nodes[x.as_usize()].public_hpke_key().unwrap();
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
            self.nodes[p.as_usize()].node = Some(node);
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
            if let Some(node) = &self.nodes[node_index.as_usize()].node {
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
            self.nodes[path[i].as_usize()].node = Some(node);
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
            self.nodes[leaf_index.as_usize()] = Node::new_leaf(Some((*new_kp).clone()));
            let dirpath = treemath::direct_path_root(leaf_index, self.leaf_count())
                .expect("add_nodes: Error when computing direct path.");
            for d in dirpath.iter() {
                if !self.nodes[d.as_usize()].is_blank() {
                    let node = &self.nodes[d.as_usize()];
                    let index = d.as_u32();
                    // TODO handle error
                    let mut parent_node = node.node.clone().unwrap();
                    if !parent_node.unmerged_leaves().contains(&index) {
                        parent_node.unmerged_leaves_mut().push(index);
                    }
                    self.nodes[d.as_usize()].node = Some(parent_node);
                }
            }
            added_members.push((leaf_index, new_kp.credential().clone()));
        }
        // Add the remaining nodes.
        let mut new_nodes = Vec::with_capacity(num_new_kp * 2);
        let mut leaf_index = self.nodes.len() + 1;
        for add_proposal in new_kps.iter().skip(free_leaves_len) {
            new_nodes.extend(vec![
                Node::new_blank_parent_node(),
                Node::new_leaf(Some((*add_proposal).clone())),
            ]);
            let node_index = NodeIndex::from(leaf_index);
            added_members.push((node_index, add_proposal.credential().clone()));
            leaf_index += 2;
        }
        self.nodes.extend(new_nodes);
        self.trim_tree();
        added_members
    }

    /// Applies a list of proposals from a Commit to the tree.
    /// `proposal_id_list` corresponds to the `proposals` field of a Commit
    /// `proposal_queue` is the queue of proposals received or sent in the
    /// current epoch `updates_key_package_bundles` is the list of own
    /// KeyPackageBundles corresponding to updates or commits sent in the
    /// current epoch
    pub fn apply_proposals(
        &mut self,
        proposal_id_list: &[ProposalID],
        proposal_queue: ProposalQueue,
        updates_key_package_bundles: &[KeyPackageBundle],
        // (path_required, self_removed, invitation_list)
    ) -> Result<(bool, bool, InvitationList), TreeError> {
        let mut has_updates = false;
        let mut has_removes = false;
        let mut invitation_list = Vec::new();

        let mut self_removed = false;

        // Process updates first
        for queued_proposal in proposal_queue
            .filtered_queued_proposals(proposal_id_list, ProposalType::Update)
            .iter()
        {
            has_updates = true;
            let update_proposal = &queued_proposal.proposal().as_update().unwrap();
            let sender_index = queued_proposal.sender().to_node_index();
            // Prepare leaf node
            let leaf_node = Node::new_leaf(Some(update_proposal.key_package.clone()));
            // Blank the direct path of that leaf node
            self.blank_member(sender_index);
            // Replace the leaf node
            self.nodes[sender_index.as_usize()] = leaf_node;
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
        for queued_proposal in proposal_queue
            .filtered_queued_proposals(proposal_id_list, ProposalType::Remove)
            .iter()
        {
            has_removes = true;
            let remove_proposal = &queued_proposal.proposal().as_remove().unwrap();
            let removed = NodeIndex::from(LeafIndex::from(remove_proposal.removed));
            // Check if we got removed from the group
            if removed == self.own_node_index() {
                self_removed = true;
            }
            // Blank the direct path of the removed member
            self.blank_member(removed);
        }

        // Process adds
        let add_proposals: Vec<AddProposal> = proposal_queue
            .filtered_queued_proposals(proposal_id_list, ProposalType::Add)
            .iter()
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

        Ok((path_required, self_removed, invitation_list))
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
    /// Computes the tree hash
    pub fn compute_tree_hash(&self) -> Vec<u8> {
        fn node_hash(ciphersuite: &Ciphersuite, tree: &RatchetTree, index: NodeIndex) -> Vec<u8> {
            let node = &tree.nodes[index.as_usize()];
            match node.node_type {
                NodeType::Leaf => {
                    let leaf_node_hash = LeafNodeHashInput::new(&index, &node.key_package);
                    leaf_node_hash.hash(ciphersuite)
                }
                NodeType::Parent => {
                    let left = treemath::left(index)
                        .expect("node_hash: Error when computing left child of node.");
                    let left_hash = node_hash(ciphersuite, tree, left);
                    let right = treemath::right(index, tree.leaf_count())
                        .expect("node_hash: Error when computing left child of node.");
                    let right_hash = node_hash(ciphersuite, tree, right);
                    let parent_node_hash = ParentNodeHashInput::new(
                        index.as_u32(),
                        &node.node,
                        &left_hash,
                        &right_hash,
                    );
                    parent_node_hash.hash(ciphersuite)
                }
                NodeType::Default => panic!("Default node type not supported in tree hash."),
            }
        }
        let root = treemath::root(self.leaf_count());
        node_hash(&self.ciphersuite, &self, root)
    }
    /// Computes the parent hash
    pub fn compute_parent_hash(&mut self, index: NodeIndex) -> Vec<u8> {
        let root = treemath::root(self.leaf_count());
        // This should only happen when the group only contains one member
        if index == root {
            return vec![];
        }
        // Calculate the parent's index
        let parent = treemath::parent(index, self.leaf_count())
            .expect("compute_parent_hash: Error when computing node parent.");
        // If we already reached the tree's root, return the hash of that node
        let parent_hash = if parent == root {
            let root_node = &self.nodes[parent.as_usize()];
            root_node.hash(&self.ciphersuite).unwrap()
        // Otherwise return the hash of the next parent
        } else {
            self.compute_parent_hash(parent)
        };
        // If the current node is a parent, replace the parent hash in that node
        let current_node = &self.nodes[index.as_usize()];
        if let Some(mut parent_node) = current_node.node.clone() {
            parent_node.set_parent_hash(parent_hash);
            self.nodes[index.as_usize()].node = Some(parent_node);
            let updated_parent_node = &self.nodes[index.as_usize()];
            updated_parent_node.hash(&self.ciphersuite).unwrap()
        // Otherwise we reached the leaf level, just return the hash
        } else {
            parent_hash
        }
    }
    /// Verifies the integrity of a public tree
    pub fn verify_integrity(ciphersuite: &Ciphersuite, nodes: &[Option<Node>]) -> bool {
        let node_count = NodeIndex::from(nodes.len());
        let size = node_count;
        for i in 0..node_count.as_usize() {
            let node_option = &nodes[i];
            if let Some(node) = node_option {
                match node.node_type {
                    NodeType::Parent => {
                        let left_index = treemath::left(NodeIndex::from(i))
                            .expect("verify_integrity: Error when computing left child of node.");
                        let right_index = treemath::right(NodeIndex::from(i), size.into())
                            .expect("verify_integrity: Error when computing right child of node.");
                        if right_index >= node_count {
                            return false;
                        }
                        let left_option = &nodes[left_index.as_usize()];
                        let right_option = &nodes[right_index.as_usize()];
                        let own_hash = node.hash(ciphersuite).unwrap();
                        if let Some(right) = right_option {
                            if let Some(left) = left_option {
                                let left_parent_hash = left.parent_hash().unwrap_or_else(Vec::new);
                                let right_parent_hash =
                                    right.parent_hash().unwrap_or_else(Vec::new);
                                if (left_parent_hash != own_hash) && (right_parent_hash != own_hash)
                                {
                                    return false;
                                }
                                if left_parent_hash == right_parent_hash {
                                    return false;
                                }
                            } else if right.parent_hash().unwrap() != own_hash {
                                return false;
                            }
                        } else if let Some(left) = left_option {
                            if left.parent_hash().unwrap() != own_hash {
                                return false;
                            }
                        }
                    }
                    NodeType::Leaf => {
                        if let Some(kp) = &node.key_package {
                            if i % 2 != 0 {
                                return false;
                            }
                            if kp.verify().is_err() {
                                return false;
                            }
                        }
                    }

                    NodeType::Default => {}
                }
            }
        }
        true
    }
}

pub type InvitationList = Vec<(NodeIndex, AddProposal)>;

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

/// These are errors the RatchetTree can return.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TreeError {
    InvalidArguments,
    DuplicateIndex,
    InvalidUpdatePath,
    UnknownError,
}

// TODO: Should get fixed in #83
impl From<ConfigError> for TreeError {
    fn from(e: ConfigError) -> TreeError {
        match e {
            ConfigError::UnsupportedMlsVersion => TreeError::InvalidArguments,
            ConfigError::UnsupportedCiphersuite => TreeError::InvalidArguments,
            _ => TreeError::UnknownError,
        }
    }
}
