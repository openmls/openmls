// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use rayon::prelude::*;

use crate::ciphersuite::{signable::*, *};
use crate::codec::*;
use crate::creds::*;
use crate::extensions::*;
use crate::key_packages::*;
use crate::messages::{proposals::*, *};
use crate::schedule::*;

// Tree modules
pub(crate) mod astree;
pub(crate) mod codec;
pub(crate) mod index;
pub(crate) mod node;
pub(crate) mod sender_ratchet;
pub(crate) mod treemath;

use index::*;
use node::*;

// Internal tree tests
mod test_astree;
mod test_treemath;

// TODO improve the storage memory footprint
#[derive(Default, Debug, Clone)]
pub struct PathKeypairs {
    keypairs: Vec<Option<HPKEKeyPair>>,
}

impl PathKeypairs {
    pub fn new() -> Self {
        PathKeypairs { keypairs: vec![] }
    }
    pub fn add(&mut self, keypairs: &[HPKEKeyPair], path: &[NodeIndex]) {
        fn extend_vec(tree_keypairs: &mut PathKeypairs, max_index: NodeIndex) {
            while tree_keypairs.keypairs.len() <= max_index.as_usize() {
                tree_keypairs.keypairs.push(None);
            }
        }
        assert_eq!(keypairs.len(), path.len()); // TODO return error
        for i in 0..path.len() {
            let index = path[i];
            extend_vec(self, index);
            self.keypairs[index.as_usize()] = Some(keypairs[i].clone());
        }
    }
    pub fn get(&self, index: NodeIndex) -> Option<&HPKEKeyPair> {
        if index.as_usize() >= self.keypairs.len() {
            return None;
        }
        match self.keypairs.get(index.as_usize()) {
            Some(keypair_option) => keypair_option.as_ref(),
            None => None,
        }
    }
    pub fn generate_path_secrets(
        ciphersuite: &Ciphersuite,
        start_secret: &[u8],
        n: usize,
    ) -> (Vec<Vec<u8>>, CommitSecret) {
        let hash_len = ciphersuite.hash_length();
        let leaf_node_secret = hkdf_expand_label(ciphersuite, start_secret, "path", &[], hash_len);
        let mut path_secrets = vec![leaf_node_secret];
        for i in 0..n - 1 {
            let path_secret =
                hkdf_expand_label(ciphersuite, &path_secrets[i], "path", &[], hash_len);
            path_secrets.push(path_secret);
        }
        let commit_secret = CommitSecret(hkdf_expand_label(
            ciphersuite,
            &path_secrets.last().unwrap(),
            "path",
            &[],
            hash_len,
        ));
        (path_secrets, commit_secret)
    }
    pub fn continue_path_secrets(
        ciphersuite: &Ciphersuite,
        intermediate_secret: &[u8],
        n: usize,
    ) -> (Vec<Vec<u8>>, CommitSecret) {
        let hash_len = ciphersuite.hash_length();
        let mut path_secrets = vec![intermediate_secret.to_vec()];
        for i in 0..n - 1 {
            let path_secret =
                hkdf_expand_label(ciphersuite, &path_secrets[i], "path", &[], hash_len);
            path_secrets.push(path_secret);
        }
        let commit_secret = CommitSecret(hkdf_expand_label(
            ciphersuite,
            &path_secrets.last().unwrap(),
            "path",
            &[],
            hash_len,
        ));
        (path_secrets, commit_secret)
    }
    pub fn generate_path_keypairs(
        ciphersuite: &Ciphersuite,
        path_secrets: &[Vec<u8>],
    ) -> Vec<HPKEKeyPair> {
        let hash_len = ciphersuite.hash_length();
        let mut keypairs = vec![];
        for path_secret in path_secrets {
            let node_secret = hkdf_expand_label(ciphersuite, &path_secret, "node", &[], hash_len);
            let keypair = HPKEKeyPair::from_slice(&node_secret, ciphersuite);
            keypairs.push(keypair);
        }
        keypairs
    }
}

#[derive(Debug, Clone)]
pub struct RatchetTree {
    ciphersuite: Ciphersuite,
    pub nodes: Vec<Node>,
    own_private_key: HPKEPrivateKey,
    path_keypairs: PathKeypairs,
    own_node_index: NodeIndex,
}

impl RatchetTree {
    pub(crate) fn new(ciphersuite: Ciphersuite, kpb: KeyPackageBundle) -> RatchetTree {
        let nodes = vec![Node {
            node_type: NodeType::Leaf,
            key_package: Some(kpb.get_key_package().clone()),
            node: None,
        }];
        RatchetTree {
            ciphersuite,
            nodes,
            own_private_key: kpb.get_private_key().clone(),
            path_keypairs: PathKeypairs::new(),
            own_node_index: NodeIndex::from(0u32),
        }
    }
    pub(crate) fn new_from_nodes(
        ciphersuite: Ciphersuite,
        kpb: KeyPackageBundle,
        node_options: &[Option<Node>],
    ) -> Option<RatchetTree> {
        fn find_kp_in_tree(key_package: &KeyPackage, nodes: &[Option<Node>]) -> Option<NodeIndex> {
            for (i, node_option) in nodes.iter().enumerate() {
                if let Some(node) = node_option {
                    if let Some(kp) = &node.key_package {
                        if kp == key_package {
                            return Some(NodeIndex::from(i));
                        }
                    }
                }
            }
            None
        }

        let own_node_index = find_kp_in_tree(kpb.get_key_package(), node_options)?;

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
        let private_key = kpb.get_private_key().clone();
        let secret = private_key.as_slice();
        let dirpath = treemath::dirpath_root(own_node_index, NodeIndex::from(nodes.len()).into());
        let (path_secrets, _commit_secret) =
            PathKeypairs::generate_path_secrets(&ciphersuite, secret, dirpath.len());
        let keypairs = PathKeypairs::generate_path_keypairs(&ciphersuite, &path_secrets);
        let mut path_keypairs = PathKeypairs::new();
        path_keypairs.add(&keypairs, &dirpath);
        Some(RatchetTree {
            ciphersuite,
            nodes,
            own_private_key: private_key,
            path_keypairs,
            own_node_index,
        })
    }
    fn tree_size(&self) -> NodeIndex {
        NodeIndex::from(self.nodes.len())
    }

    pub(crate) fn public_key_tree(&self) -> Vec<Option<Node>> {
        let mut tree = vec![];
        for node in self.nodes.iter() {
            if node.is_blank() {
                tree.push(None)
            } else {
                tree.push(Some(node.clone()))
            }
        }
        tree
    }

    pub(crate) fn leaf_count(&self) -> LeafIndex {
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
                    .get_unmerged_leaves()
                    .iter()
                    .map(|n| NodeIndex::from(*n)),
            );
            return unmerged_leaves;
        }

        let mut left = self.resolve(treemath::left(index));
        let right = self.resolve(treemath::right(index, size));
        left.extend(right);
        left
    }

    fn get_path_keypairs(&self) -> &PathKeypairs {
        &self.path_keypairs
    }

    pub(crate) fn set_path_keypairs(&mut self, path_keypairs: PathKeypairs) {
        self.path_keypairs = path_keypairs;
    }

    pub(crate) fn get_own_node_index(&self) -> NodeIndex {
        self.own_node_index
    }

    pub(crate) fn get_own_key_package(&self) -> &KeyPackage {
        let own_node = &self.nodes[self.own_node_index.as_usize()];
        own_node.key_package.as_ref().unwrap()
    }

    fn get_own_private_key(&self) -> &HPKEPrivateKey {
        &self.own_private_key
    }

    fn blank_member(&mut self, index: NodeIndex) {
        let size = self.leaf_count();
        self.nodes[index.as_usize()].blank();
        self.nodes[treemath::root(size).as_usize()].blank();
        for index in treemath::dirpath(index, size) {
            self.nodes[index.as_usize()].blank();
        }
    }
    fn free_leaves(&self) -> Vec<NodeIndex> {
        let mut free_leaves = vec![];
        for i in 0..self.leaf_count().as_usize() {
            // TODO use an iterator instead
            if self.nodes[NodeIndex::from(i).as_usize()].is_blank() {
                free_leaves.push(NodeIndex::from(i));
            }
        }
        free_leaves
    }

    pub(crate) fn update_direct_path(
        &mut self,
        sender: LeafIndex,
        direct_path: &DirectPath,
        group_context: &[u8],
    ) -> CommitSecret {
        let own_index = self.get_own_node_index();
        // TODO check that the direct path is long enough

        // Find common ancestor of own leaf and sender leaf
        let common_ancestor = treemath::common_ancestor(NodeIndex::from(sender), own_index);

        // Calculate sender direct path & copath, common path
        let sender_dirpath = treemath::dirpath_root(NodeIndex::from(sender), self.leaf_count());
        let sender_copath = treemath::copath(NodeIndex::from(sender), self.leaf_count());

        // Find the position of the common ancestor in the sender's direct path
        let common_ancestor_sender_dirpath_index = sender_dirpath
            .iter()
            .position(|x| *x == common_ancestor)
            .unwrap();
        let common_ancestor_copath_index = sender_copath[common_ancestor_sender_dirpath_index];

        // Resolve the node of that copath index
        let resolution = self.resolve(common_ancestor_copath_index);
        let position_in_resolution = resolution.iter().position(|x| *x == own_index).unwrap_or(0);
        // TODO Check resolution.len() == encrypted_path_secret.len()

        // Decrypt the ciphertext of that node
        let hpke_ciphertext = &direct_path.nodes[common_ancestor_sender_dirpath_index]
            .encrypted_path_secret[position_in_resolution];

        // Check whether the secret was encrypted to the leaf node
        let private_key = if resolution[position_in_resolution] == own_index {
            self.get_own_private_key()
        } else {
            self.get_path_keypairs()
                .get(common_ancestor_copath_index)
                .unwrap()
                .get_private_key()
        };

        // Compute the common path between the common ancestor and the root
        let common_path = treemath::dirpath_long(common_ancestor, self.leaf_count());

        // Decrypt the secret and derive path secrets
        let secret = self
            .ciphersuite
            .hpke_open(hpke_ciphertext, &private_key, group_context, &[]);
        let (path_secrets, commit_secret) =
            PathKeypairs::continue_path_secrets(&self.ciphersuite, &secret, common_path.len());
        let keypairs = PathKeypairs::generate_path_keypairs(&self.ciphersuite, &path_secrets);
        let sender_path_offset = sender_dirpath.len() - common_path.len();

        // Generate keypairs from the path secrets
        for (i, keypair) in keypairs.iter().enumerate().take(common_path.len()) {
            // TODO return an error if public keys don't match
            assert_eq!(
                &direct_path.nodes[sender_path_offset + i].public_key,
                keypair.get_public_key()
            );
        }

        // Merge new nodes and path secrets
        self.merge_public_keys(direct_path, sender_dirpath);
        self.path_keypairs.add(&keypairs, &common_path);
        self.merge_keypairs(&keypairs, &common_path);
        self.nodes[NodeIndex::from(sender).as_usize()] =
            Node::new_leaf(Some(direct_path.leaf_key_package.clone()));
        self.compute_parent_hash(NodeIndex::from(sender));
        commit_secret
    }
    pub(crate) fn replace_own_leaf(
        &mut self,
        key_package_bundle: KeyPackageBundle,
        group_context: &[u8],
    ) -> CommitSecret {
        let (commit_secret, _path_option, _secrets_option) =
            self.update_own_leaf(&key_package_bundle, group_context, false);
        commit_secret
    }
    pub(crate) fn refresh_own_leaf(
        &mut self,
        signature_key: &SignaturePrivateKey,
        group_context: &[u8],
    ) -> (CommitSecret, Option<DirectPath>, Option<Vec<Vec<u8>>>) {
        // Generate new keypair
        let own_index = self.get_own_node_index();
        let keypair = self.ciphersuite.new_hpke_keypair();

        // Replace the init key in the current KeyPackage
        let key_package_bundle = {
            // Generate new keypair and replace it in current KeyPackage
            let mut key_package = self.get_own_key_package().clone();
            key_package.set_hpke_init_key(keypair.get_public_key().clone());
            KeyPackageBundle::from_values(key_package, keypair.get_private_key().clone())
        };
        let (commit_secret, path_option, secrets_option) =
            self.update_own_leaf(&key_package_bundle, group_context, true);

        // Compute the parent hash extension and add it to the KeyPackage
        let key_package_bundle = {
            let parent_hash = self.compute_parent_hash(own_index);
            let parent_hash_extension = ParentHashExtension::new(&parent_hash).to_extension();
            let mut key_package = key_package_bundle.get_key_package().clone();
            key_package.add_extension(parent_hash_extension);
            key_package.sign(&self.ciphersuite, signature_key);
            KeyPackageBundle::from_values(key_package, keypair.get_private_key().clone())
        };

        // Store new KeyPackage in tree
        self.nodes[own_index.as_usize()] =
            Node::new_leaf(Some(key_package_bundle.get_key_package().clone()));
        (commit_secret, path_option, secrets_option)
    }
    fn update_own_leaf(
        &mut self,
        key_package_bundle: &KeyPackageBundle,
        group_context: &[u8],
        with_direct_path: bool,
    ) -> (CommitSecret, Option<DirectPath>, Option<Vec<Vec<u8>>>) {
        // Extract the private key from the KeyPackageBundle
        let private_key = key_package_bundle.get_private_key();

        // Compute the direct path and keypairs along it
        let own_index = self.get_own_node_index();
        let dirpath_root = treemath::dirpath_root(own_index, self.leaf_count());
        let node_secret = private_key.as_slice();
        let (path_secrets, confirmation) = PathKeypairs::generate_path_secrets(
            &self.ciphersuite,
            &node_secret,
            dirpath_root.len(),
        );
        let keypairs = PathKeypairs::generate_path_keypairs(&self.ciphersuite, &path_secrets);
        self.merge_keypairs(&keypairs, &dirpath_root);

        // Update own leaf node with the new values
        self.nodes[own_index.as_usize()] =
            Node::new_leaf(Some(key_package_bundle.get_key_package().clone()));
        let mut path_keypairs = PathKeypairs::new();
        path_keypairs.add(&keypairs, &dirpath_root);
        self.own_private_key = key_package_bundle.get_private_key().clone();
        self.path_keypairs = path_keypairs;
        if with_direct_path {
            (
                confirmation,
                Some(self.encrypt_to_copath(
                    &path_secrets,
                    keypairs,
                    group_context,
                    key_package_bundle.get_key_package().clone(),
                )),
                Some(path_secrets),
            )
        } else {
            (confirmation, None, None)
        }
    }
    fn encrypt_to_copath(
        &self,
        path_secrets: &[Vec<u8>],
        keypairs: Vec<HPKEKeyPair>,
        group_context: &[u8],
        leaf_key_package: KeyPackage,
    ) -> DirectPath {
        let copath = treemath::copath(self.get_own_node_index(), self.leaf_count());
        assert_eq!(path_secrets.len(), copath.len()); // TODO return error
        assert_eq!(keypairs.len(), copath.len());
        let mut direct_path_nodes = vec![];
        let mut ciphertexts = vec![];
        for pair in path_secrets.iter().zip(copath.iter()) {
            let (path_secret, copath_node) = pair;
            let node_ciphertexts: Vec<HpkeCiphertext> = self
                .resolve(*copath_node)
                .par_iter()
                .map(|&x| {
                    let pk = self.nodes[x.as_usize()].get_public_hpke_key().unwrap();
                    self.ciphersuite
                        .hpke_seal(&pk, group_context, &[], &path_secret)
                })
                .collect();
            // TODO Check that all public keys are non-empty
            // TODO Handle potential errors
            ciphertexts.push(node_ciphertexts);
        }
        for pair in keypairs.iter().zip(ciphertexts.iter()) {
            let (keypair, node_ciphertexts) = pair;
            direct_path_nodes.push(DirectPathNode {
                public_key: keypair.get_public_key().clone(),
                encrypted_path_secret: node_ciphertexts.clone(),
            });
        }
        DirectPath {
            leaf_key_package,
            nodes: direct_path_nodes,
        }
    }
    fn merge_public_keys(&mut self, direct_path: &DirectPath, path: Vec<NodeIndex>) {
        assert_eq!(direct_path.nodes.len(), path.len()); // TODO return error
        for (i, p) in path.iter().enumerate() {
            let public_key = direct_path.nodes[i].clone().public_key;
            let node = ParentNode::new(public_key.clone(), &[], &[]);
            self.nodes[p.as_usize()].node = Some(node);
        }
    }
    pub fn merge_keypairs(&mut self, keypairs: &[HPKEKeyPair], path: &[NodeIndex]) {
        assert_eq!(keypairs.len(), path.len()); // TODO return error
        for i in 0..path.len() {
            let node = ParentNode::new(keypairs[i].get_public_key().clone(), &[], &[]);
            self.nodes[path[i].as_usize()].node = Some(node);
        }
    }

    /// Add nodes for the provided key packages.
    pub(crate) fn add_nodes(&mut self, new_kp: &[KeyPackage]) -> Vec<(NodeIndex, Credential)> {
        let num_new_kp = new_kp.len();
        let mut added_members = Vec::with_capacity(num_new_kp);

        if num_new_kp > (2 * self.leaf_count().as_usize()) {
            self.nodes
                .reserve_exact((2 * num_new_kp) - (2 * self.leaf_count().as_usize()));
        }

        // Add new nodes for key packages into existing free leaves.
        // Note that zip makes it so only the first free_leaves().len() nodes are taken.
        let free_leaves = self.free_leaves();
        let free_leaves_len = free_leaves.len();
        for (new_kp, leaf_index) in new_kp.iter().zip(free_leaves) {
            self.nodes[leaf_index.as_usize()] = Node::new_leaf(Some(new_kp.clone()));
            let dirpath = treemath::dirpath_root(leaf_index, self.leaf_count());
            for d in dirpath.iter() {
                if !self.nodes[d.as_usize()].is_blank() {
                    let node = &self.nodes[d.as_usize()];
                    let index = d.as_u32();
                    // TODO handle error
                    let mut parent_node = node.node.clone().unwrap();
                    if !parent_node.get_unmerged_leaves().contains(&index) {
                        parent_node.get_unmerged_leaves_mut().push(index);
                    }
                    self.nodes[d.as_usize()].node = Some(parent_node);
                }
            }
            added_members.push((leaf_index, new_kp.get_credential().clone()));
        }
        // Add the remaining nodes.
        let mut new_nodes = Vec::with_capacity(num_new_kp * 2);
        let mut leaf_index = self.nodes.len() + 1;
        for add_proposal in new_kp.iter().skip(free_leaves_len) {
            new_nodes.extend(vec![
                Node::new_blank_parent_node(),
                Node::new_leaf(Some(add_proposal.clone())),
            ]);
            let node_index = NodeIndex::from(leaf_index);
            added_members.push((node_index, add_proposal.get_credential().clone()));
            leaf_index += 2;
        }
        self.nodes.extend(new_nodes);
        self.trim_tree();
        added_members
    }

    pub fn apply_proposals(
        &mut self,
        proposal_id_list: &ProposalIDList,
        proposal_queue: ProposalQueue,
        pending_kpbs_option: Option<Vec<KeyPackageBundle>>,
    ) -> (MembershipChanges, Vec<(NodeIndex, AddProposal)>, bool) {
        let mut updated_members = vec![];
        let mut removed_members = vec![];
        let mut invited_members = Vec::with_capacity(proposal_id_list.adds.len());

        let mut self_removed = false;

        for u in proposal_id_list.updates.iter() {
            let (_proposal_id, queued_proposal) = proposal_queue.get(&u).unwrap();
            let proposal = &queued_proposal.proposal;
            let update_proposal = proposal.as_update().unwrap();
            let sender = queued_proposal.sender;
            let index = sender.as_node_index();
            let leaf_node = Node::new_leaf(Some(update_proposal.key_package.clone()));
            updated_members.push(update_proposal.key_package.get_credential().clone());
            self.blank_member(index);
            self.nodes[index.as_usize()] = leaf_node;
            if index == self.get_own_node_index() {
                if let Some(pending_kpbs) = &pending_kpbs_option {
                    let own_kpb = pending_kpbs
                        .iter()
                        .find(|&kpb| kpb.get_key_package() == &update_proposal.key_package)
                        .unwrap();
                    self.own_private_key = own_kpb.get_private_key().clone();
                    self.path_keypairs = PathKeypairs::new();
                }
            }
        }
        for r in proposal_id_list.removes.iter() {
            let (_proposal_id, queued_proposal) = proposal_queue.get(&r).unwrap();
            let proposal = &queued_proposal.proposal;
            let remove_proposal = proposal.as_remove().unwrap();
            let removed = NodeIndex::from(remove_proposal.removed);
            if removed == self.get_own_node_index() {
                self_removed = true;
            }
            let removed_member_node = self.nodes[removed.as_usize()].clone();
            let removed_member = if let Some(key_package) = removed_member_node.key_package {
                key_package
            } else {
                // TODO check it's really a leaf node
                panic!("Cannot remove a parent/empty node")
            };
            removed_members.push(removed_member.get_credential().clone());
            self.blank_member(removed);
        }

        // Process adds
        let added_members = if !proposal_id_list.adds.is_empty() {
            let add_proposals: Vec<AddProposal> = proposal_id_list
                .adds
                .par_iter()
                .map(|a| {
                    let (_proposal_id, queued_proposal) = proposal_queue.get(&a).unwrap();
                    let proposal = &queued_proposal.proposal;
                    proposal.as_add().unwrap()
                })
                .collect();
            // TODO make sure intermediary nodes are updated with unmerged_leaves
            let key_packages: Vec<KeyPackage> = add_proposals
                .iter()
                .map(|a| a.key_package.clone())
                .collect();
            let added = self.add_nodes(&key_packages);

            for (i, added) in added.iter().enumerate() {
                invited_members.push((added.0, add_proposals.get(i).unwrap().clone()));
            }
            added
        } else {
            Vec::new()
        };

        // Return membership changes
        (
            MembershipChanges {
                updates: updated_members,
                removes: removed_members,
                adds: added_members.iter().map(|(_, n)| n.clone()).collect(),
            },
            invited_members,
            self_removed,
        )
    }
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
    pub fn compute_tree_hash(&self) -> Vec<u8> {
        fn node_hash(ciphersuite: &Ciphersuite, tree: &RatchetTree, index: NodeIndex) -> Vec<u8> {
            let node = &tree.nodes[index.as_usize()];
            match node.node_type {
                NodeType::Leaf => {
                    let leaf_node_hash = LeafNodeHashInput::new(&index, &node.key_package);
                    leaf_node_hash.hash(ciphersuite)
                }
                NodeType::Parent => {
                    let left = treemath::left(index);
                    let left_hash = node_hash(ciphersuite, tree, left);
                    let right = treemath::right(index, tree.leaf_count());
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
    pub fn compute_parent_hash(&mut self, index: NodeIndex) -> Vec<u8> {
        let parent = treemath::parent(index, self.leaf_count());
        let parent_hash = if parent == treemath::root(self.leaf_count()) {
            let root_node = &self.nodes[parent.as_usize()];
            root_node.hash(&self.ciphersuite).unwrap()
        } else {
            self.compute_parent_hash(parent)
        };
        let current_node = &self.nodes[index.as_usize()];
        if let Some(mut parent_node) = current_node.node.clone() {
            parent_node.set_parent_hash(parent_hash);
            self.nodes[index.as_usize()].node = Some(parent_node);
            let updated_parent_node = &self.nodes[index.as_usize()];
            updated_parent_node.hash(&self.ciphersuite).unwrap()
        } else {
            parent_hash
        }
    }
    pub fn verify_integrity(ciphersuite: &Ciphersuite, nodes: &[Option<Node>]) -> bool {
        let node_count = NodeIndex::from(nodes.len());
        let size = node_count;
        for i in 0..node_count.as_usize() {
            let node_option = &nodes[i];
            if let Some(node) = node_option {
                match node.node_type {
                    NodeType::Parent => {
                        let left_index = treemath::left(NodeIndex::from(i));
                        let right_index = treemath::right(NodeIndex::from(i), size.into());
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
                            if !kp.verify() {
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

pub struct ParentNodeHashInput<'a> {
    node_index: u32,
    parent_node: &'a Option<ParentNode>,
    left_hash: &'a [u8],
    right_hash: &'a [u8],
}

impl<'a> ParentNodeHashInput<'a> {
    pub fn new(
        node_index: u32,
        parent_node: &'a Option<ParentNode>,
        left_hash: &'a [u8],
        right_hash: &'a [u8],
    ) -> Self {
        Self {
            node_index,
            parent_node,
            left_hash,
            right_hash,
        }
    }
    pub fn hash(&self, ciphersuite: &Ciphersuite) -> Vec<u8> {
        let payload = self.encode_detached().unwrap();
        ciphersuite.hash(&payload)
    }
}

pub struct LeafNodeHashInput<'a> {
    node_index: &'a NodeIndex,
    key_package: &'a Option<KeyPackage>,
}

impl<'a> LeafNodeHashInput<'a> {
    pub fn new(node_index: &'a NodeIndex, key_package: &'a Option<KeyPackage>) -> Self {
        Self {
            node_index,
            key_package,
        }
    }
    pub fn hash(&self, ciphersuite: &Ciphersuite) -> Vec<u8> {
        let payload = self.encode_detached().unwrap();
        ciphersuite.hash(&payload)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DirectPathNode {
    pub public_key: HPKEPublicKey,
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct DirectPath {
    pub leaf_key_package: KeyPackage,
    pub nodes: Vec<DirectPathNode>,
}
