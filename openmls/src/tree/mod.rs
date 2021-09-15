use crate::ciphersuite::signable::Signable;
use crate::config::{Config, ProtocolVersion};
use crate::credentials::*;
use crate::key_packages::*;
use crate::messages::proposals::*;
use crate::messages::PathSecret;
use crate::{ciphersuite::*, prelude::PreSharedKeyId};

// Tree modules
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
use tls_codec::{Size, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU32};

use crate::schedule::{CommitSecret, PreSharedKeys};
pub(crate) use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};

use std::{collections::HashSet, convert::TryFrom};

#[cfg(any(feature = "test-utils", test))]
pub mod tests_and_kats;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
/// The ratchet tree.
pub struct RatchetTree {
    /// The ciphersuite used in this tree.
    ciphersuite: &'static Ciphersuite,

    /// The MLS protocol version used in this tree.
    mls_version: ProtocolVersion,

    /// All nodes in the tree.
    /// Note that these only hold public values.
    /// Private values are stored in the `private_tree`.
    /// FIXME: this must not be public and will be fixed in #423.
    pub nodes: Vec<Node>,

    /// This holds all private values in the tree.
    /// See `PrivateTree` for details.
    private_tree: PrivateTree,
}

implement_persistence!(RatchetTree, mls_version, nodes, private_tree);

impl RatchetTree {
    /// Create a new `RatchetTree` with only the "self" member as first node.
    pub(crate) fn new(kpb: KeyPackageBundle) -> RatchetTree {
        // Create an initial, empty tree
        let mut tree = Self {
            ciphersuite: kpb.key_package().ciphersuite(),
            mls_version: kpb.key_package().protocol_version(),
            nodes: Vec::new(),
            private_tree: PrivateTree::new(0usize.into()),
        };
        // Add our own node
        let (index, _credential) = tree.add_node(kpb.key_package());
        tree.private_tree = PrivateTree::from_leaf_secret(index, kpb.leaf_secret());
        tree
    }

    pub fn ciphersuite(&self) -> &'static Ciphersuite {
        self.ciphersuite
    }

    /// Create a new `RatchetTree` by cloning the public tree nodes from another
    /// tree and an empty `PrivateTree`
    pub(crate) fn new_from_public_tree(ratchet_tree: &RatchetTree) -> Self {
        RatchetTree {
            ciphersuite: ratchet_tree.ciphersuite,
            mls_version: ratchet_tree.mls_version,
            nodes: ratchet_tree.nodes.clone(),
            private_tree: PrivateTree::new(ratchet_tree.private_tree.leaf_index()),
        }
    }

    /// Generate a new `RatchetTree` from `Node`s with the client's key package
    /// bundle `kpb`. The client's node must be in the list of nodes and the list
    /// of nodes must contain all nodes of the tree, including intermediates.
    pub(crate) fn new_from_nodes(
        kpb: KeyPackageBundle,
        node_options: &[Option<Node>],
    ) -> Result<RatchetTree, TreeError> {
        // Build a full set of nodes for the tree based on the potentially incomplete
        // input nodes.
        let mut nodes: Vec<Node> = Vec::with_capacity(node_options.len());
        let mut own_node_index = None;
        for (i, node_option) in node_options.iter().enumerate() {
            if let Some(node) = node_option.clone() {
                if let Some(kp) = &node.key_package {
                    if kp == kpb.key_package() {
                        // Unwrapping here is safe, because we know it is a leaf node
                        own_node_index = Some(LeafIndex::try_from(NodeIndex::from(i)).unwrap());
                    }
                }
                nodes.push(node);
            } else if NodeIndex::from(i).is_leaf() {
                nodes.push(Node::new_leaf(None));
            } else {
                nodes.push(Node::new_blank_parent_node());
            }
        }

        let own_node_index = own_node_index.ok_or(TreeError::InvalidArguments)?;
        let private_tree = PrivateTree::from_leaf_secret(own_node_index, kpb.leaf_secret());

        Ok(Self {
            ciphersuite: kpb.leaf_secret().ciphersuite(),
            mls_version: kpb.leaf_secret().version(),
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
        self.public_key_tree().iter().map(|&n| n.cloned()).collect()
    }

    /// Returns the number of leaves in a tree
    pub fn leaf_count(&self) -> LeafIndex {
        treemath::leaf_count(self.tree_size())
    }

    /// Compute the resolution for a given node index. Leaves listed in the
    /// `exclusion_list` are subtracted from the final resolution.
    fn resolve(&self, index: NodeIndex, exclusion_list: &HashSet<&LeafIndex>) -> Vec<NodeIndex> {
        let size = self.leaf_count();

        // We end the recursion at leaf level
        if self.nodes[index].node_type == NodeType::Leaf {
            if self.nodes[index].is_blank()
                // We can unwrap here, because we just checked that the node is
                // indeed a leaf.
                || exclusion_list.contains(&LeafIndex::try_from(index).unwrap())
            {
                return vec![];
            } else {
                return vec![index];
            }
        }

        // If a node is not blank, the resolution consists of that node's index,
        // as well as its unmerged leaves.
        if !self.nodes[index].is_blank() {
            let mut resolution = vec![index];
            let node = self.nodes[index].node.as_ref();
            resolution.extend(
                node.unwrap()
                    .unmerged_leaves()
                    .iter()
                    .filter(|resolution_node| !exclusion_list.contains(resolution_node))
                    .map(|&n| NodeIndex::from(n)),
            );
            resolution
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

    /// Set a new own key package.
    fn set_key_package(&mut self, key_package: &KeyPackage) {
        let _old = self.nodes[self.private_tree.leaf_index()]
            .key_package
            .replace(key_package.clone());
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
        new_leaves_indexes: HashSet<&LeafIndex>,
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

        // Figure out the position in the resolution of the node that we have a
        // secret for. We first have to check if our leaf is in the resolution,
        // either due to blanks or due to us being an unmerged leaf.
        let position_in_resolution = match resolution.iter().position(|&x| own_index == x) {
            Some(position) => position,
            // If our leaf is not included, we look again and search for an
            // index in our leaf's direct path.
            None => {
                resolution
                    .iter()
                    .position(|&x| own_direct_path.contains(&x))
                    // We can unwrap here, because regardless of what the resolution
                    // looks like, there has to be a an entry in the resolution that
                    // corresponds to either the own leaf or a node in the direct path.
                    .unwrap()
            }
        };
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
        let secret_bytes =
            self.ciphersuite
                .hpke_open(hpke_ciphertext, private_key, &[], group_context)?;
        let path_secret =
            Secret::from_slice(&secret_bytes, ProtocolVersion::default(), self.ciphersuite).into();
        // Derive new path secrets and generate keypairs
        let new_path_public_keys =
            self.private_tree
                .continue_path_secrets(self.ciphersuite, path_secret, &common_path);

        // Extract public keys from UpdatePath
        let update_path_public_keys: Vec<HpkePublicKey> = update_path
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

        // We can unwrap here, because we know the commit secret was set via
        // ´continue_path_secrets´.
        Ok(self.private_tree.commit_secret().unwrap())
    }

    /// Update the private tree with the new `KeyPackageBundle`.
    pub(crate) fn replace_private_tree(
        &mut self,
        key_package_bundle: &KeyPackageBundle,
        group_context: &[u8],
    ) -> Option<&CommitSecret> {
        let _path_option = self.replace_private_tree_(
            key_package_bundle.leaf_secret(),
            key_package_bundle.key_package(),
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
        new_leaves_indexes: HashSet<&LeafIndex>,
    ) -> Result<(UpdatePath, KeyPackageBundle), TreeError> {
        // Generate new keypair
        let own_index = self.own_node_index();
        let own_key_package = self.own_key_package();

        // Replace the init key in the current KeyPackage
        let key_package_bundle_unsigned =
            KeyPackageBundlePayload::from_rekeyed_key_package(own_key_package);
        // FIXME: #419 THIS IS UNNECESSARY
        let key_package_bundle = key_package_bundle_unsigned.sign(credential_bundle)?;

        // Replace the private tree with a new one based on the new key package
        // bundle and store the key package in the own node.
        // XXX: #419 this step of setting the key package must go away.
        self.nodes[own_index] = Node::new_leaf(Some(key_package_bundle.key_package().clone()));
        let path_nodes = self
            .replace_private_tree_path_(
                key_package_bundle.leaf_secret(),
                group_context,
                Some(new_leaves_indexes), /* with update path */
            )
            .ok_or(TreeError::InvalidTree)?;

        // Compute the parent hash extension and update the KeyPackage and sign it
        let parent_hash = self.set_parent_hashes(own_index);
        let mut key_package_bundle_unsigned = key_package_bundle.unsigned();
        key_package_bundle_unsigned.update_parent_hash(&parent_hash);
        let key_package_bundle = key_package_bundle_unsigned.sign(credential_bundle)?;

        // Use new key package
        let mut path = UpdatePath::new(key_package_bundle.key_package().clone(), path_nodes);

        // Store it in the UpdatePath and the tree
        path.leaf_key_package = key_package_bundle.key_package().clone();
        self.set_key_package(key_package_bundle.key_package());

        Ok((path, key_package_bundle))
    }

    /// Replace the private tree with a new one based on the
    /// `key_package` and `leaf_secret`.
    fn replace_private_tree_(
        &mut self,
        leaf_secret: &Secret,
        key_package: &KeyPackage,
        group_context: &[u8],
        new_leaves_indexes_option: Option<HashSet<&LeafIndex>>,
    ) -> Option<UpdatePath> {
        let own_index = self.own_node_index();
        // Update own leaf node with the new values
        self.nodes[own_index] = Node::new_leaf(Some(key_package.clone()));
        let update_path_nodes =
            self.replace_private_tree_path_(leaf_secret, group_context, new_leaves_indexes_option);
        update_path_nodes.map(|nodes| UpdatePath::new(key_package.clone(), nodes))
    }

    /// Replace the private tree with a new one based on the
    /// `leaf_secret` only.
    fn replace_private_tree_path_(
        &mut self,
        leaf_secret: &Secret,
        group_context: &[u8],
        new_leaves_indexes_option: Option<HashSet<&LeafIndex>>,
    ) -> Option<Vec<UpdatePathNode>> {
        // Compute the direct path and keypairs along it
        let own_index = self.own_node_index();
        let direct_path_root = treemath::leaf_direct_path(own_index, self.leaf_count())
            .expect("replace_private_tree: Error when computing direct path.");
        // Update private tree and merge corresponding public keys.
        let (private_tree, new_public_keys) =
            PrivateTree::new_with_keys(self.ciphersuite, own_index, leaf_secret, &direct_path_root);
        self.private_tree = private_tree;

        self.merge_public_keys(&new_public_keys, &direct_path_root)
            .unwrap();

        self.set_parent_hashes(own_index);
        if let Some(new_leaves_indexes) = new_leaves_indexes_option {
            let update_path_nodes = self
                .encrypt_to_copath(new_public_keys, group_context, new_leaves_indexes)
                .unwrap();
            Some(update_path_nodes)
        } else {
            None
        }
    }

    /// Encrypt the path secrets to the co path and return the update path.
    fn encrypt_to_copath(
        &self,
        public_keys: Vec<HpkePublicKey>,
        group_context: &[u8],
        new_leaves_indexes: HashSet<&LeafIndex>,
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
                    self.ciphersuite.hpke_seal_secret(
                        pk,
                        &[],
                        group_context,
                        &path_secret.path_secret,
                    )
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
                encrypted_path_secret: node_ciphertexts.clone().into(),
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
        public_keys: &[HpkePublicKey],
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
        public_keys: &[HpkePublicKey],
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

    /// Add a node for the provided key package the tree on the right side.
    /// Note, that this function will not fill blank leaves. This function
    /// returns references to the `LeafIndex` the `KeyPackage` was placed into
    /// and to the Credential of the `KeyPackage.`
    fn add_node<'a>(&mut self, key_package: &'a KeyPackage) -> (LeafIndex, &'a Credential) {
        if !self.nodes.is_empty() {
            self.nodes.push(Node::new_blank_parent_node());
        }
        self.nodes.push(Node::new_leaf(Some((key_package).clone())));
        (
            (self.leaf_count().as_usize() - 1).into(),
            key_package.credential(),
        )
    }

    /// Add nodes for the provided key packages. Returns a vector containing the
    /// `LeafIndex` of the leaf each `KeyPackage` was placed into, as well as a
    /// reference to the corresponding `KeyPackage`'s `Credential`.
    pub(crate) fn add_nodes<'a>(
        &mut self,
        new_kps: &[&'a KeyPackage],
    ) -> Vec<(LeafIndex, &'a Credential)> {
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
        for (&new_kp, leaf_index) in new_kps.iter().zip(free_leaves) {
            self.nodes[leaf_index] = Node::new_leaf(Some((new_kp).clone()));
            added_members.push((leaf_index, new_kp.credential()));
        }
        // Add the remaining nodes.
        for &key_package in new_kps.iter().skip(free_leaves_len) {
            added_members.push(self.add_node(key_package));
        }

        // Add the newly added leaves to the unmerged leaves of all non-blank
        // parent nodes in their direct path.
        for (leaf_index, _) in &added_members {
            let dirpath = treemath::leaf_direct_path(leaf_index.to_owned(), self.leaf_count())
                .expect("add_nodes: Error when computing direct path.");
            for d in dirpath.iter() {
                if !self.nodes[d].is_blank() {
                    let node = &mut self.nodes[d];
                    // We can unwrap here, because we just checked that the node
                    // is not blank.
                    let mut parent_node = node.node.take().unwrap();
                    if !parent_node.unmerged_leaves().contains(leaf_index) {
                        parent_node.add_unmerged_leaf(leaf_index.to_owned());
                    }
                    self.nodes[d].node = Some(parent_node);
                }
            }
        }

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
        log::debug!("Applying proposal");
        let mut has_updates = false;
        let mut has_removes = false;
        let mut self_removed = false;

        // Process updates first
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Update) {
            has_updates = true;
            // Unwrapping here is safe because we know the proposal type
            let update_proposal = &queued_proposal.proposal().as_update().unwrap();
            let sender_index = queued_proposal.sender().to_leaf_index();
            // Prepare leaf node
            let leaf_node = Node::new_leaf(Some(update_proposal.key_package().clone()));
            // Blank the direct path of that leaf node
            self.blank_member(sender_index);
            // Replace the leaf node
            self.nodes[sender_index] = leaf_node;
            // Check if it is a self-update
            if sender_index == self.own_node_index() {
                let own_kpb = match updates_key_package_bundles
                    .iter()
                    .find(|&kpb| kpb.key_package() == update_proposal.key_package())
                {
                    Some(kpb) => kpb,
                    // We lost the KeyPackageBundle apparently
                    None => return Err(TreeError::InvalidArguments),
                };
                // Update the private tree with new values
                self.private_tree =
                    PrivateTree::from_leaf_secret(sender_index, own_kpb.leaf_secret());
            }
        }

        // Process removes
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Remove) {
            has_removes = true;
            // Unwrapping here is safe because we know the proposal type
            let remove_proposal = &queued_proposal.proposal().as_remove().unwrap();
            let removed = LeafIndex::from(remove_proposal.removed());
            // Check if we got removed from the group
            if removed == self.own_node_index() {
                self_removed = true;
            }
            // Blank the direct path of the removed member
            self.blank_member(removed);
        }

        // Process adds
        let add_proposals: Vec<AddProposal> = proposal_queue
            .filtered_by_type(ProposalType::Add)
            .map(|queued_proposal| {
                let proposal = &queued_proposal.proposal();
                // Unwrapping here is safe because we know the proposal type
                proposal.as_add().unwrap()
            })
            .collect();
        let has_adds = !add_proposals.is_empty();
        // Extract KeyPackages from proposals
        let key_packages: Vec<&KeyPackage> =
            add_proposals.iter().map(|a| a.key_package()).collect();
        // Add new members to tree
        let added_members = self.add_nodes(&key_packages);

        // Prepare invitations
        let mut invitation_list = Vec::new();
        for (i, added) in added_members.iter().enumerate() {
            invitation_list.push((added.0, add_proposals.get(i).unwrap().clone()));
        }

        // Process PSK proposals
        let psks: Vec<PreSharedKeyId> = proposal_queue
            .filtered_by_type(ProposalType::Presharedkey)
            .map(|queued_proposal| {
                // FIXME: remove unwrap
                // Unwrapping here is safe because we know the proposal type
                let psk_proposal = queued_proposal.proposal().as_presharedkey().unwrap();
                psk_proposal.into_psk_id()
            })
            .collect();

        let presharedkeys = PreSharedKeys { psks: psks.into() };

        // Determine if Commit needs a path field
        let path_required = has_updates || has_removes || !has_adds;

        // If members were removed, truncate the tree.
        if has_removes {
            self.trim_tree()
        }

        Ok(ApplyProposalsValues {
            path_required,
            self_removed,
            invitation_list,
            presharedkeys,
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
    pub(crate) fn commit_secret(&self) -> Option<&CommitSecret> {
        self.private_tree.commit_secret()
    }

    /// Get the path secret for a given target node. Returns `None` if the given
    /// index is not in the tree or not on the direct path of the `own_node`.
    pub(crate) fn path_secret(&self, index: NodeIndex) -> Option<&PathSecret> {
        // Get a Vector containing the node indices of the direct path to the
        // root from our own leaf.
        if let Ok(mut dirpath) =
            treemath::leaf_direct_path(self.own_node_index(), self.leaf_count())
        {
            // Filter out blanks for which we don't have path secrets
            let mut dirpath_filter = dirpath
                .drain(..)
                .filter(|&index| !self.nodes[index].is_blank());

            // Compute the right index in the `path_secrets` vector and get the secret.
            if let Some(position) = dirpath_filter.position(|x| x == index) {
                return self.private_tree.path_secrets().get(position);
            }
        }

        // Return None if either of the conditions is not fulfilled.
        None
    }
}

/// This struct contain the return vallues of the `apply_proposals()` function
pub struct ApplyProposalsValues {
    pub path_required: bool,
    pub self_removed: bool,
    pub invitation_list: Vec<(LeafIndex, AddProposal)>,
    pub presharedkeys: PreSharedKeys,
}

impl ApplyProposalsValues {
    /// This function creates a `HashSet` of node indexes of the new nodes that
    /// were added to the tree. The `HashSet` will be querried by the
    /// `resolve()` function to filter out those nodes from the resolution.
    pub fn exclusion_list(&self) -> HashSet<&LeafIndex> {
        // Collect the new leaves' indexes so we can filter them out in the resolution
        // later
        let new_leaves_indexes: HashSet<&LeafIndex> = self
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
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct UpdatePathNode {
    pub(crate) public_key: HpkePublicKey,
    pub(crate) encrypted_path_secret: TlsVecU32<HpkeCiphertext>,
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     KeyPackage leaf_key_package;
///     UpdatePathNode nodes<0..2^32-1>;
/// } UpdatePath;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct UpdatePath {
    pub(crate) leaf_key_package: KeyPackage,
    pub(crate) nodes: TlsVecU32<UpdatePathNode>,
}

impl UpdatePath {
    /// Create a new update path.
    fn new(leaf_key_package: KeyPackage, nodes: Vec<UpdatePathNode>) -> Self {
        Self {
            leaf_key_package,
            nodes: nodes.into(),
        }
    }
}
