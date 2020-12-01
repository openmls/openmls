use std::collections::HashMap;

use hpke::HPKEPrivateKey;

use crate::messages::proposals::ProposalID;
use crate::messages::proposals::ProposalQueue;
use crate::prelude::Ciphersuite;
use crate::prelude::KeyPackageBundle;
use crate::schedule::EpochSecrets;
use crate::tree::index::NodeIndex;
use crate::tree::InvitationList;
use crate::tree::TreeError;

use super::binary_tree::BinaryTree;
use super::node::Node;
use super::node::NodeContents;
use super::tree_secrets::CommitSecret;
use super::tree_secrets::PathSecret;
use super::RatchetTreeBundle;

#[allow(dead_code)]
pub(crate) struct ProvisionalTree<'a> {
    original_tree: Option<&'a RatchetTreeBundle>,

    /// If the `original_tree` is `Some`, the `node_index` should be equal to
    /// `original_tree.node_index`. If the `original_tree` is `None`, it has to
    /// be provided when creating the provisional tree.
    own_node_index: NodeIndex,
    /// The provisional public tree. It's either the base for a new
    /// `RatchetTree` or the staging ground for changes to an already existing
    /// `RatchetTree`.
    provisional_public_tree: BinaryTree<Option<Node>>,

    provisional_private_key: Option<HPKEPrivateKey>,
    provisional_path_keys: HashMap<NodeIndex, HPKEPrivateKey>,
}

#[allow(dead_code, unused_variables)]
impl<'a> ProvisionalTree<'a> {
    /// Create a `ProvisionalTree` from a given `RatchetTreeBundle` reference.
    pub(crate) fn from_ratchet_tree_bundle(original_tree: &'a RatchetTreeBundle) -> Self {
        let mut tree = Vec::new();
        tree.resize(original_tree.public_tree.size(), None);
        let provisional_public_tree = BinaryTree::from(tree);
        let provisional_private_key = None;
        let provisional_path_keys = HashMap::new();
        ProvisionalTree {
            original_tree: Some(original_tree),
            own_node_index: original_tree.node_index,
            provisional_public_tree,
            provisional_private_key,
            provisional_path_keys,
        }
    }

    /// Create a `ProvisionalTree` from a `KeyPackageBundle`. This function is
    /// used when creating a new group.
    pub(crate) fn from_key_package_bundle(key_package_bundle: KeyPackageBundle) -> Self {
        let node_contents = Some(NodeContents::LeafContents(key_package_bundle.key_package));
        let node = Node::new_leaf(node_contents);
        let provisional_public_tree = BinaryTree::from(vec![Some(node)]);
        let provisional_private_key = Some(key_package_bundle.private_key);
        let provisional_path_keys = HashMap::new();
        let node_index = NodeIndex::from(0u32);
        ProvisionalTree {
            original_tree: None,
            own_node_index: node_index,
            provisional_public_tree,
            provisional_private_key,
            provisional_path_keys,
        }
    }

    /// Create a `ProvisionalTree` from a `KeyPackageBundle` and some
    /// information from a `Welcome` message.
    pub(crate) fn from_welcome_info(
        key_package_bundle: KeyPackageBundle,
        node_index: NodeIndex,
        mut public_tree: BinaryTree<Node>,
    ) -> Self {
        let option_nodes: Vec<Option<Node>> =
            public_tree.nodes.drain(..).map(|n| Some(n)).collect();
        let provisional_public_tree = BinaryTree::from(option_nodes);
        let provisional_private_key = Some(key_package_bundle.private_key);
        let provisional_path_keys = HashMap::new();
        ProvisionalTree {
            original_tree: None,
            own_node_index: node_index,
            provisional_public_tree,
            provisional_private_key,
            provisional_path_keys,
        }
    }

    /// Apply a list of proposals to the `ProvisionalTree`.
    pub(crate) fn apply_proposals(
        &mut self,
        proposal_id_list: &[ProposalID],
        proposal_queue: ProposalQueue,
        updates_key_package_bundles: &[KeyPackageBundle],
        // (path_required, self_removed, invitation_list)
    ) -> Result<(bool, bool, InvitationList), TreeError> {
        unimplemented!()
    }

    /// Given an initial `PathSecret` for a node at `node_index`, derive the
    /// `PathSecret`s for the rest of the direct path and use them to derive the
    /// corresponding `HPKEKeyPairs`. The `HPKEPrivateKey` parts are written
    /// into the `provisional_path_keys` and the `provisional_public_tree` is
    /// updated with the `HPKEPublicKey` parts. Finally, return the
    /// `CommitSecret`.
    pub(crate) fn derive_path_keypairs(
        &mut self,
        path_secret: PathSecret,
        node_index: NodeIndex,
    ) -> CommitSecret {
        unimplemented!()
    }

    /// Verifies the integrity of the original tree as if the changes of the
    /// provisional tree had been applied.
    pub fn verify_integrity(&self, ciphersuite: &Ciphersuite) -> bool {
        unimplemented!()
    }

    /// Computes the tree hash of the original tree as if the changes of the
    /// provisional tree had been applied.
    pub fn compute_tree_hash(&self) -> Vec<u8> {
        unimplemented!()
    }

    /// Computes the parent hash of the original tree as if the changes of the
    /// provisional tree had been applied.
    pub fn compute_parent_hash(&mut self, index: NodeIndex) -> Vec<u8> {
        unimplemented!()
    }

    /// Computes the confirmation tag based on the original tree as if the
    /// changes of the provisional tree had been applied. TODO: I think we only
    /// need the confirmation key directly after applying a commit, so it should
    /// not be part of the `EpochSecrets` and instead derived seperately, so it
    /// can be consumed here.
    pub fn compute_confirmation_tag(
        &mut self,
        ciphersuite: &Ciphersuite,
        epoch_secrets: &EpochSecrets,
    ) -> Vec<u8> {
        unimplemented!()
    }
}
