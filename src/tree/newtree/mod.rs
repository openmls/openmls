use hpke::HPKEPrivateKey;

use crate::key_packages::KeyPackageBundle;

use self::binary_tree::BinaryTree;
use self::node::Node;
use self::provisional_tree::ProvisionalTree;
use self::ratchet_tree::RatchetTree;

use super::index::NodeIndex;
use super::path_keys::PathKeys;

mod binary_tree;
mod node;
mod provisional_tree;
mod ratchet_tree;
mod tree_secrets;

pub(crate) struct RatchetTreeBundle {
    /// The index of the node that represents owner of this `RatchetTreeBundle`.
    node_index: NodeIndex,

    /// The public part of the ratchet tree.
    public_tree: RatchetTree,
    /// This is the HPKE private key corresponding to the `HPKEPublicKey` in the
    /// node with index `node_index`.
    private_key: HPKEPrivateKey,

    /// A HashMap from NodeIndex to HPKEPrivateKeys in the (potentially partial)
    /// path from this leaf.
    path_keys: PathKeys,
}

impl RatchetTreeBundle {
    /// Create a new `RatchetTreeBundle` from a `KeyPackageBundle`. This
    /// function should only be used when creating a new group.
    pub(crate) fn new(key_package_bundle: KeyPackageBundle) -> Self {
        unimplemented!()
    }

    /// This function should be used when creating a new group from a `Welcome`
    /// message. It requires a copy of the group's public tree, as well as our
    /// own starting `KeyPackageBundle`, as well as our position in the tree.
    pub(crate) fn from_provisional_tree(public_tree: BinaryTree<Node>) -> Self {
        unimplemented!()
    }

    /// Write the changes from a provisional tree that was created from this
    /// `RatchetTree` back to this `RatchetTree`. In addition to updating the
    /// `RatchetTreeBundle` with the `ProvisionalTree`, the `public_tree` is
    /// trimmed.
    pub(crate) fn update_from_provisional_tree(&mut self, provisional_tree: ProvisionalTree) {
        unimplemented!()
    }
}
