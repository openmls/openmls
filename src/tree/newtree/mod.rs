use self::binary_tree::BinaryTree;
use self::node::Node;

mod binary_tree;
mod node;

pub(crate) struct RatchetTreeBundle {
    /// The public part of the ratchet tree.
    public_tree: BinaryTree<Node>,
    /// The private part of the ratchet tree, containing only the private part
    /// of the leaf, as well as a (potentially partial) direct path, where each
    /// node on the direct path contains the corresponding `HPKEPrivateKey`.
    private_tree: PrivateTree,
}
