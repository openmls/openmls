use std::convert::TryFrom;

use super::BinaryTree;
use crate::{prelude::random_u8, tree::index::NodeIndex};
use evercrypt::prelude::get_random_vec;

fn create_random_tree() -> BinaryTree<u8> {
    let size = random_u8() % 3;
    let nodes = get_random_vec(size as usize);
    BinaryTree::try_from(nodes).unwrap()
}

#[test]
fn test_basic_operations() {
    let tree = create_random_tree();
    // Get current tree size.
    let tree_size = tree.size().as_usize();
    // Create nodes to add.
    let new_nodes = get_random_vec(10);
    // Clone so we can compare later.
    let mut new_tree = tree.clone();
    // Add new nodes to the tree.
    new_tree.add(new_nodes.clone()).unwrap();
    let new_tree_size = new_tree.size().as_usize();

    // Compare sizes of old and new tree.
    assert_eq!(tree_size + 10, new_tree_size);

    // Check that nodes were added properly.
    assert_eq!(
        &new_tree.nodes().as_slice()[tree_size..new_tree_size],
        new_nodes.as_slice()
    );

    // Remove newly added nodes.
    new_tree.remove(10).unwrap();

    // Check that trees are now the same again.
    assert_eq!(new_tree.nodes(), tree.nodes());

    // Replace first node with zero.
    let old_first = new_tree.nodes().first().unwrap().clone();
    let old_removed_first = new_tree.replace(NodeIndex::from(0u32), 0u8);
    // Check that it worked.
    assert_eq!(new_tree.nodes().first().unwrap(), &0u8);
    assert_eq!(old_first, old_removed_first.unwrap());

    // Finally, let's try to replace something with an out-of-bounds index.
    let error = new_tree.replace(NodeIndex::from(new_tree_size), 0u8);
    assert!(error.is_err());
}

#[test]
fn test_out_of_bounds() {
    let mut tree = create_random_tree();

    let node = tree.node(NodeIndex::from(tree.size().as_usize() + 1));

    assert!(node.is_err());

    let node = tree.node_mut(NodeIndex::from(tree.size().as_usize() + 1));

    assert!(node.is_err());
}
