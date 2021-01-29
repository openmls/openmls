use std::convert::TryFrom;

use super::BinaryTree;
use crate::tree::index::NodeIndex;
use evercrypt::prelude::get_random_vec;

#[test]
fn test_basic_operations() {
    let nodes = get_random_vec(9 as usize);
    let tree = BinaryTree::try_from(nodes).unwrap();
    // Get current tree size.
    let tree_size = tree.size().as_usize();
    // Create nodes to add.
    let mut new_nodes_part1 = get_random_vec(5);
    let mut new_nodes_part2 = get_random_vec(5);
    let new_nodes: Vec<(u8, u8)> = new_nodes_part1
        .drain(..)
        .zip(new_nodes_part2.drain(..))
        .collect();

    let flattened_new_nodes_len = new_nodes.len() * 2;
    let flattened_new_nodes = new_nodes.clone().drain(..).fold(
        Vec::with_capacity(flattened_new_nodes_len),
        |mut vector, tuple| {
            vector.push(tuple.0);
            vector.push(tuple.1);
            vector
        },
    );
    // Clone so we can compare later.
    let mut new_tree = tree.clone();
    // Add new nodes to the tree.
    new_tree.add(new_nodes.clone());
    let new_tree_size = new_tree.size().as_usize();

    // Compare sizes of old and new tree.
    assert_eq!(tree_size + 10, new_tree_size);

    // Check that nodes were added properly.
    assert_eq!(
        &new_tree.nodes().as_slice()[tree_size..new_tree_size],
        flattened_new_nodes.as_slice()
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
    let nodes = get_random_vec(9 as usize);
    let mut tree = BinaryTree::try_from(nodes).unwrap();

    let node = tree.node(NodeIndex::from(tree.size().as_usize() + 1));

    assert!(node.is_err());

    let node = tree.node_mut(NodeIndex::from(tree.size().as_usize() + 1));

    assert!(node.is_err());
}
