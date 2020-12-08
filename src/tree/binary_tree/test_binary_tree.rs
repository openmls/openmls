use super::BinaryTree;
use crate::{prelude::random_u8, tree::index::NodeIndex};
use evercrypt::prelude::get_random_vec;

fn create_random_tree() -> BinaryTree<u8> {
    let size = random_u8();
    let nodes = get_random_vec(size as usize);
    BinaryTree::from(nodes)
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
    new_tree.add(new_nodes.clone());
    let new_tree_size = new_tree.size().as_usize();

    // Compare sizes of old and new tree.
    assert_eq!(tree_size + 10, new_tree_size);

    // Check that nodes were added properly.
    assert_eq!(
        &new_tree.nodes().as_slice()[tree_size..new_tree_size],
        new_nodes.as_slice()
    );

    // Remove newly added nodes.
    new_tree.truncate(tree_size);

    // Check that trees are now the same again.
    assert_eq!(new_tree.nodes(), tree.nodes());

    // Replace first node with zero.
    let old_first = new_tree.nodes().first().unwrap().clone();
    let old_removed_first = new_tree.replace(&NodeIndex::from(0u32), 0u8);
    // Check that it worked.
    assert_eq!(new_tree.nodes().first().unwrap(), &0u8);
    assert_eq!(old_first, old_removed_first.unwrap());

    // Finally, let's try to replace something with an out-of-bounds index.
    let error = new_tree.replace(&NodeIndex::from(new_tree_size), 0u8);
    assert!(error.is_err());
}

#[test]
fn test_out_of_bounds() {
    let mut tree = create_random_tree();

    let node = tree.node(&NodeIndex::from(tree.size().as_usize() + 1));

    assert!(node.is_err());

    let node = tree.node_mut(&NodeIndex::from(tree.size().as_usize() + 1));

    assert!(node.is_err());
}

#[test]
fn test_resolution() {
    // Create simple tree.
    let nodes = vec![0, 1, 2, 3, 4, 5, 6];
    let tree = BinaryTree::from(nodes);
    // A simple predicate. Return true if the node equals 1 or if it's a leaf
    // node.
    let predicate = |index: NodeIndex, node: &u8| -> Vec<NodeIndex> {
        if node == &1u8 || index.is_leaf() {
            vec![index.to_owned()]
        } else {
            vec![]
        }
    };

    let resolution = tree.resolve(&NodeIndex::from(3u32), &predicate).unwrap();
    println!("Resolution: {:?}", resolution);
    let mut result = vec![1u32, 4u32, 6u32];
    let result_indices: Vec<NodeIndex> = result.drain(..).map(|i| NodeIndex::from(i)).collect();
    assert_eq!(resolution, result_indices)
}
