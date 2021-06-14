use crate::binary_tree::NodeIndex;

use super::{array_representation::*, FLBBinaryTree, FLBBinaryTreeError};

#[test]
fn test_tree_creation() {
    // Test tree creation: Wrong number of nodes.
    let mut nodes = vec![0, 1];
    assert_eq!(
        ABinaryTree::new(nodes.clone())
            .expect_err("No error when creating a non-full binary tree."),
        FLBBinaryTreeError::InvalidNumberOfNodes
    );
    nodes.push(2);

    // Test tree creation: Positive case.
    let tree1 = ABinaryTree::new(nodes).expect("Error when creating tree from nodes.");
    let mut tree2 = ABinaryTree::new(vec![0]).expect("Error when creating a one-node binary tree.");
    tree2
        .add(1, 2)
        .expect("error when adding nodes to small enough tree");
    assert_eq!(tree1, tree2);

    // Test tree creation: Too many nodes.
    unsafe {
        let len = NodeIndex::max_value() as usize + 2;
        let mut nodes: Vec<u32> = Vec::new();
        nodes.set_len(len);

        assert_eq!(
            ABinaryTree::new(nodes).expect_err("No error while creating too large tree."),
            FLBBinaryTreeError::OutOfRange
        )
    }
}

#[test]
fn test_node_addition() {
    // Test node addition: Positive case.
    let mut tree = ABinaryTree::new(vec![0]).expect("Error when creating a one-node binary tree.");
    tree.add(1, 2)
        .expect("error when adding nodes to small enough tree");

    // Test node addition: Exceeding max number of nodes.
    unsafe {
        let len = NodeIndex::max_value() as usize;
        let mut nodes: Vec<u32> = Vec::new();
        nodes.set_len(len);
        let mut large_tree = ABinaryTree::new(nodes).expect("Error while creating large tree.");

        assert_eq!(
            large_tree
                .add(0, 0)
                .expect_err("No error while adding nodes when exceeding max tree size."),
            FLBBinaryTreeError::OutOfRange
        )
    }
}

#[test]
fn test_node_removal() {
    // Test node removal: Positive case.
    let mut tree = ABinaryTree::new(vec![0, 1, 2]).expect("Error when creating a tree.");
    tree.remove()
        .expect("error when adding nodes to small enough tree");
    assert_eq!(
        tree,
        ABinaryTree::new(vec![0]).expect("Error when creating tree from nodes.")
    );

    // Test node removal: Too few nodes.
    let nodes = vec![0];
    let mut tree = ABinaryTree::new(nodes).expect("Error while creating tree.");

    assert_eq!(
        tree.remove()
            .expect_err("No error when trying to remove nodes from too small tree."),
        FLBBinaryTreeError::NotEnoughNodes
    )
}

#[test]
fn test_node_access() {
    // Test node access: Positive case.
    let tree = ABinaryTree::new(vec![0, 1, 2]).expect("Error when creating a tree.");
    assert_eq!(tree.node(1).expect("Error when accessing node."), &1);

    // Test node access: Out of range.
    assert_eq!(
        tree.node(3)
            .expect_err("No error when accessing node outside of the tree."),
        FLBBinaryTreeError::OutOfBounds
    );

    // Test mutable node access: Positive case.
    let mut tree = ABinaryTree::new(vec![0, 1, 2]).expect("Error when creating a tree.");
    *tree
        .node_mut(1)
        .expect("Error when accessing node mutably.") = 5;
    assert_eq!(tree.node(1).expect("Error when accessing node."), &5);

    // Test leaf access: Positive case.
    assert_eq!(tree.leaf(0).expect("Error when accessing leaf."), &0);

    // Test leaf access: Not a leaf.
    assert_eq!(
        tree.leaf(1).expect_err("Given index is not a leaf index"),
        FLBBinaryTreeError::IndexError
    );

    // Test leaf access: Out of bounds.
    assert_eq!(
        tree.leaf(4).expect_err("Given index is not a leaf index"),
        FLBBinaryTreeError::OutOfBounds
    );

    // Test mutable leaf access: Positive case.
    let mut tree = ABinaryTree::new(vec![0, 1, 2]).expect("Error when creating a tree.");
    *tree
        .leaf_mut(0)
        .expect("Error when accessing node mutably.") = 9;
    assert_eq!(tree.leaf(0).expect("Error when accessing node."), &9);
}

#[test]
fn test_direct_path() {
    let mut tree =
        ABinaryTree::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8]).expect("Error when creating a tree.");

    // Test direct path: Out of bounds.
    assert_eq!(
        tree.direct_path(10)
            .expect_err("No error when computing direct path out of bounds."),
        FLBBinaryTreeError::OutOfBounds
    );

    // Test direct path: Positive case.
    let direct_path = tree
        .direct_path(0)
        .expect("Error when computing direct path.");
    assert_eq!(direct_path, vec![1, 3, 7]);

    let direct_path = tree
        .direct_path(6)
        .expect("Error when computing direct path.");
    assert_eq!(direct_path, vec![5, 3, 7]);

    let direct_path = tree
        .direct_path(8)
        .expect("Error when computing direct path.");
    assert_eq!(direct_path, vec![7]);

    let direct_path = tree
        .direct_path(7)
        .expect("Error when computing direct path.");
    assert_eq!(direct_path, Vec::<u32>::new());

    tree.add(9, 10).expect("error when adding nodes");

    let direct_path = tree
        .direct_path(8)
        .expect("Error when computing direct path.");
    assert_eq!(direct_path, vec![9, 7]);
}

#[test]
fn test_copath() {
    let mut tree =
        ABinaryTree::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8]).expect("Error when creating a tree.");

    // Test copath: Out of bounds.
    assert_eq!(
        tree.copath(10)
            .expect_err("No error when computing copath out of bounds."),
        FLBBinaryTreeError::OutOfBounds
    );

    // Test direct path: Positive case.
    let copath = tree.copath(0).expect("Error when computing copath.");
    assert_eq!(copath, vec![2, 5, 8]);

    let copath = tree.copath(6).expect("Error when computing copath.");
    assert_eq!(copath, vec![4, 1, 8]);

    let copath = tree.copath(8).expect("Error when computing copath.");
    assert_eq!(copath, vec![3]);

    let copath = tree.copath(7).expect("Error when computing copath.");
    assert_eq!(copath, Vec::<u32>::new());

    tree.add(9, 10).expect("error when adding nodes");

    let copath = tree.copath(8).expect("Error when computing copath.");
    assert_eq!(copath, vec![10, 3]);
}

#[test]
fn test_lowest_common_ancestor() {
    let mut tree =
        ABinaryTree::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8]).expect("Error when creating a tree.");

    // Test lowest common ancestor: Out of bounds.
    assert_eq!(
        tree.lowest_common_ancestor(10, 0)
            .expect_err("No error when computing lowest common ancestor out of bounds."),
        FLBBinaryTreeError::OutOfBounds
    );
    assert_eq!(
        tree.lowest_common_ancestor(0, 10)
            .expect_err("No error when computing lowest common ancestor out of bounds."),
        FLBBinaryTreeError::OutOfBounds
    );

    // Test direct path: Positive case.
    let lowest_common_ancestor = tree
        .lowest_common_ancestor(0, 2)
        .expect("Error when computing lowest common ancestor.");
    assert_eq!(lowest_common_ancestor, 1);

    let lowest_common_ancestor = tree
        .lowest_common_ancestor(0, 1)
        .expect("Error when computing lowest common ancestor.");
    assert_eq!(lowest_common_ancestor, 1);

    let lowest_common_ancestor = tree
        .lowest_common_ancestor(8, 4)
        .expect("Error when computing lowest common ancestor.");
    assert_eq!(lowest_common_ancestor, 7);

    let lowest_common_ancestor = tree
        .lowest_common_ancestor(4, 1)
        .expect("Error when computing lowest common ancestor.");
    assert_eq!(lowest_common_ancestor, 3);

    tree.add(9, 10).expect("error when adding nodes");

    let lowest_common_ancestor = tree
        .lowest_common_ancestor(10, 4)
        .expect("Error when computing lowest common ancestor.");
    assert_eq!(lowest_common_ancestor, 7);
}
