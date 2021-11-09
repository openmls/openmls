use crate::binary_tree::{MlsBinaryTree, MlsBinaryTreeError};

use super::array_representation::tree::NodeIndex;

use super::Addressable;

impl Addressable for u32 {
    type Address = Self;

    fn address(&self) -> Option<Self::Address> {
        Some(*self)
    }
}

#[test]
fn test_tree_creation() {
    // Test tree creation: Wrong number of nodes.
    let mut nodes = vec![1, 0];
    assert_eq!(
        MlsBinaryTree::new(&nodes).expect_err("No error when creating a non-full binary tree."),
        MlsBinaryTreeError::InvalidNumberOfNodes
    );
    nodes.push(2);

    // Test tree creation: Positive case.
    let tree1 = MlsBinaryTree::new(&nodes).expect("Error when creating tree from nodes.");
    let mut tree2 = MlsBinaryTree::new(&[1]).expect("Error when creating a one-node binary tree.");
    tree2
        .add_leaf(2)
        .expect("error when adding nodes to small enough tree");
    assert_eq!(tree1, tree2);

    // Test size reporting
    assert_eq!(tree1.size(), 3);
    assert_eq!(tree1.leaf_count(), 2);

    // Test tree creation: Too many nodes.
    let len = NodeIndex::max_value() as usize + 2;
    let mut nodes: Vec<u32> = Vec::new();

    unsafe {
        nodes.set_len(len);

        assert_eq!(
            MlsBinaryTree::new(&nodes).expect_err("No error while creating too large tree."),
            MlsBinaryTreeError::OutOfRange
        )
    }
}

#[test]
fn test_node_addition() {
    // Test node addition: Positive case.
    let mut tree = MlsBinaryTree::new(&[0]).expect("Error when creating a one-node binary tree.");
    tree.add_leaf(2)
        .expect("error when adding nodes to small enough tree");

    // Test node addition: Exceeding max number of nodes.
    unsafe {
        let len = NodeIndex::max_value() as usize;
        let mut nodes: Vec<u32> = Vec::new();

        nodes.set_len(len + 1);

        assert_eq!(
            MlsBinaryTree::new(&nodes).expect_err("Error while creating large tree."),
            MlsBinaryTreeError::OutOfRange
        )
    }

    // Test node collision
    assert_eq!(
        tree.add_leaf(2)
            .expect_err("No error when adding duplicate node."),
        MlsBinaryTreeError::AddressCollision
    );
}

#[test]
fn test_node_defaulting() {
    let mut tree = MlsBinaryTree::new(&[1, 2, 3]).expect("Error when creating a tree.");
    assert_eq!(
        tree.make_default(&1)
            .expect("error when making node default"),
        1
    );
    assert_eq!(
        tree,
        MlsBinaryTree::new(&[0, 2, 3]).expect("Error when creating tree from nodes.")
    );
}

#[test]
fn test_node_removal() {
    // Test node removal: Positive case.
    let mut tree = MlsBinaryTree::new(&[0, 1, 2]).expect("Error when creating a tree.");
    tree.remove()
        .expect("error when adding nodes to small enough tree");
    assert_eq!(
        tree,
        MlsBinaryTree::new(&[0]).expect("Error when creating tree from nodes.")
    );

    // Test node removal: Too few nodes.
    let nodes = vec![0];
    let mut tree = MlsBinaryTree::new(&nodes).expect("Error while creating tree.");

    assert_eq!(
        tree.remove()
            .expect_err("No error when trying to remove nodes from too small tree."),
        MlsBinaryTreeError::NotEnoughNodes
    )
}

#[test]
fn test_node_access() {
    // Test node access: Positive case.
    let tree = MlsBinaryTree::new(&[0, 1, 2]).expect("Error when creating a tree.");
    assert_eq!(tree.node(&1).expect("Error when accessing node."), &1);

    // Test node access: Not in the tree.
    assert_eq!(tree.node(&3), None);

    // Test node replacement: Positive case.
    let mut tree = MlsBinaryTree::new(&[0, 1, 2]).expect("Error when creating a tree.");
    tree.replace(&1, 5)
        .expect("Error when trying to replace node.");
    assert_eq!(tree.node(&5).expect("Error when accessing node."), &5);
    assert_eq!(
        tree,
        MlsBinaryTree::new(&[0, 5, 2]).expect("Error when creating tree from nodes.")
    );

    assert_eq!(
        tree.replace(&1, 5)
            .expect_err("No error when trying to replace non-existing node."),
        MlsBinaryTreeError::NodeNotFound
    );
}

#[test]
fn test_direct_path() {
    let mut tree =
        MlsBinaryTree::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8]).expect("Error when creating a tree.");

    // Test direct path: Out of bounds.
    assert_eq!(
        tree.direct_path(&10)
            .expect_err("No error when computing direct path out of bounds."),
        MlsBinaryTreeError::NodeNotFound
    );

    // Test direct path: Positive case.
    let direct_path = tree
        .direct_path(&0)
        .expect("Error when computing direct path.");
    let test_vec = vec![1, 3, 7];
    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
    assert_eq!(direct_path, test_vec_ref);

    let direct_path = tree
        .direct_path(&6)
        .expect("Error when computing direct path.");
    let test_vec = vec![5, 3, 7];
    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
    assert_eq!(direct_path, test_vec_ref);

    let direct_path = tree
        .direct_path(&8)
        .expect("Error when computing direct path.");
    let test_vec = vec![7];
    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
    assert_eq!(direct_path, test_vec_ref);

    let direct_path = tree
        .direct_path(&7)
        .expect("Error when computing direct path.");
    assert_eq!(direct_path, Vec::<&u32>::new());

    tree.add_leaf(10).expect("error when adding nodes");

    let direct_path = tree
        .direct_path(&8)
        .expect("Error when computing direct path.");
    let test_vec = vec![0, 7];
    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
    assert_eq!(direct_path, test_vec_ref);

    // Test for a very small tree.
    let tree = MlsBinaryTree::new(&[1]).expect("Error when creating a tree.");

    let direct_path = tree
        .direct_path(&1)
        .expect("Error when computing direct path.");
    assert_eq!(direct_path, Vec::<&u32>::new());
}

#[test]
fn test_copath() {
    let tree =
        MlsBinaryTree::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8]).expect("Error when creating a tree.");

    // Test copath: Out of bounds.
    assert_eq!(
        tree.copath(&10)
            .expect_err("No error when computing copath out of bounds."),
        MlsBinaryTreeError::NodeNotFound
    );

    // Test direct path: Positive case.
    let copath = tree.copath(&0).expect("Error when computing copath.");
    let test_vec = vec![2, 5, 8];
    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
    assert_eq!(copath, test_vec_ref);

    let copath = tree.copath(&6).expect("Error when computing copath.");
    let test_vec = vec![4, 1, 8];
    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
    assert_eq!(copath, test_vec_ref);

    let copath = tree.copath(&8).expect("Error when computing copath.");
    let test_vec = vec![3];
    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
    assert_eq!(copath, test_vec_ref);

    let copath = tree.copath(&7).expect("Error when computing copath.");
    assert_eq!(copath, Vec::<&u32>::new());

    let mut tree = tree.clone();
    tree.add_leaf(10).expect("error when adding nodes");

    let copath = tree.copath(&8).expect("Error when computing copath.");
    let test_vec = vec![10, 3];
    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
    assert_eq!(copath, test_vec_ref);

    // Test for a very small tree.
    let tree = MlsBinaryTree::new(&[1]).expect("Error when creating a tree.");

    let copath = tree.copath(&1).expect("Error when computing copath.");
    assert_eq!(copath, Vec::<&u32>::new());
}

#[test]
fn test_lowest_common_ancestor() {
    let mut tree =
        MlsBinaryTree::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8]).expect("Error when creating a tree.");

    // Test lowest common ancestor: Node not found.
    assert_eq!(
        tree.lowest_common_ancestor(&10, &0)
            .expect_err("No error when computing lowest common ancestor out of bounds."),
        MlsBinaryTreeError::NodeNotFound
    );
    assert_eq!(
        tree.lowest_common_ancestor(&0, &10)
            .expect_err("No error when computing lowest common ancestor out of bounds."),
        MlsBinaryTreeError::NodeNotFound
    );

    // Test direct path: Positive case.
    let lowest_common_ancestor = tree
        .lowest_common_ancestor(&0, &2)
        .expect("Error when computing lowest common ancestor.");
    assert_eq!(lowest_common_ancestor, &1u32);

    let lowest_common_ancestor = tree
        .lowest_common_ancestor(&0, &1)
        .expect("Error when computing lowest common ancestor.");
    assert_eq!(lowest_common_ancestor, &1u32);

    let lowest_common_ancestor = tree
        .lowest_common_ancestor(&8, &4)
        .expect("Error when computing lowest common ancestor.");
    assert_eq!(lowest_common_ancestor, &7u32);

    let lowest_common_ancestor = tree
        .lowest_common_ancestor(&4, &1)
        .expect("Error when computing lowest common ancestor.");
    assert_eq!(lowest_common_ancestor, &3u32);

    tree.add_leaf(10).expect("error when adding nodes");

    let lowest_common_ancestor = tree
        .lowest_common_ancestor(&10, &4)
        .expect("Error when computing lowest common ancestor.");
    assert_eq!(lowest_common_ancestor, &7u32);

    // Test for a very small tree.
    let tree = MlsBinaryTree::new(&[1]).expect("Error when creating a tree.");

    let lowest_common_ancestor = tree
        .lowest_common_ancestor(&1, &1)
        .expect("Error when computing lowest common ancestor.");
    assert_eq!(lowest_common_ancestor, &1u32);
}
