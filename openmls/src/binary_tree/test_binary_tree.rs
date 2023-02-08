use std::collections::HashSet;

use crate::binary_tree::{
    array_representation::tree::{ABinaryTree, TreeNode},
    MlsBinaryTree, MlsBinaryTreeError,
};

use super::{
    array_representation::{ParentNodeIndex, TreeSize},
    LeafNodeIndex,
};

#[test]
fn test_tree_basics() {
    // Test tree creation: Wrong number of nodes.
    let mut nodes = vec![TreeNode::Leaf(1), TreeNode::Parent(0)];
    assert_eq!(
        MlsBinaryTree::new(nodes.clone())
            .expect_err("No error when creating a non-full binary tree."),
        MlsBinaryTreeError::InvalidNumberOfNodes
    );
    nodes.push(TreeNode::Leaf(2));

    let tree1 = MlsBinaryTree::new(nodes.clone()).expect("Error when creating tree from nodes.");

    // Test size reporting
    assert_eq!(tree1.tree_size(), TreeSize::new(3));
    assert_eq!(tree1.leaf_count(), 2);

    // Test tree creation: Too many nodes (only in cases where usize is 64 bit).
    #[cfg(target_pointer_width = "64")]
    // We allow uninitialized vectors because we don't want to allocate so much memory
    #[allow(clippy::uninit_vec)]
    unsafe {
        let len = u32::MAX as usize + 2;
        let mut nodes: Vec<TreeNode<u32, u32>> = Vec::new();

        nodes.set_len(len);

        assert_eq!(
            MlsBinaryTree::new(nodes).expect_err("No error while creating too large tree."),
            MlsBinaryTreeError::OutOfRange
        )
    }

    // Node access
    assert_eq!(&1, tree1.leaf_by_index(LeafNodeIndex::new(0)));
    assert_eq!(&0, tree1.parent_by_index(ParentNodeIndex::new(0)));
    assert_eq!(&2, tree1.leaf_by_index(LeafNodeIndex::new(1)));

    // Leaves
    let leaves1: Vec<(LeafNodeIndex, &u32)> = tree1.leaves().collect();
    assert_eq!(
        vec![(LeafNodeIndex::new(0), &1), (LeafNodeIndex::new(1), &2)],
        leaves1
    );

    let tree3: ABinaryTree<u32, u32> =
        MlsBinaryTree::new(vec![TreeNode::Leaf(1)]).expect("error creating 1 node binary tree.");
    let leaves3: Vec<(LeafNodeIndex, &u32)> = tree3.leaves().collect();
    assert_eq!(vec![(LeafNodeIndex::new(0), &1)], leaves3);
}

#[test]
fn test_diff_merging() {
    let mut tree = MlsBinaryTree::new(vec![
        TreeNode::Leaf(2),
        TreeNode::Parent(0),
        TreeNode::Leaf(4),
    ])
    .expect("Error creating tree.");
    let original_tree = tree.clone();

    // Test the leaves in the original tree
    let leaves: Vec<(LeafNodeIndex, &u32)> = original_tree.leaves().collect();

    assert_eq!(leaves.len(), 2);
    assert_eq!(leaves[0], (LeafNodeIndex::new(0), &2));
    assert_eq!(leaves[1], (LeafNodeIndex::new(1), &4));

    let mut diff = tree.empty_diff();

    // Merging larger diffs.

    // Add a lot of leaves.

    // First we grow the tree
    while diff.size().u32() < 1000 {
        diff.grow_tree().expect("tree too big");
    }

    assert_eq!(diff.size().u32(), 1023);

    // Then we replace the leaves
    for index in 2..diff.size().leaf_count() {
        diff.replace_leaf(LeafNodeIndex::new(index), index);
    }

    // Check that the leaves were actually added.
    let leaves: Vec<(LeafNodeIndex, &u32)> = diff.leaves().collect();

    // Expect original leaves
    assert_eq!(leaves[0], (LeafNodeIndex::new(0), &2));
    assert_eq!(leaves[1], (LeafNodeIndex::new(1), &4));

    // Expect new leaves
    assert_eq!(leaves[2], (LeafNodeIndex::new(2), &2));
    assert_eq!(leaves[3], (LeafNodeIndex::new(3), &3));
    assert_eq!(leaves[4], (LeafNodeIndex::new(4), &4));

    let first_leaf = leaves.first().expect("leaf vector is empty");
    let last_leaf = leaves.last().expect("leaf vector is empty");
    assert_eq!(first_leaf, &(LeafNodeIndex::new(0), &2));
    assert_eq!(last_leaf, &(LeafNodeIndex::new(511), &511));
    assert_eq!(leaves.len(), diff.leaf_count() as usize);

    // Remove some of the leaves again by shrinking the tree
    diff.shrink_tree().expect("could not shrink the tree");
    assert_eq!(diff.size().u32(), 511);

    // Check that the leaves were actually removed.
    let leaves: Vec<(LeafNodeIndex, &u32)> = diff.leaves().collect();

    let first_leaf = leaves.first().expect("leaf vector is empty");
    let last_leaf = leaves.last().expect("leaf vector is empty");
    assert_eq!(first_leaf, &(LeafNodeIndex::new(0), &2));
    assert_eq!(last_leaf, &(LeafNodeIndex::new(255), &255));
    assert_eq!(leaves.len(), diff.leaf_count() as usize);

    let staged_diff = diff.into();
    tree.merge_diff(staged_diff);

    assert_eq!(tree.tree_size().u32(), 511);

    // Verify that the tree has changed post-merge.
    let leaves: Vec<(LeafNodeIndex, &u32)> = tree.leaves().collect();

    let first_leaf = leaves.first().expect("leaf vector is empty");
    let last_leaf = leaves.last().expect("leaf vector is empty");
    assert_eq!(first_leaf, &(LeafNodeIndex::new(0), &2));
    assert_eq!(last_leaf, &(LeafNodeIndex::new(255), &255));

    // Merging a diff that decreases the size of the tree.

    let mut diff = tree.empty_diff();
    while diff.size().leaf_count() > 2 {
        diff.shrink_tree().expect("could not shrink the tree");
    }

    let staged_diff = diff.into();
    tree.merge_diff(staged_diff);

    assert_eq!(tree, original_tree);
}

#[test]
fn test_new_tree_error() {
    // Let's test what happens when the tree is getting too large.
    let mut nodes: Vec<TreeNode<u32, u32>> = Vec::new();

    // We allow uninitialized vectors because we don't want to allocate so much memory
    #[allow(clippy::uninit_vec)]
    unsafe {
        nodes.set_len(u32::MAX as usize);

        assert_eq!(
            MlsBinaryTree::new(nodes).expect_err("no error adding beyond TREE_MAX"),
            MlsBinaryTreeError::OutOfRange
        )
    }
}

#[test]
fn test_diff_iter() {
    let nodes = (0..101)
        .map(|i| {
            if i % 2 == 0 {
                TreeNode::Leaf(i)
            } else {
                TreeNode::Parent(i)
            }
        })
        .collect();
    let tree = MlsBinaryTree::new(nodes).expect("error creating tree");

    let diff = tree.empty_diff();

    let mut leaf_set = HashSet::new();
    for (_, node) in diff.leaves() {
        leaf_set.insert(node);
    }
    for i in 0..51 {
        assert!(leaf_set.contains(&(i * 2)));
    }

    let mut parent_set = HashSet::new();
    for (_, node) in diff.parents() {
        parent_set.insert(node);
    }
    for i in 0..50 {
        assert!(parent_set.contains(&((i * 2) + 1)));
    }
}

#[test]
fn test_diff_mutable_access_after_manipulation() {
    let nodes = (0..101)
        .map(|i| {
            if i % 2 == 0 {
                TreeNode::Leaf(i)
            } else {
                TreeNode::Parent(i)
            }
        })
        .collect();
    let tree = MlsBinaryTree::new(nodes).expect("error creating tree");

    let mut diff = tree.empty_diff();

    // Let's change the nodes along a direct path.
    diff.set_direct_path_to_node(LeafNodeIndex::new(5), &999);

    // Now let's get references to a neighbour's path, where some nodes were
    // changed and some weren't.
    let direct_path_refs = diff.direct_path(LeafNodeIndex::new(6));
    for node_ref in &direct_path_refs {
        let node_mut = diff.parent_mut(*node_ref);
        *node_mut = 888;
    }

    let direct_path = diff
        .deref_vec(direct_path_refs)
        .expect("error dereferencing direct path nodes");
    assert_eq!(direct_path, vec![&888, &888, &888, &888, &888, &888])
}

#[test]
fn diff_leaf_access() {
    // We want to test if leaf access works correctly in a diff. In particular,
    // we want to ensure that if we access outside of the diff (but inside of
    // the original tree, e.g. because the tree was shrunk) we get a blank (i.e. the default leaf) back.
    let nodes = (0..7)
        .map(|i| {
            if i % 2 == 0 {
                // Let's add 10 so we recognize the default leaf which should be 0.
                TreeNode::Leaf(i + 10)
            } else {
                TreeNode::Parent(i + 10)
            }
        })
        .collect();
    let tree = MlsBinaryTree::new(nodes).expect("error creating tree");

    let mut diff = tree.empty_diff();

    // This should reduce the size of the tree by 1/2.
    diff.shrink_tree().unwrap();

    // The leaf at index 3 should be outside of the diff.
    let leaf_outside_of_diff = diff.leaf(LeafNodeIndex::new(3));
    assert_eq!(leaf_outside_of_diff, &0)
}
