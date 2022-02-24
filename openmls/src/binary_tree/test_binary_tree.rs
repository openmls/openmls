use std::collections::HashSet;

use crate::binary_tree::{
    MlsBinaryTree, MlsBinaryTreeDiffError, MlsBinaryTreeError, OutOfBoundsError,
};

use super::array_representation::{tree::NodeIndex, treemath::TreeMathError};

#[test]
fn test_tree_basics() {
    // Test tree creation: Wrong number of nodes.
    let mut nodes = vec![1, 0];
    assert_eq!(
        MlsBinaryTree::new(nodes.clone())
            .expect_err("No error when creating a non-full binary tree."),
        MlsBinaryTreeError::InvalidNumberOfNodes
    );
    nodes.push(2);

    let tree1 = MlsBinaryTree::new(nodes.clone()).expect("Error when creating tree from nodes.");

    // Test size reporting
    assert_eq!(tree1.size().expect("error computing size"), 3);
    assert_eq!(tree1.leaf_count().expect("error computing leaf count"), 2);

    // Test tree creation: Too many nodes (only in cases where usize is 64 bit).
    #[cfg(target_pointer_width = "64")]
    // We allow uninitialized vectors because we don't want to allocate so much memory
    #[allow(clippy::uninit_vec)]
    unsafe {
        let len = NodeIndex::MAX as usize + 2;
        let mut nodes: Vec<u32> = Vec::new();

        nodes.set_len(len);

        assert_eq!(
            MlsBinaryTree::new(nodes).expect_err("No error while creating too large tree."),
            MlsBinaryTreeError::OutOfRange
        )
    }

    // Test node export
    let exported_nodes = tree1.nodes().to_vec();
    let tree2 =
        MlsBinaryTree::new(exported_nodes).expect("error when creating tree from exported nodes.");

    assert_eq!(tree1, tree2);

    // Node access
    assert_eq!(
        &1,
        tree1
            .node_by_index(0)
            .expect("no return value when accessing node in tree.")
    );
    assert_eq!(
        &0,
        tree1
            .node_by_index(1)
            .expect("no return value when accessing node in tree.")
    );
    assert_eq!(
        &2,
        tree1
            .node_by_index(2)
            .expect("error when accessing node in tree.")
    );
    assert_eq!(
        MlsBinaryTreeError::OutOfBounds,
        tree1
            .node_by_index(3)
            .expect_err("no error retrieving node out of bounds")
    );
    assert_eq!(
        MlsBinaryTreeError::OutOfBounds,
        tree1
            .node_by_index(10)
            .expect_err("no error retrieving node out of bounds")
    );

    // Leaves
    let leaves1 = tree1
        .leaves()
        .expect("error while compiling leaf references.");
    assert_eq!(vec![&1, &2], leaves1);

    let tree3 = MlsBinaryTree::new(vec![1]).expect("error creating 1 node binary tree.");
    let leaves3 = tree3
        .leaves()
        .expect("error while compiling leaf references.");
    assert_eq!(vec![&1], leaves3);
}

#[test]
fn test_node_references() {
    // Test empty diff.
    let mut tree =
        MlsBinaryTree::new(vec![0]).expect("Error when creating a one-node binary tree.");
    let original_tree = tree.clone();

    let diff = tree.empty_diff().expect("error creating empty diff");
    let staged_diff = diff.into();
    tree.merge_diff(staged_diff)
        .expect("error while merging empty diff.");

    assert_eq!(tree, original_tree);

    // Node access and node references
    let diff = tree.empty_diff().expect("error creating empty diff");
    let leaf_reference = diff.leaf(0).expect("error obtaining leaf reference.");

    assert_eq!(
        diff.leaf(1)
            .expect_err("no error when accessing leaf outside of tree"),
        MlsBinaryTreeDiffError::IndexOutOfBounds(OutOfBoundsError::IndexOutOfBounds)
    );

    let leaf_index = diff
        .leaf_index(leaf_reference)
        .expect("leaf reference without a leaf index.");

    assert_eq!(leaf_index, 0);
    assert!(diff.is_leaf(leaf_reference));

    let leaf = diff
        .node(leaf_reference)
        .expect("error dereferencing valid node reference");

    assert_eq!(leaf, &0);

    // Leaf replacement and node references.
    let mut diff = tree.empty_diff().expect("error creating empty diff");
    diff.replace_leaf(0, 1).expect("error replacing leaf");

    assert_eq!(
        diff.replace_leaf(1, 1).expect_err("error replacing leaf"),
        MlsBinaryTreeDiffError::IndexOutOfBounds(OutOfBoundsError::IndexOutOfBounds)
    );

    let leaf_reference = diff.leaf(0).expect("error obtaining leaf reference.");

    let leaf_mut = diff
        .node_mut(leaf_reference)
        .expect("error dereferencing valid node reference");

    assert_eq!(leaf_mut, &1);

    *leaf_mut = 2;

    let leaf_reference = diff.leaf(0).expect("error obtaining leaf reference.");

    let leaf = diff
        .node(leaf_reference)
        .expect("error dereferencing valid node reference");

    assert_eq!(leaf, &2);

    // Diff size
    assert_eq!(diff.tree_size(), 1);
    assert_eq!(diff.leaf_count(), 1);

    // root
    let root_ref = diff.root();

    let root = diff.node(root_ref).expect("error dereferencing root ref");
    assert_eq!(root, &2);

    // Leaf addition.
    let new_leaf_index = diff.add_leaf(0, 4).expect("error adding leaf");

    assert_eq!(new_leaf_index, 1);

    let leaf_reference = diff.leaf(1).expect("error obtaining leaf reference.");

    let leaf = diff
        .node(leaf_reference)
        .expect("error dereferencing valid node reference");

    assert_eq!(leaf, &4);

    assert_eq!(diff.tree_size(), 3);
    assert_eq!(diff.leaf_count(), 2);

    let root_ref = diff.root();

    let root = diff.node(root_ref).expect("error dereferencing root ref");
    assert_eq!(root, &0);

    // Now, root should not be a leaf.
    assert!(!diff.is_leaf(root_ref));
    assert_eq!(diff.leaf_index(root_ref), None);

    // Diff merging
    let staged_diff = diff.into();
    tree.merge_diff(staged_diff).expect("error merging diff");

    let new_tree =
        MlsBinaryTree::new(vec![2, 0, 4]).expect("Error when creating a one-node binary tree.");

    assert_eq!(new_tree, tree);
}

#[test]
fn test_diff_merging() {
    let mut tree = MlsBinaryTree::new(vec![2, 0, 4]).expect("Error creating tree.");
    let original_tree = tree.clone();

    let mut diff = tree.empty_diff().expect("error creating empty diff");

    // Merging larger diffs.

    // Add a lot of leaves.
    for index in 0..1000 {
        diff.add_leaf(index, index)
            .expect("error while adding large number of leaves");
    }

    // Check that the leaves were actually added.
    let leaves = diff
        .leaves()
        .expect("error compiling vector of leaf references.");

    let first_leaf = leaves.first().expect("leaf vector is empty");
    let last_leaf = leaves.last().expect("leaf vector is empty");
    assert_eq!(diff.node(*first_leaf).expect("error dereferencing"), &2);
    assert_eq!(diff.node(*last_leaf).expect("error dereferencing"), &999);
    assert_eq!(leaves.len(), diff.leaf_count() as usize);

    // Remove some of them again
    for _ in 0..200 {
        diff.remove_leaf()
            .expect("error while removing large number of leaves");
    }

    // Check that the leaves were actually removed.
    let leaves = diff
        .leaves()
        .expect("error compiling vector of leaf references.");

    let first_leaf = leaves.first().expect("leaf vector is empty");
    let last_leaf = leaves.last().expect("leaf vector is empty");
    assert_eq!(diff.node(*first_leaf).expect("error dereferencing"), &2);
    assert_eq!(diff.node(*last_leaf).expect("error dereferencing"), &799);
    assert_eq!(leaves.len(), diff.leaf_count() as usize);

    let staged_diff = diff.into();
    tree.merge_diff(staged_diff)
        .expect("error when merging large diff");

    // Verify that the tree has changed post-merge.
    let leaves = tree
        .leaves()
        .expect("error compiling vector of leaf references.");

    let first_leaf = leaves.first().expect("leaf vector is empty");
    let last_leaf = leaves.last().expect("leaf vector is empty");
    assert_eq!(*first_leaf, &2);
    assert_eq!(*last_leaf, &799);

    // Merging a diff that decreases the size of the tree.

    let mut diff = tree.empty_diff().expect("error creating empty diff");
    for _ in 0..800 {
        diff.remove_leaf()
            .expect("error while removing large number of leaves");
    }

    let staged_diff = diff.into();
    tree.merge_diff(staged_diff)
        .expect("error when merging large diff");

    assert_eq!(tree, original_tree);
}

#[test]
fn test_leaf_addition_and_removal_errors() {
    let tree = MlsBinaryTree::new((0..3).collect()).expect("error creating tree");
    let mut diff = tree.empty_diff().expect("error creating empty diff");

    diff.remove_leaf().expect("error removing leaf");

    // Should fail removing the last remaining leaf.
    assert_eq!(
        diff.remove_leaf()
            .expect_err("no error trying to remove the last leaf in the diff"),
        MlsBinaryTreeDiffError::TreeTooSmall
    );

    // Let's test what happens when the tree is getting too large.
    let mut nodes: Vec<u32> = Vec::new();

    // We allow uninitialized vectors because we don't want to allocate so much memory
    #[allow(clippy::uninit_vec)]
    unsafe {
        nodes.set_len(NodeIndex::MAX as usize);

        let tree = MlsBinaryTree::new(nodes).expect("error creating tree");
        let mut diff = tree.empty_diff().expect("error creating empty diff");

        assert_eq!(
            diff.add_leaf(666, 667)
                .expect_err("no error adding beyond u32 max"),
            MlsBinaryTreeDiffError::TreeTooLarge
        )
    }
}

#[test]
fn test_tree_navigation() {
    let tree = MlsBinaryTree::new((0..3).collect()).expect("error creating tree");

    let diff = tree.empty_diff().expect("error creating empty diff");

    // Create a root reference and navigate around a little bit.
    let root_ref = diff.root();

    let left_child = diff
        .left_child(root_ref)
        .expect("error finding left child of node");

    assert_eq!(diff.node(left_child).expect("error dereferencing"), &0);

    let right_child = diff
        .right_child(root_ref)
        .expect("error finding right child of node");

    assert_eq!(diff.node(right_child).expect("error dereferencing"), &2);

    let right_child_sibling = diff
        .sibling(right_child)
        .expect("failed to navigate to sibling of right child");
    assert_eq!(
        diff.node(right_child_sibling).expect("error dereferencing"),
        diff.node(left_child).expect("error dereferencing")
    );

    // Error cases

    assert_eq!(
        diff.left_child(right_child)
            .expect_err("successfully navigated to child of leaf node"),
        MlsBinaryTreeDiffError::TreeError(TreeMathError::LeafHasNoChildren)
    );

    assert_eq!(
        diff.right_child(right_child)
            .expect_err("successfully navigated to child of leaf node"),
        MlsBinaryTreeDiffError::TreeError(TreeMathError::LeafHasNoChildren)
    );

    assert_eq!(
        diff.sibling(root_ref)
            .expect_err("successfully navigated to sibling of root node"),
        MlsBinaryTreeDiffError::TreeError(TreeMathError::RootHasNoParent)
    );
}

#[test]
fn test_direct_path_manipulation() {
    let small_tree = MlsBinaryTree::new(vec![0]).expect("error creating tree");

    // Getting the direct path.
    let mut st_diff = small_tree.empty_diff().expect("error creating empty diff");
    let direct_path = st_diff
        .direct_path(0)
        .expect("error computing direct path for small tree.");
    // Direct path should be empty for 1-node trees.
    assert_eq!(direct_path.len(), 0);

    assert_eq!(
        st_diff.direct_path(1).expect_err(
            "should not be able to compute direct path with leaf index outside of tree."
        ),
        OutOfBoundsError::IndexOutOfBounds
    );

    // Setting the direct path to one node.
    st_diff
        .set_direct_path_to_node(0, &1)
        .expect("error setting direct path in small tree.");
    // Nothing should have changed.
    assert_eq!(st_diff.tree_size(), 1);
    assert_eq!(
        st_diff
            .node(st_diff.leaf(0).expect("error getting leaf reference"))
            .expect("error dereferencing"),
        &0
    );

    // Setting the direct path to a given path.
    st_diff
        .set_direct_path(0, vec![])
        .expect("error setting direct path in small tree.");
    // Nothing should have changed.
    assert_eq!(st_diff.tree_size(), 1);
    assert_eq!(
        st_diff
            .node(st_diff.leaf(0).expect("error getting leaf reference"))
            .expect("error dereferencing"),
        &0
    );

    // Medium tree
    let medium_tree = MlsBinaryTree::new((0..3).collect()).expect("error creating tree");

    // Getting the direct path.
    let mut mt_diff = medium_tree.empty_diff().expect("error creating empty diff");
    let direct_path = mt_diff
        .direct_path(1)
        .expect("error computing direct path for medium tree.");

    let direct_path_nodes = mt_diff
        .deref_vec(direct_path.clone())
        .expect("error dereferencing direct path nodes.");

    assert_eq!(direct_path_nodes, vec![&1]);

    // Setting the direct path to one node.
    mt_diff
        .set_direct_path_to_node(0, &999)
        .expect("error setting direct path in medium tree.");
    let direct_path_nodes = mt_diff
        .deref_vec(direct_path.clone())
        .expect("error dereferencing direct path nodes.");
    assert_eq!(direct_path_nodes, vec![&999]);

    // Setting the direct path to a given path.
    mt_diff
        .set_direct_path(0, vec![888])
        .expect("error setting direct path in medium tree.");
    let direct_path_nodes = mt_diff
        .deref_vec(direct_path)
        .expect("error dereferencing direct path nodes.");
    assert_eq!(direct_path_nodes, vec![&888]);

    // Large tree
    let mut large_tree = MlsBinaryTree::new((0..101).collect()).expect("error creating tree");

    // Getting the direct path.
    let mut lt_diff = large_tree.empty_diff().expect("error creating empty diff");
    let direct_path = lt_diff
        .direct_path(42)
        .expect("error computing direct path for large tree.");

    let direct_path_nodes = lt_diff
        .deref_vec(direct_path.clone())
        .expect("error dereferencing direct path nodes.");

    assert_eq!(direct_path_nodes, vec![&85, &83, &87, &79, &95, &63]);

    // Setting the direct path to one node.
    lt_diff
        .set_direct_path_to_node(42, &999)
        .expect("error setting direct path in large tree.");
    let direct_path_nodes = lt_diff
        .deref_vec(direct_path.clone())
        .expect("error dereferencing direct path nodes.");
    assert_eq!(direct_path_nodes, vec![&999; 6]);

    // Setting the direct path to a given path.
    lt_diff
        .set_direct_path(42, vec![888, 887, 886, 885, 884, 883])
        .expect("error setting direct path in large tree.");
    let direct_path_nodes = lt_diff
        .deref_vec(direct_path)
        .expect("error dereferencing direct path nodes.");
    assert_eq!(direct_path_nodes, vec![&888, &887, &886, &885, &884, &883]);

    // The path of the left-most node should only have changed in the root.
    let direct_path = lt_diff
        .direct_path(0)
        .expect("error computing direct path for large tree.");
    let direct_path_nodes = lt_diff
        .deref_vec(direct_path)
        .expect("error dereferencing direct path nodes.");
    println!("direct path nodes: {:?}", direct_path_nodes);
    assert_eq!(direct_path_nodes, vec![&1, &3, &7, &15, &31, &883]);

    // Error cases

    // Setting the direct path of a node outside of the tree.
    let error = lt_diff
        .set_direct_path_to_node(51, &999)
        .expect_err("no error setting direct path outside of tree.");
    assert_eq!(
        error,
        MlsBinaryTreeDiffError::TreeError(TreeMathError::NodeNotInTree)
    );

    let error = lt_diff
        .set_direct_path(100, vec![888, 887, 886, 885, 884, 883])
        .expect_err("no error setting direct path outside of tree.");
    assert_eq!(
        error,
        MlsBinaryTreeDiffError::TreeError(TreeMathError::NodeNotInTree)
    );

    // Setting a direct path with wrong length
    let error = lt_diff
        .set_direct_path(49, vec![888, 887, 886, 885, 884, 883, 0])
        .expect_err("no error setting direct path outside of tree.");
    assert_eq!(error, MlsBinaryTreeDiffError::PathLengthMismatch);

    let error = lt_diff
        .set_direct_path(0, vec![666, 999])
        .expect_err("no error setting direct path outside of tree.");
    assert_eq!(error, MlsBinaryTreeDiffError::PathLengthMismatch);

    // Merging and creating a new, empty diff to ensure that the changes persist
    // on merge.
    let staged_diff = lt_diff.into();
    large_tree
        .merge_diff(staged_diff)
        .expect("error merging diff");
    let empty_diff = large_tree.empty_diff().expect("error creating empty diff");
    let direct_path = empty_diff
        .direct_path(0)
        .expect("error computing direct path for large tree.");
    let direct_path_nodes = empty_diff
        .deref_vec(direct_path)
        .expect("error dereferencing direct path nodes.");
    println!("direct path nodes: {:?}", direct_path_nodes);
    assert_eq!(direct_path_nodes, vec![&1, &3, &7, &15, &31, &883]);
}

#[test]
fn test_subtree_root_position() {
    // Computing with a 1-node tree will always lead to a SameLeafError. See below.

    // Small tree
    let small_tree = MlsBinaryTree::new((0..3).collect()).expect("error creating tree");
    let diff = small_tree.empty_diff().expect("error creating empty diff");

    // If the given leaf indices are identical, the shared subtree root is
    // the index itself. Since the index of the leaf itself doesn't appear
    // in the direct path, we can't return anything meaningful.
    let error = diff
        .subtree_root_position(0, 0)
        .expect_err("no error when computing subtree root position of identical indices");
    assert_eq!(error, MlsBinaryTreeDiffError::SameLeafError);

    // Since the tree is small, the subtree root is on position 0.
    let subtree_root_position = diff
        .subtree_root_position(0, 1)
        .expect("error computing subtree root");
    assert_eq!(subtree_root_position, 0);

    // Computing with one of the indices out of bounds.
    let error = diff
        .subtree_root_position(3, 0)
        .expect_err("no error when computing subtree root position outside of tree");
    assert_eq!(
        error,
        MlsBinaryTreeDiffError::IndexOutOfBounds(OutOfBoundsError::IndexOutOfBounds)
    );

    // Larger tree
    let tree = MlsBinaryTree::new((0..101).collect()).expect("error creating tree");

    let diff = tree.empty_diff().expect("error creating empty diff");

    // Subtree root position of leaves in the left and right half of the tree is
    // the last node in the direct path.
    let subtree_root_position = diff
        .subtree_root_position(0, 49)
        .expect("error computing subtree root");
    let direct_path = diff.direct_path(0).expect("error computing direct path");
    assert_eq!(subtree_root_position, direct_path.len() - 1);

    // Subtree root position of leaves in the same half of the tree.
    let subtree_root_position = diff
        .subtree_root_position(0, 10)
        .expect("error computing subtree root");
    assert_eq!(subtree_root_position, 3);

    let subtree_root_position = diff
        .subtree_root_position(24, 42)
        .expect("error computing subtree root");
    assert_eq!(subtree_root_position, 5);
}

#[test]
fn test_subtree_root_copath_node() {
    // The tree needs to have at least two leaves, as the function will error
    // out if the given leaf indices are identical. (Tested below.)

    // Small tree
    let small_tree = MlsBinaryTree::new((0..3).collect()).expect("error creating tree");
    let diff = small_tree.empty_diff().expect("error creating empty diff");

    // If the given leaf indices are identical, the function should return an error.
    let error = diff
        .subtree_root_copath_node(0, 0)
        .expect_err("no error when computing subtree root copath node of identical indices");
    assert_eq!(error, MlsBinaryTreeDiffError::SameLeafError);

    // Since the tree is small, the subtree root copath node is the same as the
    // second leaf index.
    let subtree_root_copath_node = diff
        .subtree_root_copath_node(0, 1)
        .expect("error computing subtree root");
    assert_eq!(
        diff.node(subtree_root_copath_node)
            .expect("error dereferencing"),
        &2
    );

    // Computing with one of the indices out of bounds.
    let error = diff
        .subtree_root_copath_node(3, 0)
        .expect_err("no error when computing subtree root position outside of tree");
    assert_eq!(
        error,
        MlsBinaryTreeDiffError::IndexOutOfBounds(OutOfBoundsError::IndexOutOfBounds)
    );

    // Larger tree
    let tree = MlsBinaryTree::new((0..101).collect()).expect("error creating tree");

    let diff = tree.empty_diff().expect("error creating empty diff");

    // Subtree root copath node of leaves in the left and right half of the tree is
    // the second to last node in the direct path of the second index.
    let subtree_root_copath_node_ref = diff
        .subtree_root_copath_node(0, 49)
        .expect("error computing subtree root");
    let subtree_root_copath_node = diff
        .node(subtree_root_copath_node_ref)
        .expect("error dereferencing");
    let direct_path = diff.direct_path(49).expect("error computing direct path");
    let direct_path_node = diff
        .node(direct_path[direct_path.len() - 2])
        .expect("error dereferencing");
    assert_eq!(subtree_root_copath_node, direct_path_node);

    // Subtree root position of leaves in the same half of the tree.
    let subtree_root_copath_node_ref = diff
        .subtree_root_copath_node(0, 10)
        .expect("error computing subtree root");
    let subtree_root_copath_node = diff
        .node(subtree_root_copath_node_ref)
        .expect("error dereferencing");
    assert_eq!(subtree_root_copath_node, &23);

    let subtree_root_copath_node_ref = diff
        .subtree_root_copath_node(42, 34)
        .expect("error computing subtree root");
    let subtree_root_copath_node = diff
        .node(subtree_root_copath_node_ref)
        .expect("error dereferencing");
    assert_eq!(subtree_root_copath_node, &71);
}

#[test]
fn test_subtree_path() {
    // This should work on a one-node tree.
    let tree = MlsBinaryTree::new(vec![0]).expect("error creating tree");
    let diff = tree.empty_diff().expect("error creating empty diff");

    // Since in contrast to the direct path, the subtree path contains the
    // shared subtree root itself, the subtree path of the only node should be
    // that node.
    let subtree_path = diff
        .subtree_path(0, 0)
        .expect("error computing subtree path");
    let node = diff
        .node(*subtree_path.first().expect("An unexpected error occurred."))
        .expect("error dereferencing");
    assert_eq!(node, &0);

    // Small tree
    let small_tree = MlsBinaryTree::new((0..3).collect()).expect("error creating tree");
    let diff = small_tree.empty_diff().expect("error creating empty diff");

    // Since the tree is small, the subtree path of the two leaves should
    // consist of only the root.
    let subtree_path = diff
        .subtree_path(0, 1)
        .expect("error computing subtree path");
    assert_eq!(
        diff.node(*subtree_path.first().expect("An unexpected error occurred."))
            .expect("error dereferencing"),
        &1
    );

    // Computing with one of the indices out of bounds.
    let error = diff
        .subtree_path(0, 3)
        .expect_err("no error when computing subtree root position outside of tree");
    assert_eq!(
        error,
        MlsBinaryTreeDiffError::IndexOutOfBounds(OutOfBoundsError::IndexOutOfBounds)
    );

    // Larger tree
    let tree = MlsBinaryTree::new((0..101).collect()).expect("error creating tree");

    let diff = tree.empty_diff().expect("error creating empty diff");

    // Subtree path of leaves in the left and right half of the tree is the root node.
    let subtree_path = diff
        .subtree_path(0, 49)
        .expect("error computing subtree path");
    assert_eq!(
        diff.node(*subtree_path.first().expect("An unexpected error occurred."))
            .expect("error dereferencing"),
        diff.node(diff.root()).expect("error dereferencing")
    );

    // Subtree root position of leaves in the same half of the tree.
    let subtree_path = diff
        .subtree_path(0, 10)
        .expect("error computing subtree root");
    assert_eq!(
        diff.deref_vec(subtree_path).expect("error dereferencing"),
        vec![&15, &31, &63]
    );

    let subtree_path = diff
        .subtree_path(34, 42)
        .expect("error computing subtree root");
    assert_eq!(
        diff.deref_vec(subtree_path).expect("error dereferencing"),
        vec![&79, &95, &63]
    );
}

#[test]
fn test_diff_iter() {
    let tree = MlsBinaryTree::new((0..101).collect()).expect("error creating tree");

    let diff = tree.empty_diff().expect("error creating empty diff");

    let mut node_set = HashSet::new();

    for node_ref in diff.iter() {
        let node = diff.node(node_ref).expect("error dereferencing");
        node_set.insert(node);
    }

    for i in 0..101 {
        assert!(node_set.contains(&i));
    }
}

#[test]
fn test_export_diff_nodes() {
    let tree = MlsBinaryTree::new((0..101).collect()).expect("error creating tree");

    let diff = tree.empty_diff().expect("error creating empty diff");

    let nodes = diff
        .export_nodes()
        .expect("error exporting nodes from diff");

    // If we re-export the nodes into a tree, we should end up with the same tree.
    let new_tree = MlsBinaryTree::new(nodes).expect("error creating tree from exported nodes");

    assert_eq!(tree, new_tree);
}

#[test]
fn test_diff_mutable_access_after_manipulation() {
    let tree = MlsBinaryTree::new((0..101).collect()).expect("error creating tree");

    let mut diff = tree.empty_diff().expect("error creating empty diff");

    // Let's change the nodes along a direct path.
    diff.set_direct_path_to_node(5, &999)
        .expect("error setting direct path nodes");

    // Now let's get references to a neighbour's path, where some nodes were
    // changed and some weren't.
    let direct_path_refs = diff
        .direct_path(6)
        .expect("error getting direct path references");
    for node_ref in &direct_path_refs {
        let node_mut = diff
            .node_mut(*node_ref)
            .expect("error dereferencing mutably");
        *node_mut = 888;
    }

    let direct_path = diff
        .deref_vec(direct_path_refs)
        .expect("error dereferencing direct path nodes");
    assert_eq!(direct_path, vec![&888, &888, &888, &888, &888, &888])
}
