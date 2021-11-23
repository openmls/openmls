use core::panic;

use crate::binary_tree::{MlsBinaryTree, MlsBinaryTreeDiffError, MlsBinaryTreeError};

use super::array_representation::tree::NodeIndex;

use super::array_representation::treemath::TreeMathError;

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
    assert_eq!(tree1.size(), 3);
    assert_eq!(tree1.leaf_count(), 2);

    // Test tree creation: Too many nodes.
    let len = NodeIndex::max_value() as usize + 2;
    let mut nodes: Vec<u32> = Vec::new();

    unsafe {
        nodes.set_len(len);

        assert_eq!(
            MlsBinaryTree::new(nodes).expect_err("No error while creating too large tree."),
            MlsBinaryTreeError::OutOfRange
        )
    }

    // Test node export
    let exported_nodes = tree1.export_nodes();
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
    assert_eq!(None, tree1.node_by_index(3));
    assert_eq!(None, tree1.node_by_index(10));

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
fn test_basic_diff_mechanics() {
    // Test empty diff.
    let mut tree =
        MlsBinaryTree::new(vec![0]).expect("Error when creating a one-node binary tree.");
    let original_tree = tree.clone();

    let diff = tree.empty_diff();
    let staged_diff = diff.into();
    tree.merge_diff(staged_diff)
        .expect("error while merging empty diff.");

    assert_eq!(tree, original_tree);

    // Node access and node references
    let diff = tree.empty_diff();
    let leaf_reference = diff.leaf(0).expect("error obtaining leaf reference.");

    assert_eq!(
        diff.leaf(1)
            .expect_err("no error when accessing leaf outside of tree"),
        MlsBinaryTreeDiffError::OutOfBounds
    );

    let leaf_index = diff
        .leaf_index(leaf_reference)
        .expect("leaf reference without a leaf index.");

    assert_eq!(leaf_index, 0);
    assert_eq!(diff.is_leaf(leaf_reference), true);

    let leaf = diff
        .try_deref(leaf_reference)
        .expect("error dereferencing valid node reference");

    assert_eq!(leaf, &0);

    // Leaf replacement and node references.
    let mut diff = tree.empty_diff();
    diff.replace_leaf(0, 1).expect("error replacing leaf");

    assert_eq!(
        diff.replace_leaf(1, 1).expect_err("error replacing leaf"),
        MlsBinaryTreeDiffError::OutOfBounds
    );

    let leaf_reference = diff.leaf(0).expect("error obtaining leaf reference.");

    let leaf_mut = diff
        .try_deref_mut(leaf_reference)
        .expect("error dereferencing valid node reference");

    assert_eq!(leaf_mut, &1);

    *leaf_mut = 2;

    let leaf_reference = diff.leaf(0).expect("error obtaining leaf reference.");

    let leaf = diff
        .try_deref(leaf_reference)
        .expect("error dereferencing valid node reference");

    assert_eq!(leaf, &2);

    // Diff size
    assert_eq!(diff.size(), 1);
    assert_eq!(diff.leaf_count(), 1);

    // root
    let root_ref = diff.root();

    let root = diff
        .try_deref(root_ref)
        .expect("error dereferencing root ref");
    assert_eq!(root, &2);

    // Leaf addition.
    let new_leaf_index = diff.add_leaf(0, 4).expect("error adding leaf");

    assert_eq!(new_leaf_index, 1);

    let leaf_reference = diff.leaf(1).expect("error obtaining leaf reference.");

    let leaf = diff
        .try_deref(leaf_reference)
        .expect("error dereferencing valid node reference");

    assert_eq!(leaf, &4);

    assert_eq!(diff.size(), 3);
    assert_eq!(diff.leaf_count(), 2);

    let root_ref = diff.root();

    let root = diff
        .try_deref(root_ref)
        .expect("error dereferencing root ref");
    assert_eq!(root, &0);

    // Now, root should not be a leaf.
    assert_eq!(diff.is_leaf(root_ref), false);
    assert_eq!(diff.leaf_index(root_ref), None);

    // Diff merging
    let staged_diff = diff.into();
    tree.merge_diff(staged_diff).expect("error merging diff");

    let new_tree =
        MlsBinaryTree::new(vec![2, 0, 4]).expect("Error when creating a one-node binary tree.");

    assert_eq!(new_tree, tree);

    let mut diff = tree.empty_diff();
    // Diff merging with more nodes.
    for index in 0..1000 {
        diff.add_leaf(index, index)
            .expect("error while adding large number of leaves");
    }

    let leaves = diff
        .leaves()
        .expect("error compiling vector of leaf references.");

    let first_leaf = leaves.first().expect("leaf vector is empty");
    let last_leaf = leaves.last().expect("leaf vector is empty");
    assert_eq!(
        diff.try_deref(*first_leaf).expect("error dereferencing"),
        &2
    );
    assert_eq!(
        diff.try_deref(*last_leaf).expect("error dereferencing"),
        &999
    );
    assert_eq!(leaves.len(), diff.leaf_count() as usize);

    let staged_diff = diff.into();
    tree.merge_diff(staged_diff)
        .expect("error when merging large diff");
}

#[test]
fn test_tree_navigation() {
    let tree = MlsBinaryTree::new((0..3).collect()).expect("error creating tree");

    let diff = tree.empty_diff();
    let root_ref = diff.root();

    let left_child = diff
        .left_child(root_ref)
        .expect("error finding left child of node");

    assert_eq!(diff.try_deref(left_child).expect("error dereferencing"), &0);

    let right_child = diff
        .right_child(root_ref)
        .expect("error finding right child of node");

    assert_eq!(
        diff.try_deref(right_child).expect("error dereferencing"),
        &2
    );

    let right_child_sibling = diff
        .sibling(right_child)
        .expect("failed to navigate to sibling of right child");
    assert_eq!(
        diff.try_deref(right_child_sibling)
            .expect("error dereferencing"),
        diff.try_deref(left_child).expect("error dereferencing")
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
    let mut st_diff = small_tree.empty_diff();
    let direct_path = st_diff
        .direct_path(0)
        .expect("error computing direct path for small tree.");
    // Direct path should be empty for 1-node trees.
    assert_eq!(direct_path.len(), 0);

    assert_eq!(
        st_diff.direct_path(1).expect_err(
            "should not be able to compute direct path with leaf index outside of tree."
        ),
        MlsBinaryTreeDiffError::ABinaryTreeError(MlsBinaryTreeError::OutOfBounds)
    );

    // Setting the direct path to one node.
    st_diff
        .set_direct_path_to_node(0, &1)
        .expect("error setting direct path in small tree.");
    // Nothing should have changed.
    assert_eq!(st_diff.size(), 1);
    assert_eq!(
        st_diff
            .try_deref(st_diff.leaf(0).expect("error getting leaf reference"))
            .expect("error dereferencing"),
        &0
    );

    // Setting the direct path to a given path.
    st_diff
        .set_direct_path(0, vec![])
        .expect("error setting direct path in small tree.");
    // Nothing should have changed.
    assert_eq!(st_diff.size(), 1);
    assert_eq!(
        st_diff
            .try_deref(st_diff.leaf(0).expect("error getting leaf reference"))
            .expect("error dereferencing"),
        &0
    );

    // Medium tree
    let medium_tree = MlsBinaryTree::new((0..3).collect()).expect("error creating tree");

    // Getting the direct path.
    let mut mt_diff = medium_tree.empty_diff();
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
    let large_tree = MlsBinaryTree::new((0..101).collect()).expect("error creating tree");

    // Getting the direct path.
    let mut lt_diff = large_tree.empty_diff();
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
}
