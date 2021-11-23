use crate::binary_tree::{MlsBinaryTree, MlsBinaryTreeDiffError, MlsBinaryTreeError};

use super::array_representation::tree::NodeIndex;

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

    // Leaf replacement and node references..
    let mut diff = tree.empty_diff();
    diff.replace_leaf(0, 1).expect("error replacing leaf");

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
    let staged_diff = diff.into();
    tree.merge_diff(staged_diff)
        .expect("error when merging large diff");
}

//#[test]
//fn test_node_defaulting() {
//    let mut tree = MlsBinaryTree::new(&[1, 2, 3]).expect("Error when creating a tree.");
//    assert_eq!(
//        tree.make_default(&1)
//            .expect("error when making node default"),
//        1
//    );
//    assert_eq!(
//        tree,
//        MlsBinaryTree::new(&[0, 2, 3]).expect("Error when creating tree from nodes.")
//    );
//}
//
//#[test]
//fn test_node_removal() {
//    // Test node removal: Positive case.
//    let mut tree = MlsBinaryTree::new(&[0, 1, 2]).expect("Error when creating a tree.");
//    tree.remove()
//        .expect("error when adding nodes to small enough tree");
//    assert_eq!(
//        tree,
//        MlsBinaryTree::new(&[0]).expect("Error when creating tree from nodes.")
//    );
//
//    // Test node removal: Too few nodes.
//    let nodes = vec![0];
//    let mut tree = MlsBinaryTree::new(&nodes).expect("Error while creating tree.");
//
//    assert_eq!(
//        tree.remove()
//            .expect_err("No error when trying to remove nodes from too small tree."),
//        MlsBinaryTreeError::NotEnoughNodes
//    )
//}
//
//#[test]
//fn test_node_access() {
//    // Test node access: Positive case.
//    let tree = MlsBinaryTree::new(&[0, 1, 2]).expect("Error when creating a tree.");
//    assert_eq!(tree.node(&1).expect("Error when accessing node."), &1);
//
//    // Test node access: Not in the tree.
//    assert_eq!(tree.node(&3), None);
//
//    // Test node replacement: Positive case.
//    let mut tree = MlsBinaryTree::new(&[0, 1, 2]).expect("Error when creating a tree.");
//    tree.replace(&1, 5)
//        .expect("Error when trying to replace node.");
//    assert_eq!(tree.node(&5).expect("Error when accessing node."), &5);
//    assert_eq!(
//        tree,
//        MlsBinaryTree::new(&[0, 5, 2]).expect("Error when creating tree from nodes.")
//    );
//
//    assert_eq!(
//        tree.replace(&1, 5)
//            .expect_err("No error when trying to replace non-existing node."),
//        MlsBinaryTreeError::NodeNotFound
//    );
//}
//
//#[test]
//fn test_direct_path() {
//    let mut tree =
//        MlsBinaryTree::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8]).expect("Error when creating a tree.");
//
//    // Test direct path: Out of bounds.
//    assert_eq!(
//        tree.direct_path(&10)
//            .expect_err("No error when computing direct path out of bounds."),
//        MlsBinaryTreeError::NodeNotFound
//    );
//
//    // Test direct path: Positive case.
//    let direct_path = tree
//        .direct_path(&0)
//        .expect("Error when computing direct path.");
//    let test_vec = vec![1, 3, 7];
//    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
//    assert_eq!(direct_path, test_vec_ref);
//
//    let direct_path = tree
//        .direct_path(&6)
//        .expect("Error when computing direct path.");
//    let test_vec = vec![5, 3, 7];
//    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
//    assert_eq!(direct_path, test_vec_ref);
//
//    let direct_path = tree
//        .direct_path(&8)
//        .expect("Error when computing direct path.");
//    let test_vec = vec![7];
//    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
//    assert_eq!(direct_path, test_vec_ref);
//
//    let direct_path = tree
//        .direct_path(&7)
//        .expect("Error when computing direct path.");
//    assert_eq!(direct_path, Vec::<&u32>::new());
//
//    tree.add_leaf(10).expect("error when adding nodes");
//
//    let direct_path = tree
//        .direct_path(&8)
//        .expect("Error when computing direct path.");
//    let test_vec = vec![0, 7];
//    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
//    assert_eq!(direct_path, test_vec_ref);
//
//    // Test for a very small tree.
//    let tree = MlsBinaryTree::new(&[1]).expect("Error when creating a tree.");
//
//    let direct_path = tree
//        .direct_path(&1)
//        .expect("Error when computing direct path.");
//    assert_eq!(direct_path, Vec::<&u32>::new());
//}
//
//#[test]
//fn test_copath() {
//    let tree =
//        MlsBinaryTree::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8]).expect("Error when creating a tree.");
//
//    // Test copath: Out of bounds.
//    assert_eq!(
//        tree.copath(&10)
//            .expect_err("No error when computing copath out of bounds."),
//        MlsBinaryTreeError::NodeNotFound
//    );
//
//    // Test direct path: Positive case.
//    let copath = tree.copath(&0).expect("Error when computing copath.");
//    let test_vec = vec![2, 5, 8];
//    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
//    assert_eq!(copath, test_vec_ref);
//
//    let copath = tree.copath(&6).expect("Error when computing copath.");
//    let test_vec = vec![4, 1, 8];
//    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
//    assert_eq!(copath, test_vec_ref);
//
//    let copath = tree.copath(&8).expect("Error when computing copath.");
//    let test_vec = vec![3];
//    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
//    assert_eq!(copath, test_vec_ref);
//
//    let copath = tree.copath(&7).expect("Error when computing copath.");
//    assert_eq!(copath, Vec::<&u32>::new());
//
//    let mut tree = tree.clone();
//    tree.add_leaf(10).expect("error when adding nodes");
//
//    let copath = tree.copath(&8).expect("Error when computing copath.");
//    let test_vec = vec![10, 3];
//    let test_vec_ref: Vec<&u32> = test_vec.iter().map(|node| node).collect();
//    assert_eq!(copath, test_vec_ref);
//
//    // Test for a very small tree.
//    let tree = MlsBinaryTree::new(&[1]).expect("Error when creating a tree.");
//
//    let copath = tree.copath(&1).expect("Error when computing copath.");
//    assert_eq!(copath, Vec::<&u32>::new());
//}
//
//#[test]
//fn test_lowest_common_ancestor() {
//    let mut tree =
//        MlsBinaryTree::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8]).expect("Error when creating a tree.");
//
//    // Test lowest common ancestor: Node not found.
//    assert_eq!(
//        tree.lowest_common_ancestor(&10, &0)
//            .expect_err("No error when computing lowest common ancestor out of bounds."),
//        MlsBinaryTreeError::NodeNotFound
//    );
//    assert_eq!(
//        tree.lowest_common_ancestor(&0, &10)
//            .expect_err("No error when computing lowest common ancestor out of bounds."),
//        MlsBinaryTreeError::NodeNotFound
//    );
//
//    // Test direct path: Positive case.
//    let lowest_common_ancestor = tree
//        .lowest_common_ancestor(&0, &2)
//        .expect("Error when computing lowest common ancestor.");
//    assert_eq!(lowest_common_ancestor, &1u32);
//
//    let lowest_common_ancestor = tree
//        .lowest_common_ancestor(&0, &1)
//        .expect("Error when computing lowest common ancestor.");
//    assert_eq!(lowest_common_ancestor, &1u32);
//
//    let lowest_common_ancestor = tree
//        .lowest_common_ancestor(&8, &4)
//        .expect("Error when computing lowest common ancestor.");
//    assert_eq!(lowest_common_ancestor, &7u32);
//
//    let lowest_common_ancestor = tree
//        .lowest_common_ancestor(&4, &1)
//        .expect("Error when computing lowest common ancestor.");
//    assert_eq!(lowest_common_ancestor, &3u32);
//
//    tree.add_leaf(10).expect("error when adding nodes");
//
//    let lowest_common_ancestor = tree
//        .lowest_common_ancestor(&10, &4)
//        .expect("Error when computing lowest common ancestor.");
//    assert_eq!(lowest_common_ancestor, &7u32);
//
//    // Test for a very small tree.
//    let tree = MlsBinaryTree::new(&[1]).expect("Error when creating a tree.");
//
//    let lowest_common_ancestor = tree
//        .lowest_common_ancestor(&1, &1)
//        .expect("Error when computing lowest common ancestor.");
//    assert_eq!(lowest_common_ancestor, &1u32);
//}
