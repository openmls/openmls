use crate::{binary_tree::LeafNodeIndex, treesync::node::parent_node::UnmergedLeaves};

use tls_codec::{Deserialize, Serialize};

// Verifies that when we add an unmerged leaf to an UnmergedLeaves struct, the
// list remains sorted.
#[test]
fn test_insert_unmerged_leaf() {
    let mut unmerged_leaves = UnmergedLeaves::new();

    // Add leaves in random order
    unmerged_leaves.add(LeafNodeIndex::new(9));
    unmerged_leaves.add(LeafNodeIndex::new(5));
    unmerged_leaves.add(LeafNodeIndex::new(7));
    unmerged_leaves.add(LeafNodeIndex::new(1));
    unmerged_leaves.add(LeafNodeIndex::new(3));

    // Expect a sorted list
    assert_eq!(
        unmerged_leaves.list(),
        &[
            LeafNodeIndex::new(1),
            LeafNodeIndex::new(3),
            LeafNodeIndex::new(5),
            LeafNodeIndex::new(7),
            LeafNodeIndex::new(9)
        ]
    );
}

// Verify that we cannot successfully deserialize an UnmergedLeaves struct that
// has an unsorted list.
#[test]
fn test_deserialize_unsorted_unmerged_leaves() {
    let mut unmerged_leaves = UnmergedLeaves::new();

    // Add leaves in random order
    unmerged_leaves.set_list(vec![
        LeafNodeIndex::new(9),
        LeafNodeIndex::new(5),
        LeafNodeIndex::new(7),
        LeafNodeIndex::new(1),
        LeafNodeIndex::new(3),
    ]);

    // Serialize the unmerged leaves
    let serialized_unmerged_leaves = unmerged_leaves.tls_serialize_detached().unwrap();

    // Deserialize the unmerged leaves
    let err =
        UnmergedLeaves::tls_deserialize(&mut serialized_unmerged_leaves.as_slice()).unwrap_err();

    // We expect a decoding error
    assert!(matches!(err, tls_codec::Error::DecodingError(_)));
}

// Verify that we can successfully deserialize an UnmergedLeaves struct that has
// a sorted list.
#[test]
fn test_deserialize_sorted_unmerged_leaves() {
    let mut unmerged_leaves = UnmergedLeaves::new();

    // Add leaves in random order
    unmerged_leaves.set_list(vec![
        LeafNodeIndex::new(1),
        LeafNodeIndex::new(3),
        LeafNodeIndex::new(5),
        LeafNodeIndex::new(7),
        LeafNodeIndex::new(9),
    ]);

    // Serialize the unmerged leaves
    let serialized_unmerged_leaves = unmerged_leaves.tls_serialize_detached().unwrap();

    // Deserialize the unmerged leaves
    let deserialized_unmerged_leaves =
        UnmergedLeaves::tls_deserialize(&mut serialized_unmerged_leaves.as_slice()).unwrap();

    // We expect the deserialized unmerged leaves to have the same list as the
    // original one
    assert_eq!(
        deserialized_unmerged_leaves.list(),
        &[
            LeafNodeIndex::new(1),
            LeafNodeIndex::new(3),
            LeafNodeIndex::new(5),
            LeafNodeIndex::new(7),
            LeafNodeIndex::new(9)
        ]
    );
}
