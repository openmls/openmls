use crate::{
    ciphersuite::{HpkePrivateKey, HpkePublicKey},
    treesync::ParentNode,
};

use tls_codec::{Deserialize, Serialize};

// Verifies that when we add an unmerged leaf to a parent node, the list of
// unmerged leaves remains sorted.
#[test]
fn test_insert_unmerged_leaf() {
    let public_key: HpkePublicKey = Vec::new().into();
    let private_key: HpkePrivateKey = Vec::new().into();
    let mut parent_node = ParentNode::from((public_key, private_key));

    // Add leaves in random order
    parent_node.add_unmerged_leaf(9);
    parent_node.add_unmerged_leaf(5);
    parent_node.add_unmerged_leaf(7);
    parent_node.add_unmerged_leaf(1);
    parent_node.add_unmerged_leaf(3);

    // Expect a sorted list
    assert_eq!(parent_node.unmerged_leaves(), &[1, 3, 5, 7, 9]);
}

// Verify that we cannot successfully deserialize a ParentNode that has an unsorted list of unmerged leaves.
#[test]
fn test_deserialize_unsorted_unmerged_leaves() {
    let public_key: HpkePublicKey = Vec::new().into();
    let private_key: HpkePrivateKey = Vec::new().into();
    let mut parent_node = ParentNode::from((public_key, private_key));

    // Add leaves in random order
    parent_node.set_unmerged_leaves(vec![9, 5, 7, 1, 3]);

    // Serialize the parent node
    let serialized_parent_node = (&parent_node).tls_serialize_detached().unwrap();

    // Deserialize the parent node
    let err = ParentNode::tls_deserialize(&mut serialized_parent_node.as_slice()).unwrap_err();

    // We expect a decoding error
    assert!(matches!(err, tls_codec::Error::DecodingError(_)));
}

// Verify that we can successfully deserialize a ParentNode that has a sorted list of unmerged leaves.
#[test]
fn test_deserialize_sorted_unmerged_leaves() {
    let public_key: HpkePublicKey = Vec::new().into();
    let private_key: HpkePrivateKey = Vec::new().into();
    let mut parent_node = ParentNode::from((public_key, private_key));

    // Add leaves in random order
    parent_node.set_unmerged_leaves(vec![1, 3, 5, 7, 9]);

    // Serialize the parent node
    let serialized_parent_node = (&parent_node).tls_serialize_detached().unwrap();

    // Deserialize the parent node
    let deserialized_parent_node =
        ParentNode::tls_deserialize(&mut serialized_parent_node.as_slice()).unwrap();

    // We expect the deserialized parent node to have the same unmerged leaves as the original one
    assert_eq!(deserialized_parent_node.unmerged_leaves(), &[1, 3, 5, 7, 9]);
}
