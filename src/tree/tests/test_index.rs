use crate::tree::*;

/// Test whether a NodeIndex is a leaf or a parent
#[test]
fn test_leaf_parent() {
    // Index 1 should be a parent node
    let index = NodeIndex::from(1usize);
    assert!(!index.is_leaf());
    assert!(index.is_parent());

    // Index 2 should be a parent node
    let index = NodeIndex::from(2usize);
    assert!(index.is_leaf());
    assert!(!index.is_parent());
}
