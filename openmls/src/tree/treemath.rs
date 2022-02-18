use crate::tree::index::*;
use thiserror::Error;

/// TreeMath error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum TreeMathError {
    /// Leaf nodes don't have children.
    #[error("Leaf nodes don't have children.")]
    LeafHasNoChildren,
    /// Root nodes don't have parents.
    #[error("Root nodes don't have parents.")]
    RootHasNoParent,
    /// The leaf index is larger than the tree size.
    #[error("The leaf index is larger than the tree size.")]
    LeafNotInTree,
    /// The provided input is invalid for tree math.
    #[error("The provided input is invalid for tree math.")]
    InvalidInput,
}

pub(crate) fn log2(x: usize) -> usize {
    if x == 0 {
        return 0;
    }
    let mut k = 0;
    while (x >> k) > 0 {
        k += 1
    }
    k - 1
}

pub(crate) fn level(index: SecretTreeNodeIndex) -> usize {
    let x = index.as_usize();
    if (x & 0x01) == 0 {
        return 0;
    }
    let mut k = 0;
    while ((x as u64 >> k) & 0x01) == 1 {
        k += 1;
    }
    k
}

pub(crate) fn node_width(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        2 * (n - 1) + 1
    }
}

pub(crate) fn root(size: SecretTreeLeafIndex) -> SecretTreeNodeIndex {
    let n = size.as_usize();
    let w = node_width(n);
    SecretTreeNodeIndex::from((1usize << log2(w)) - 1)
}

pub(crate) fn left(index: SecretTreeNodeIndex) -> Result<SecretTreeNodeIndex, TreeMathError> {
    let x = index.as_usize();
    let k = level(SecretTreeNodeIndex::from(x));
    if k == 0 {
        return Err(TreeMathError::LeafHasNoChildren);
    }
    Ok(SecretTreeNodeIndex::from(x ^ (0x01 << (k - 1))))
}

pub(crate) fn right(
    index: SecretTreeNodeIndex,
    size: SecretTreeLeafIndex,
) -> Result<SecretTreeNodeIndex, TreeMathError> {
    let x = index.as_usize();
    let n = size.as_usize();
    let k = level(SecretTreeNodeIndex::from(x));
    if k == 0 {
        return Err(TreeMathError::LeafHasNoChildren);
    }
    let mut r = x ^ (0x03 << (k - 1));
    while r >= node_width(n) {
        r = left(SecretTreeNodeIndex::from(r))?.as_usize();
    }
    Ok(SecretTreeNodeIndex::from(r))
}

// The parent here might be beyond the right edge of the tree.
pub(crate) fn parent_step(x: usize) -> usize {
    // We need to use u64 for some of the operations where usize is too small on 32bit platforms
    let k = level(SecretTreeNodeIndex::from(x));
    let b = (x as u64 >> (k + 1)) & 0x01;
    let res = (x as u64 | (1 << k)) ^ (b << (k + 1));
    res as usize
}

// This function is only safe to use if index <= size.
// If this is not checked before calling the function, `parent` should be used.
fn try_parent(
    index: SecretTreeNodeIndex,
    size: SecretTreeLeafIndex,
) -> Result<SecretTreeNodeIndex, TreeMathError> {
    let x = index.as_usize();
    let n = size.as_usize();
    if index == root(size) {
        return Err(TreeMathError::RootHasNoParent);
    }
    let mut p = parent_step(x);
    while p >= node_width(n) {
        let new_p = parent_step(p);
        if new_p == p {
            return Err(TreeMathError::InvalidInput);
        }
        p = new_p;
    }
    Ok(SecretTreeNodeIndex::from(p))
}

#[inline(always)]
fn leaf_in_tree(
    leaf_index: SecretTreeLeafIndex,
    size: SecretTreeLeafIndex,
) -> Result<(), TreeMathError> {
    if leaf_index >= size {
        Err(TreeMathError::LeafNotInTree)
    } else {
        Ok(())
    }
}

/// Direct path from a leaf node to the root.
/// Does not include the leaf node but includes the root.
pub(crate) fn leaf_direct_path(
    leaf_index: SecretTreeLeafIndex,
    size: SecretTreeLeafIndex,
) -> Result<Vec<SecretTreeNodeIndex>, TreeMathError> {
    leaf_in_tree(leaf_index, size)?;
    let node_index = SecretTreeNodeIndex::from(leaf_index);
    let r = root(size);
    if node_index == r {
        return Ok(vec![r]);
    }

    let mut d = vec![];
    let mut x = node_index;
    while x != r {
        x = try_parent(x, size)?;
        d.push(x);
    }
    Ok(d)
}

// The following is not currently used but could be useful in future parent hash
// computations:

#[test]
fn invalid_inputs() {
    assert_eq!(
        Err(TreeMathError::InvalidInput),
        try_parent(1000u32.into(), 100u32.into())
    );
}

#[test]
fn test_leaf_in_tree() {
    let tests = [(0u32, 2u32), (1, 2), (4, 5), (9, 10)];
    for test in tests.iter() {
        leaf_in_tree(test.0.into(), test.1.into()).expect("An unexpected error occurred.");
    }
}

#[test]
fn test_leaf_not_in_tree() {
    let tests = [(2u32, 2u32), (7, 7)];
    for test in tests.iter() {
        assert_eq!(
            leaf_in_tree(test.0.into(), test.1.into()),
            Err(TreeMathError::LeafNotInTree)
        );
    }
}
