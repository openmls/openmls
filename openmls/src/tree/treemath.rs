use crate::tree::index::*;

implement_error! {
    pub enum TreeMathError {
        LeafHasNoChildren = "Leaf nodes don't have children.",
        RootHasNoParent = "Root nodes don't have parents.",
        LeafNotInTree = "The leaf index is larger than the tree size.",
        InvalidInput = "The provided input is invalid for tree math.",
    }
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

pub(crate) fn level(index: NodeIndex) -> usize {
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

pub(crate) fn root(size: LeafIndex) -> NodeIndex {
    let n = size.as_usize();
    let w = node_width(n);
    NodeIndex::from((1usize << log2(w)) - 1)
}

pub(crate) fn left(index: NodeIndex) -> Result<NodeIndex, TreeMathError> {
    let x = index.as_usize();
    let k = level(NodeIndex::from(x));
    if k == 0 {
        return Err(TreeMathError::LeafHasNoChildren);
    }
    Ok(NodeIndex::from(x ^ (0x01 << (k - 1))))
}

pub(crate) fn right(index: NodeIndex, size: LeafIndex) -> Result<NodeIndex, TreeMathError> {
    let x = index.as_usize();
    let n = size.as_usize();
    let k = level(NodeIndex::from(x));
    if k == 0 {
        return Err(TreeMathError::LeafHasNoChildren);
    }
    let mut r = x ^ (0x03 << (k - 1));
    while r >= node_width(n) {
        r = left(NodeIndex::from(r))?.as_usize();
    }
    Ok(NodeIndex::from(r))
}

// The parent here might be beyond the right edge of the tree.
pub(crate) fn parent_step(x: usize) -> usize {
    // We need to use u64 for some of the operations where usize is too small on 32bit platforms
    let k = level(NodeIndex::from(x));
    let b = (x as u64 >> (k + 1)) & 0x01;
    let res = (x as u64 | (1 << k)) ^ (b << (k + 1));
    res as usize
}

// This function is only safe to use if index <= size.
// If this is not checked before calling the function, `parent` should be used.
fn unsafe_parent(index: NodeIndex, size: LeafIndex) -> Result<NodeIndex, TreeMathError> {
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
    Ok(NodeIndex::from(p))
}

#[inline(always)]
fn leaf_in_tree(leaf_index: LeafIndex, size: LeafIndex) -> Result<(), TreeMathError> {
    if leaf_index >= size {
        Err(TreeMathError::LeafNotInTree)
    } else {
        Ok(())
    }
}

/// Direct path from a leaf node to the root.
/// Does not include the leaf node but includes the root.
pub(crate) fn leaf_direct_path(
    leaf_index: LeafIndex,
    size: LeafIndex,
) -> Result<Vec<NodeIndex>, TreeMathError> {
    leaf_in_tree(leaf_index, size)?;
    let node_index = NodeIndex::from(leaf_index);
    let r = root(size);
    if node_index == r {
        return Ok(vec![r]);
    }

    let mut d = vec![];
    let mut x = node_index;
    while x != r {
        x = unsafe_parent(x, size)?;
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
        unsafe_parent(1000u32.into(), 100u32.into())
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
