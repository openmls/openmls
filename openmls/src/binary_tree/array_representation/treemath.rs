use std::cmp::Ordering;
use thiserror::Error;

use super::tree::NodeIndex;

/// Tree math error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum TreeMathError {
    /// Leaf nodes don't have children.
    #[error("Leaf nodes don't have children.")]
    LeafHasNoChildren,
    /// Root nodes don't have parents.
    #[error("Root nodes don't have parents.")]
    RootHasNoParent,
    /// The node index is larger than the tree size.
    #[error("The node index is larger than the tree size.")]
    NodeNotInTree,
    /// The provided input is invalid for tree math.
    #[error("The provided input is invalid for tree math.")]
    InvalidInput,
}

fn log2(x: NodeIndex) -> usize {
    if x == 0 {
        return 0;
    }
    let mut k = 0;
    while (x >> k) > 0 {
        k += 1
    }
    k - 1
}

fn level(index: NodeIndex) -> usize {
    let x = index;
    if (x & 0x01) == 0 {
        return 0;
    }
    let mut k = 0;
    while ((x >> k) & 0x01) == 1 {
        k += 1;
    }
    k
}

pub(super) fn root(size: NodeIndex) -> NodeIndex {
    (1 << log2(size)) - 1
}

pub(super) fn left(index: NodeIndex) -> Result<NodeIndex, TreeMathError> {
    let x = index;
    let k = level(x);
    if k == 0 {
        return Err(TreeMathError::LeafHasNoChildren);
    }
    Ok(x ^ (0x01 << (k - 1)))
}

pub(super) fn right(index: NodeIndex, size: NodeIndex) -> Result<NodeIndex, TreeMathError> {
    let x = index;
    let n = size;
    let k = level(x);
    if k == 0 {
        return Err(TreeMathError::LeafHasNoChildren);
    }
    let mut r = x ^ (0x03 << (k - 1));
    while r >= n {
        r = left(r)?;
    }
    Ok(r)
}

// The parent here might be beyond the right edge of the tree.
pub(super) fn parent_step(x: NodeIndex) -> NodeIndex {
    let k = level(x);
    let b = (x >> (k + 1)) & 0x01;
    (x | (1 << k)) ^ (b << (k + 1))
}

// This function is only safe to use if index <= size.
// If this is not checked before calling the function, `parent` should be used.
fn try_parent(index: NodeIndex, size: NodeIndex) -> Result<NodeIndex, TreeMathError> {
    let x = index;
    let n = size;
    if index == root(size) {
        return Err(TreeMathError::RootHasNoParent);
    }
    let mut p = parent_step(x);
    while p >= n {
        let new_p = parent_step(p);
        if new_p == p {
            return Err(TreeMathError::InvalidInput);
        }
        p = new_p;
    }
    Ok(p)
}

pub(super) fn sibling(index: NodeIndex, size: NodeIndex) -> Result<NodeIndex, TreeMathError> {
    node_in_tree(index, size)?;
    let p = try_parent(index, size)?;
    match index.cmp(&p) {
        Ordering::Less => right(p, size),
        Ordering::Greater => left(p),
        Ordering::Equal => left(p),
    }
}

#[inline(always)]
pub(super) fn node_in_tree(node_index: NodeIndex, size: NodeIndex) -> Result<(), TreeMathError> {
    if node_index >= size {
        Err(TreeMathError::NodeNotInTree)
    } else {
        Ok(())
    }
}

/// Direct path from a node to the root.
/// Does not include the node itself.
pub(super) fn direct_path(
    node_index: NodeIndex,
    size: NodeIndex,
) -> Result<Vec<NodeIndex>, TreeMathError> {
    node_in_tree(node_index, size)?;
    let node_index = node_index;
    let r = root(size);
    if node_index == r {
        return Ok(vec![]);
    }

    let mut d = vec![];
    let mut x = node_index;
    while x != r {
        x = try_parent(x, size)?;
        d.push(x);
    }
    Ok(d)
}

pub(super) fn lowest_common_ancestor(x: NodeIndex, y: NodeIndex) -> NodeIndex {
    let (lx, ly) = (level(x) + 1, level(y) + 1);
    if (lx <= ly) && (x >> ly == y >> ly) {
        return y;
    } else if (ly <= lx) && (x >> lx == y >> lx) {
        return x;
    }

    let (mut xn, mut yn) = (x, y);
    let mut k = 0;
    while xn != yn {
        xn >>= 1;
        yn >>= 1;
        k += 1;
    }
    (xn << k) + (1 << (k - 1)) - 1
}

pub(super) fn parent(index: NodeIndex, size: NodeIndex) -> Result<NodeIndex, TreeMathError> {
    node_in_tree(index, size)?;
    try_parent(index, size)
}

#[cfg(any(feature = "test-utils", test))]
pub(crate) fn node_width(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        2 * (n - 1) + 1
    }
}

#[test]
fn invalid_inputs() {
    assert_eq!(Err(TreeMathError::NodeNotInTree), parent(1000u32, 100u32));
}

#[test]
fn test_node_in_tree() {
    let tests = [(0u32, 2u32), (1, 2), (2, 4), (5, 6), (2, 10)];
    for test in tests.iter() {
        node_in_tree(test.0, test.1).expect("An unexpected error occurred.");
    }
}

#[test]
fn test_node_not_in_tree() {
    let tests = [(3u32, 2u32), (13, 7)];
    for test in tests.iter() {
        assert_eq!(
            node_in_tree(test.0, test.1),
            Err(TreeMathError::NodeNotInTree)
        );
    }
}
