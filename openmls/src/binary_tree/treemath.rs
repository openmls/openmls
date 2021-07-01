use std::cmp::Ordering;

use super::NodeIndex;

implement_error! {
    pub enum TreeMathError {
        LeafHasNoChildren = "Leaf nodes don't have children.",
        RootHasNoParent = "Root nodes don't have parents.",
        NotAParentNode = "Node index was not a parent node.",
        LeafNotInTree = "The leaf index is larger than the tree size.",
        NodeNotInTree = "The node index is larger than the tree size.",
        InvalidInput = "The provided input is invalid for tree math.",
    }
}

pub(crate) fn log2(x: NodeIndex) -> usize {
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

pub(crate) fn root(size: NodeIndex) -> NodeIndex {
    (1 << log2(size)) - 1
}

pub(crate) fn left(index: NodeIndex) -> Result<NodeIndex, TreeMathError> {
    let x = index;
    let k = level(x);
    if k == 0 {
        return Err(TreeMathError::LeafHasNoChildren);
    }
    Ok(x ^ (0x01 << (k - 1)))
}

pub(crate) fn right(index: NodeIndex, size: NodeIndex) -> Result<NodeIndex, TreeMathError> {
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
pub(crate) fn parent_step(x: NodeIndex) -> NodeIndex {
    let k = level(x);
    let b = (x >> (k + 1)) & 0x01;
    (x | (1 << k)) ^ (b << (k + 1))
}

pub(crate) fn parent(index: NodeIndex, size: NodeIndex) -> Result<NodeIndex, TreeMathError> {
    node_in_tree(index, size)?;
    unsafe_parent(index, size)
}

// This function is only safe to use if index <= size.
// If this is not checked before calling the function, `parent` should be used.
fn unsafe_parent(index: NodeIndex, size: NodeIndex) -> Result<NodeIndex, TreeMathError> {
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

pub(crate) fn sibling(index: NodeIndex, size: NodeIndex) -> Result<NodeIndex, TreeMathError> {
    node_in_tree(index, size)?;
    let p = unsafe_parent(index, size)?;
    match index.cmp(&p) {
        Ordering::Less => right(p, size),
        Ordering::Greater => left(p),
        Ordering::Equal => left(p),
    }
}

#[inline(always)]
pub(crate) fn node_in_tree(node_index: NodeIndex, size: NodeIndex) -> Result<(), TreeMathError> {
    if node_index >= size {
        Err(TreeMathError::NodeNotInTree)
    } else {
        Ok(())
    }
}

/// Direct path from a node to the root. Does not include the node itself.
/// Returns an error if the given node index is not within the tree.
pub(crate) fn direct_path(
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
        x = unsafe_parent(x, size)?;
        d.push(x);
    }
    Ok(d)
}

/// Copath of a node.
/// Ordered from starting node to root.
pub(crate) fn copath(
    node_index: NodeIndex,
    size: NodeIndex,
) -> Result<Vec<NodeIndex>, TreeMathError> {
    node_in_tree(node_index, size)?;
    let node_index = node_index;
    // If the tree only has one leaf
    if node_index == root(size) {
        return Ok(vec![]);
    }
    // Add leaf node
    let mut d = vec![node_index];
    // Add direct path
    d.append(&mut direct_path(node_index, size)?);
    // Remove root node
    d.pop();
    // Calculate copath
    d.iter()
        .map(|&node_index| sibling(node_index, size))
        .collect()
}

pub(crate) fn lowest_common_ancestor(x: NodeIndex, y: NodeIndex) -> NodeIndex {
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

/// Returns the number of leaves in a tree
pub(crate) fn leaf_count(number_of_nodes: NodeIndex) -> NodeIndex {
    (number_of_nodes + 1) / 2
}

// The following is not currently used but could be useful in future parent hash
// computations:

/// Returns the list of nodes that are descendants of a given parent node,
/// including the parent node itself
#[cfg(test)]
pub(crate) fn descendants(x: NodeIndex, size: NodeIndex) -> Vec<NodeIndex> {
    let l = level(x);
    if l == 0 {
        vec![x]
    } else {
        let s = (1 << l) - 1;
        let l = x - s;
        let mut r = x + s;
        if r > (size * 2) - 2 {
            r = (size * 2) - 2;
        }

        (l..=r).collect()
    }
}

/// Returns the list of nodes that are descendants of a given parent node,
/// including the parent node itself
/// (Alternative, easier to verify implementation)
#[cfg(test)]
pub(crate) fn descendants_alt(x: NodeIndex, size: NodeIndex) -> Vec<NodeIndex> {
    if level(x) == 0 {
        vec![x]
    } else {
        let left_child = left(x).unwrap();
        let right_child = right(x, size).unwrap();
        [
            descendants_alt(left_child, size),
            vec![x],
            descendants_alt(right_child, size),
        ]
        .concat()
    }
}

#[test]
fn invalid_inputs() {
    assert_eq!(
        Err(TreeMathError::NodeNotInTree),
        parent(1000u32.into(), 100u32.into())
    );
}

#[test]
fn test_node_in_tree() {
    let tests = [(0u32, 2u32), (1, 2), (2, 4), (5, 6), (2, 10)];
    for test in tests.iter() {
        node_in_tree(test.0.into(), test.1.into()).unwrap();
    }
}

#[test]
fn test_node_not_in_tree() {
    let tests = [(3u32, 2u32), (13, 7)];
    for test in tests.iter() {
        assert_eq!(
            node_in_tree(test.0.into(), test.1.into()),
            Err(TreeMathError::NodeNotInTree)
        );
    }
}
