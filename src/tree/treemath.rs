use crate::tree::index::*;
use std::cmp::Ordering;

implement_error! {
    pub enum TreeMathError {
        LeafHasNoChildren = "Leaf nodes don't have children.",
        RootHasNoParent = "Root nodes don't have parents.",
        NotAParentNode = "Node index was not a parent node.",
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
    while ((x >> k) & 0x01) == 1 {
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

pub(crate) fn parent_step(x: usize) -> usize {
    let k = level(NodeIndex::from(x));
    let b = (x >> (k + 1)) & 0x01;
    (x | (1 << k)) ^ (b << (k + 1))
}

pub(crate) fn parent(index: NodeIndex, size: LeafIndex) -> Result<NodeIndex, TreeMathError> {
    let x = index.as_usize();
    let n = size.as_usize();
    if index == root(size) {
        return Err(TreeMathError::RootHasNoParent);
    }
    let mut p = parent_step(x);
    while p >= node_width(n) {
        p = parent_step(p)
    }
    Ok(NodeIndex::from(p))
}

pub(crate) fn sibling(index: NodeIndex, size: LeafIndex) -> Result<NodeIndex, TreeMathError> {
    let p = parent(index, size)?;
    match index.cmp(&p) {
        Ordering::Less => right(p, size),
        Ordering::Greater => left(p),
        Ordering::Equal => left(p),
    }
}

/// Direct path from a leaf node to the root.
/// Does not include the leaf node but includes the root.
pub(crate) fn leaf_direct_path(
    leaf_index: LeafIndex,
    size: LeafIndex,
) -> Result<Vec<NodeIndex>, TreeMathError> {
    let node_index = NodeIndex::from(leaf_index);
    let r = root(size);
    if node_index == r {
        return Ok(vec![r]);
    }

    let mut d = vec![];
    let mut x = node_index;
    while x != r {
        x = parent(x, size)?;
        d.push(x);
    }
    Ok(d)
}

/// Direct path from a parent node to the root.
/// Includes the parent node and the root.
/// Returns an error if the `index` is not a parent node.
pub(crate) fn parent_direct_path(
    node_index: NodeIndex,
    size: LeafIndex,
) -> Result<Vec<NodeIndex>, TreeMathError> {
    if !node_index.is_parent() {
        return Err(TreeMathError::NotAParentNode);
    }
    let r = root(size);
    if node_index == r {
        return Ok(vec![r]);
    }

    let mut x = node_index;
    let mut d = vec![node_index];
    while x != r {
        x = parent(x, size)?;
        d.push(x);
    }
    Ok(d)
}

/// Copath of a leaf.
/// Ordered from leaf to root.
pub(crate) fn copath(
    leaf_index: LeafIndex,
    size: LeafIndex,
) -> Result<Vec<NodeIndex>, TreeMathError> {
    let node_index = NodeIndex::from(leaf_index);
    // If the tree only has one leaf
    if node_index == root(size) {
        return Ok(vec![]);
    }
    // Add leaf node
    let mut d = vec![node_index];
    // Add direct path
    d.append(&mut leaf_direct_path(leaf_index, size)?);
    // Remove root node
    d.pop();
    // Calculate copath
    d.iter()
        .map(|&node_index| sibling(node_index, size))
        .collect()
}

pub(crate) fn common_ancestor_index(x: NodeIndex, y: NodeIndex) -> NodeIndex {
    let (lx, ly) = (level(x) + 1, level(y) + 1);
    if (lx <= ly) && (x.as_usize() >> ly == y.as_usize() >> ly) {
        return y;
    } else if (ly <= lx) && (x.as_usize() >> lx == y.as_usize() >> lx) {
        return x;
    }

    let (mut xn, mut yn) = (x.as_usize(), y.as_usize());
    let mut k = 0;
    while xn != yn {
        xn >>= 1;
        yn >>= 1;
        k += 1;
    }
    NodeIndex::from((xn << k) + (1 << (k - 1)) - 1)
}

/// Returns the number of leaves in a tree
pub(crate) fn leaf_count(number_of_nodes: NodeIndex) -> LeafIndex {
    LeafIndex::from((number_of_nodes.as_usize() + 1) / 2)
}

// The following is not currently used but could be useful in future parent hash
// computations:

/// Returns the list of nodes that are descendants of a given parent node,
/// including the parent node itself
#[cfg(test)]
pub(crate) fn descendants(x: NodeIndex, size: LeafIndex) -> Vec<NodeIndex> {
    let l = level(x);
    if l == 0 {
        vec![x]
    } else {
        let s = (1 << l) - 1;
        let l = x.as_usize() - s;
        let mut r = x.as_usize() + s;
        if r > (size.as_usize() * 2) - 2 {
            r = (size.as_usize() * 2) - 2;
        }

        (l..=r).map(NodeIndex::from).collect::<Vec<NodeIndex>>()
    }
}

/// Returns the list of nodes that are descendants of a given parent node,
/// including the parent node itself
/// (Alternative, easier to verify implementation)
#[cfg(test)]
pub(crate) fn descendants_alt(x: NodeIndex, size: LeafIndex) -> Vec<NodeIndex> {
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
