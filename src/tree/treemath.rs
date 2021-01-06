use crate::tree::index::*;
use std::cmp::Ordering;

#[derive(Debug)]
pub(crate) enum TreeMathError {
    LeafHasNoChildren,
    RootHasNoParent,
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

// Ordered from leaf to root
// Includes neither leaf nor root
pub(crate) fn dirpath(index: NodeIndex, size: LeafIndex) -> Result<Vec<NodeIndex>, TreeMathError> {
    let r = root(size);
    if index == r {
        return Ok(vec![]);
    }

    let mut d = vec![];
    let mut x = parent(index, size)?;
    while x != r {
        d.push(x);
        x = parent(x, size)?;
    }
    Ok(d)
}

// Ordered from leaf to root
// Includes leaf and root
pub(crate) fn dirpath_long(
    index: NodeIndex,
    size: LeafIndex,
) -> Result<Vec<NodeIndex>, TreeMathError> {
    let r = root(size);
    if index == r {
        return Ok(vec![r]);
    }

    let mut x = index;
    let mut d = vec![index];
    while x != r {
        x = parent(x, size)?;
        d.push(x);
    }
    Ok(d)
}

// Ordered from leaf to root
// Includes root but not leaf
pub(crate) fn direct_path_root(
    index: NodeIndex,
    size: LeafIndex,
) -> Result<Vec<NodeIndex>, TreeMathError> {
    let r = root(size);
    if index == r {
        return Ok(vec![r]);
    }

    let mut d = vec![];
    let mut x = index;
    while x != r {
        x = parent(x, size)?;
        d.push(x);
    }
    Ok(d)
}

// Ordered from leaf to root
pub(crate) fn copath(index: NodeIndex, size: LeafIndex) -> Result<Vec<NodeIndex>, TreeMathError> {
    if index == root(size) {
        return Ok(vec![]);
    }
    let mut d = vec![index];
    d.append(&mut dirpath(index, size)?);
    d.iter().map(|&index| sibling(index, size)).collect()
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

// The following is not currently used but could be useful in future parent hash
// computations:

/// Returns the list of nodes that are descendants of a given parent node,
/// including the parent node itself
pub(crate) fn _descendants(x: NodeIndex, size: LeafIndex) -> Vec<NodeIndex> {
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
pub(crate) fn _descendants_alt(x: NodeIndex, size: LeafIndex) -> Vec<NodeIndex> {
    if level(x) == 0 {
        vec![x]
    } else {
        let left_child = left(x).unwrap();
        let right_child = right(x, size).unwrap();
        [
            _descendants_alt(left_child, size),
            vec![x],
            _descendants_alt(right_child, size),
        ]
        .concat()
    }
}
