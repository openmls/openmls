// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

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
        return Ok(vec![]);
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
        return Ok(vec![]);
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
