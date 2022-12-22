use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::binary_tree::TreeSize;

/// LeafNodeIndex references a leaf node in a tree.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct LeafNodeIndex(u32);

impl LeafNodeIndex {
    /// Create a new `LeafNodeIndex` from a `u32`.
    pub fn new(index: u32) -> Self {
        LeafNodeIndex(index)
    }

    /// Return the inner value as `u32`.
    pub fn u32(&self) -> u32 {
        self.0
    }

    /// Return the inner value as `usize`.
    pub fn usize(&self) -> usize {
        self.u32() as usize
    }

    /// Return the index as a TreeNodeIndex value.
    pub(crate) fn to_tree_index(self) -> u32 {
        self.0 * 2
    }

    /// Warning: Only use when the node index represents a leaf node
    pub(super) fn from_tree_index(node_index: u32) -> Self {
        LeafNodeIndex(node_index / 2)
    }
}

/// ParentNodeIndex references a parent node in a tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ParentNodeIndex(u32);

impl ParentNodeIndex {
    #[cfg(any(test, feature = "test-utils"))]
    /// Return the inner value as `u32`.
    pub fn u32(&self) -> u32 {
        self.0
    }

    /// Return the index as a TreeNodeIndex value.
    pub(crate) fn to_tree_index(self) -> u32 {
        self.0 * 2 + 1
    }

    /// Warning: Only use when the node index represents a parent node
    pub(super) fn from_tree_index(node_index: u32) -> Self {
        debug_assert!(node_index > 0);
        debug_assert!(node_index % 2 == 1);
        ParentNodeIndex((node_index - 1) / 2)
    }
}

impl From<LeafNodeIndex> for TreeNodeIndex {
    fn from(leaf_index: LeafNodeIndex) -> Self {
        TreeNodeIndex::Leaf(leaf_index)
    }
}

impl From<ParentNodeIndex> for TreeNodeIndex {
    fn from(parent_index: ParentNodeIndex) -> Self {
        TreeNodeIndex::Parent(parent_index)
    }
}

/// TreeNodeIndex references a node in a tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TreeNodeIndex {
    Leaf(LeafNodeIndex),
    Parent(ParentNodeIndex),
}

impl TreeNodeIndex {
    /// Create a new `TreeNodeIndex` from a `u32`.
    pub fn new(index: u32) -> Self {
        if index % 2 == 0 {
            TreeNodeIndex::Leaf(LeafNodeIndex::from_tree_index(index))
        } else {
            TreeNodeIndex::Parent(ParentNodeIndex::from_tree_index(index))
        }
    }

    /// Return the inner value as `u32`.
    pub fn u32(&self) -> u32 {
        match self {
            TreeNodeIndex::Leaf(index) => index.to_tree_index(),
            TreeNodeIndex::Parent(index) => index.to_tree_index(),
        }
    }

    /// Return the inner value as `usize`.
    pub fn usize(&self) -> usize {
        self.u32() as usize
    }
}

impl Ord for TreeNodeIndex {
    fn cmp(&self, other: &TreeNodeIndex) -> Ordering {
        self.u32().cmp(&other.u32())
    }
}

impl PartialOrd for TreeNodeIndex {
    fn partial_cmp(&self, other: &TreeNodeIndex) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn log2(x: u32) -> usize {
    if x == 0 {
        return 0;
    }
    let mut k = 0;
    while (x >> k) > 0 {
        k += 1
    }
    k - 1
}

fn level(index: u32) -> usize {
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

pub(super) fn root(size: u32) -> TreeNodeIndex {
    debug_assert!(size > 0);
    TreeNodeIndex::new((1 << log2(size)) - 1)
}

pub(super) fn left(index: ParentNodeIndex) -> TreeNodeIndex {
    let x = index.to_tree_index();
    let k = level(x);
    debug_assert!(k > 0);
    let index = x ^ (0x01 << (k - 1));
    TreeNodeIndex::new(index)
}

fn left_helper(x: u32) -> u32 {
    let k = level(x);
    debug_assert!(k > 0);
    x ^ (0x01 << (k - 1))
}

pub(super) fn right(index: ParentNodeIndex, size: u32) -> TreeNodeIndex {
    debug_assert!(size > 0);
    debug_assert!(index.to_tree_index() < size);
    let x = index.to_tree_index();
    let k = level(x);
    debug_assert!(k > 0);
    let mut r = x ^ (0x03 << (k - 1));
    while r >= size {
        r = left_helper(r);
    }
    TreeNodeIndex::new(r)
}

/*
/// New treemath for full tree

pub(super) fn right(index: ParentNodeIndex) -> TreeNodeIndex {
    let x = index.to_tree_index();
    let k = level(x);
    debug_assert!(k > 0);
    let index = x ^ (0x03 << (k - 1));
    TreeNodeIndex::new(index)
}

/// Warning: There is no check about the tree size and whether the parent is
/// beyond the root
pub(super) fn parent(x: TreeNodeIndex) -> ParentNodeIndex {
    let x = x.u32();
    let k = level(x);
    let b = (x >> (k + 1)) & 0x01;
    let index = (x | (1 << k)) ^ (b << (k + 1));
    ParentNodeIndex::from_tree_index(index)
} */

// The parent here might be beyond the right edge of the tree.
pub fn parent_step(x: u32) -> u32 {
    let k = level(x);
    let b = (x >> (k + 1)) & 0x01;
    (x | (1 << k)) ^ (b << (k + 1))
}

// This function is only safe to use if index <= size.
pub(super) fn parent(index: TreeNodeIndex, size: u32) -> ParentNodeIndex {
    let x = index.u32();
    let n = size;
    let mut p = parent_step(x);
    while p >= n {
        let new_p = parent_step(p);
        debug_assert!(new_p != p);
        p = new_p;
    }
    ParentNodeIndex::from_tree_index(p)
}

pub(crate) fn sibling(index: TreeNodeIndex, size: u32) -> TreeNodeIndex {
    let p = parent(index, size);
    match index.u32().cmp(&p.to_tree_index()) {
        Ordering::Less => right(p, size),
        Ordering::Greater => left(p),
        Ordering::Equal => left(p),
    }
}

/// Direct path from a node to the root.
/// Does not include the node itself.
pub(crate) fn direct_path(node_index: LeafNodeIndex, size: u32) -> Vec<ParentNodeIndex> {
    let r = root(size).u32();

    let mut d = vec![];
    let mut x = node_index.to_tree_index();
    while x != r {
        let parent = parent(TreeNodeIndex::new(x), size);
        d.push(parent);
        x = parent.to_tree_index();
    }
    d
}

/// Common ancestor of two leaf nodes, aka the node where their direct paths
/// intersect.
pub(super) fn lowest_common_ancestor(x: LeafNodeIndex, y: LeafNodeIndex) -> ParentNodeIndex {
    let x = x.to_tree_index();
    let y = y.to_tree_index();
    let (lx, ly) = (level(x) + 1, level(y) + 1);
    if (lx <= ly) && (x >> ly == y >> ly) {
        return ParentNodeIndex::from_tree_index(y);
    } else if (ly <= lx) && (x >> lx == y >> lx) {
        return ParentNodeIndex::from_tree_index(x);
    }

    let (mut xn, mut yn) = (x, y);
    let mut k = 0;
    while xn != yn {
        xn >>= 1;
        yn >>= 1;
        k += 1;
    }
    ParentNodeIndex::from_tree_index((xn << k) + (1 << (k - 1)) - 1)
}

/// The common direct path of two leaf nodes, i.e. the path from their common
/// ancestor to the root.
pub(crate) fn common_direct_path(
    x: LeafNodeIndex,
    y: LeafNodeIndex,
    size: TreeSize,
) -> Vec<ParentNodeIndex> {
    let x = x;
    let y = y;
    let mut x_path = direct_path(x, size);
    let mut y_path = direct_path(y, size);
    x_path.reverse();
    y_path.reverse();

    let mut common_path = vec![];

    for (x, y) in x_path.iter().zip(y_path.iter()) {
        if x == y {
            common_path.push(*x);
        } else {
            break;
        }
    }

    common_path.reverse();
    common_path
}

#[cfg(any(feature = "test-utils", test))]
pub(crate) fn node_width(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        2 * (n - 1) + 1
    }
}

pub(crate) fn is_node_in_tree(node_index: TreeNodeIndex, size: u32) -> bool {
    node_index.u32() < size
}

#[test]
fn test_node_in_tree() {
    let tests = [
        (TreeNodeIndex::new(0u32), 2u32),
        (TreeNodeIndex::new(1), 2),
        (TreeNodeIndex::new(2), 4),
        (TreeNodeIndex::new(5), 6),
        (TreeNodeIndex::new(2), 10),
    ];
    for test in tests.iter() {
        assert!(is_node_in_tree(test.0, test.1));
    }
}

#[test]
fn test_node_not_in_tree() {
    let tests = [
        (TreeNodeIndex::new(3u32), 2u32),
        (TreeNodeIndex::new(13), 7),
    ];
    for test in tests.iter() {
        assert!(!is_node_in_tree(test.0, test.1));
    }
}
