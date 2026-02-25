//! Node-level state model for MLS ratchet trees.
//!
//! Provides lightweight types that snapshot the blank/occupied status of every
//! node in a ratchet tree and the unmerged-leaf list of every occupied parent —
//! all the information needed to reason about co-path resolution sizes without
//! touching cryptographic key material.
//!
//! # Tree topology
//!
//! Uses MLS's array-tree indexing (RFC 9420 §7.1):
//!
//! - Leaf `i` occupies **tree-node index `2i`** (even positions).
//! - Parent node `k` occupies **tree-node index `2k + 1`** (odd positions).
//! - A tree with `n` leaf slots has exactly `n - 1` parent nodes.
//!
//! The root is the unique ancestor of all nodes, located at tree-node index
//! `(1 << floor(log2(2n − 1))) − 1`.

use std::fmt;

// ── Leaf index ────────────────────────────────────────────────────────────────

/// Index of a leaf in the ratchet tree (0-based).
///
/// Leaf `i` occupies MLS array-tree node index `2i`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeafIndex(pub u32);

impl From<u32> for LeafIndex {
    fn from(v: u32) -> Self {
        LeafIndex(v)
    }
}

impl From<LeafIndex> for u32 {
    fn from(l: LeafIndex) -> u32 {
        l.0
    }
}

impl fmt::Display for LeafIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Node states ───────────────────────────────────────────────────────────────

/// State of a leaf node in the ratchet tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafState {
    /// The leaf slot is empty — no member is assigned here.
    Blank,
    /// The leaf slot holds a group member.
    Occupied,
}

/// State of a parent (interior) node in the ratchet tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentState {
    /// The node carries no key material (blanked by a Remove or never set).
    Blank,
    /// The node carries key material.
    ///
    /// `unmerged_leaves` lists the leaf indices whose HPKE key has not yet
    /// been merged into this node; they must be included separately when
    /// computing the node's resolution.
    Occupied {
        /// Leaves whose key material is not yet merged into this node.
        unmerged_leaves: Vec<LeafIndex>,
    },
}

// ── Tree state ────────────────────────────────────────────────────────────────

/// A snapshot of the ratchet tree's node-level state.
///
/// Captures the blank/occupied status of every node and the unmerged-leaf list
/// of every occupied parent — everything needed to compute co-path resolution
/// sizes without referencing cryptographic key material.
///
/// # Construction
///
/// Build a `TreeState` by supplying one [`LeafState`] per leaf slot and one
/// [`ParentState`] per parent node:
///
/// ```
/// use openmls_tree_health::tree_state::{LeafIndex, LeafState, ParentState, TreeState};
///
/// // 4-leaf tree: all occupied, tree[1] blank, leaf[2] recently added so it
/// // is unmerged at tree[5] and at the root (every ancestor inherits the list).
/// let state = TreeState::new(
///     vec![
///         LeafState::Occupied,
///         LeafState::Occupied,
///         LeafState::Occupied,
///         LeafState::Occupied,
///     ],
///     vec![
///         ParentState::Blank,                                             // tree[1]
///         ParentState::Occupied { unmerged_leaves: vec![LeafIndex(2)] }, // tree[3] (root)
///         ParentState::Occupied { unmerged_leaves: vec![LeafIndex(2)] }, // tree[5]
///     ],
/// );
/// println!("{state}");
/// ```
#[derive(Debug, Clone)]
pub struct TreeState {
    /// State of each leaf, indexed by leaf index 0..n.
    leaves: Vec<LeafState>,
    /// State of each parent. `parents[k]` is the node at tree-node index `2k + 1`.
    parents: Vec<ParentState>,
}

impl TreeState {
    /// Construct a `TreeState` from leaf and parent states.
    ///
    /// `parents` must have exactly `leaves.len() - 1` elements
    /// (or be empty for a single-leaf tree).
    ///
    /// # Panics
    ///
    /// Panics if `parents.len() != leaves.len().saturating_sub(1)`.
    pub fn new(leaves: Vec<LeafState>, parents: Vec<ParentState>) -> Self {
        let n = leaves.len();
        let expected = n.saturating_sub(1);
        assert!(
            parents.len() == expected,
            "a tree with {n} leaves requires {expected} parents, got {}",
            parents.len(),
        );
        Self { leaves, parents }
    }

    /// Number of leaf slots (including blank ones).
    pub fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// State of leaf `idx`.
    ///
    /// # Panics
    ///
    /// Panics if `idx.0 >= self.num_leaves() as u32`.
    pub fn leaf_state(&self, idx: LeafIndex) -> &LeafState {
        &self.leaves[idx.0 as usize]
    }

    /// State of parent node `k`, occupying tree-node index `2k + 1`.
    ///
    /// # Panics
    ///
    /// Panics if `k >= self.num_leaves().saturating_sub(1)`.
    pub fn parent_state(&self, k: usize) -> &ParentState {
        &self.parents[k]
    }

    /// Iterator over leaf states, in leaf-index order.
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex, &LeafState)> {
        self.leaves
            .iter()
            .enumerate()
            .map(|(i, s)| (LeafIndex(i as u32), s))
    }

    /// Iterator over parent states, in tree-node-index order (tree[1], tree[3], …).
    pub fn parents(&self) -> impl Iterator<Item = (usize, &ParentState)> {
        self.parents
            .iter()
            .enumerate()
            .map(|(k, s)| (2 * k + 1, s))
    }

    // ── Tree math (RFC 9420 §7.1) ─────────────────────────────────────────

    /// Level of a tree node = number of trailing 1-bits in its index.
    ///
    /// Level 0 → leaf; level k > 0 → interior node spanning 2^k leaves.
    fn level(x: usize) -> u32 {
        x.trailing_ones()
    }

    /// Tree-node index of the root for a tree with `n_leaves` leaf slots.
    ///
    /// Returns `0` for a single-leaf tree (the leaf is the root).
    fn root_index(n_leaves: usize) -> usize {
        if n_leaves <= 1 {
            return 0;
        }
        // width = 2n − 1; root = (1 << floor(log2(width))) − 1
        let width = 2 * n_leaves - 1;
        let floor_log2 = usize::BITS - 1 - width.leading_zeros(); // u32
        (1usize << floor_log2) - 1
    }

    /// Left child of interior tree-node `x`.
    fn left_child(x: usize) -> usize {
        let k = Self::level(x);
        debug_assert!(k > 0, "leaf nodes have no children");
        x - (1usize << (k - 1))
    }

    /// Right child of interior tree-node `x` in a tree with `n_leaves` leaf
    /// slots.
    ///
    /// In a left-balanced binary tree the right subtree may be shorter than a
    /// perfect binary tree.  This follows RFC 9420 §7.1: starting from the
    /// would-be right child in a perfect tree, descend left until the node is
    /// within the tree bounds.
    fn right_child(x: usize, n_leaves: usize) -> usize {
        let k = Self::level(x);
        debug_assert!(k > 0, "leaf nodes have no children");
        let bounds = 2 * n_leaves - 1; // total node positions: 0..bounds
        let mut r = x ^ (3usize << (k - 1));
        while r >= bounds {
            let rl = Self::level(r);
            debug_assert!(rl > 0);
            r -= 1usize << (rl - 1);
        }
        r
    }

    // ── Display helpers ────────────────────────────────────────────────────

    fn fmt_parent_state(state: &ParentState) -> String {
        match state {
            ParentState::Blank => "blank".to_string(),
            ParentState::Occupied { unmerged_leaves } => {
                if unmerged_leaves.is_empty() {
                    "occ, unmerged=[]".to_string()
                } else {
                    let ids: Vec<String> =
                        unmerged_leaves.iter().map(|l| l.0.to_string()).collect();
                    format!("occ, unmerged=[{}]", ids.join(", "))
                }
            }
        }
    }

    /// Recursively write the subtree rooted at tree-node `x`.
    ///
    /// - `prefix` is prepended to every *child* line (not the current one).
    /// - `connector` is the branch glyph on the current line:
    ///   `""` for the root, `"├── "` for a non-last child, `"└── "` for the
    ///   last child.
    fn fmt_node(
        &self,
        f: &mut fmt::Formatter<'_>,
        x: usize,
        prefix: &str,
        connector: &str,
    ) -> fmt::Result {
        let n = self.leaves.len();

        if x % 2 == 0 {
            // ── Leaf node ──────────────────────────────────────────────────
            let leaf_idx = x / 2;
            let state_str = match &self.leaves[leaf_idx] {
                LeafState::Blank => "blank",
                LeafState::Occupied => "occ",
            };
            writeln!(f, "{}{}leaf[{}] [{}]", prefix, connector, leaf_idx, state_str)
        } else {
            // ── Parent node ────────────────────────────────────────────────
            let k = x / 2;
            let is_root = connector.is_empty();
            let node_label = if is_root {
                "root".to_string()
            } else {
                format!("tree[{}]", x)
            };
            let state_str = Self::fmt_parent_state(&self.parents[k]);
            writeln!(f, "{}{}{} [{}]", prefix, connector, node_label, state_str)?;

            // Child prefix: extend by one column based on whether this node
            // continues a sibling sequence.
            let child_prefix = if is_root {
                prefix.to_string()
            } else if connector == "└── " {
                format!("{}    ", prefix)
            } else {
                format!("{}│   ", prefix)
            };

            let left = Self::left_child(x);
            let right = Self::right_child(x, n);

            self.fmt_node(f, left, &child_prefix, "├── ")?;
            self.fmt_node(f, right, &child_prefix, "└── ")
        }
    }
}

impl fmt::Display for TreeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.leaves.len();
        writeln!(f, "TreeState ({} leaves):", n)?;
        if n == 0 {
            return Ok(());
        }
        let root = Self::root_index(n);
        self.fmt_node(f, root, "", "")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(occ: bool) -> LeafState {
        if occ {
            LeafState::Occupied
        } else {
            LeafState::Blank
        }
    }

    fn parent_blank() -> ParentState {
        ParentState::Blank
    }

    fn parent_occ(unmerged: &[u32]) -> ParentState {
        ParentState::Occupied {
            unmerged_leaves: unmerged.iter().copied().map(LeafIndex).collect(),
        }
    }

    // ── root_index ────────────────────────────────────────────────────────

    #[test]
    fn root_index_powers_of_two() {
        // n=2: width=3, floor_log2=1, root=1
        assert_eq!(TreeState::root_index(2), 1);
        // n=4: width=7, floor_log2=2, root=3
        assert_eq!(TreeState::root_index(4), 3);
        // n=8: width=15, floor_log2=3, root=7
        assert_eq!(TreeState::root_index(8), 7);
    }

    #[test]
    fn root_index_non_power_of_two() {
        // n=3: width=5, floor_log2=2, root=3
        assert_eq!(TreeState::root_index(3), 3);
        // n=5: width=9, floor_log2=3, root=7
        assert_eq!(TreeState::root_index(5), 7);
        // n=6: width=11, floor_log2=3, root=7
        assert_eq!(TreeState::root_index(6), 7);
    }

    #[test]
    fn root_index_one_leaf() {
        assert_eq!(TreeState::root_index(1), 0);
    }

    // ── right_child ───────────────────────────────────────────────────────

    #[test]
    fn right_child_perfect_tree() {
        // 4-leaf tree: right(3) = 5, right(1) = 2, right(5) = 6
        assert_eq!(TreeState::right_child(3, 4), 5);
        assert_eq!(TreeState::right_child(1, 4), 2);
        assert_eq!(TreeState::right_child(5, 4), 6);
    }

    #[test]
    fn right_child_non_power_of_two() {
        // 3-leaf tree (width=5): right(3) would be 5 (out of bounds) → descend → 4
        assert_eq!(TreeState::right_child(3, 3), 4);
        // 5-leaf tree (width=9): right(7) would be 11 (out of bounds) → descend → 8
        assert_eq!(TreeState::right_child(7, 5), 8);
    }

    // ── new() panics ──────────────────────────────────────────────────────

    #[test]
    #[should_panic]
    fn new_wrong_parent_count() {
        TreeState::new(vec![leaf(true), leaf(true)], vec![]); // 2 leaves needs 1 parent
    }

    // ── Display ───────────────────────────────────────────────────────────

    #[test]
    fn display_single_leaf() {
        let t = TreeState::new(vec![leaf(true)], vec![]);
        let s = t.to_string();
        assert!(s.contains("leaf[0] [occ]"), "got: {s}");
    }

    #[test]
    fn display_two_leaves() {
        let t = TreeState::new(vec![leaf(true), leaf(false)], vec![parent_blank()]);
        let s = t.to_string();
        assert!(s.contains("root [blank]"), "got: {s}");
        assert!(s.contains("leaf[0] [occ]"), "got: {s}");
        assert!(s.contains("leaf[1] [blank]"), "got: {s}");
    }

    #[test]
    fn display_four_leaves() {
        // leaf[2] is unmerged at tree[5] and propagates up to the root.
        let t = TreeState::new(
            vec![leaf(true); 4],
            vec![parent_blank(), parent_occ(&[2]), parent_occ(&[2])],
        );
        let s = t.to_string();
        // Root is parents[1] (tree[3])
        assert!(s.contains("root [occ, unmerged=[2]]"), "got: {s}");
        // Left child of root is parents[0] (tree[1])
        assert!(s.contains("tree[1] [blank]"), "got: {s}");
        // Right child of root is parents[2] (tree[5])
        assert!(s.contains("tree[5] [occ, unmerged=[2]]"), "got: {s}");
        // All four leaves
        for i in 0..4 {
            assert!(s.contains(&format!("leaf[{i}] [occ]")), "got: {s}");
        }
    }

    #[test]
    fn display_three_leaves_lbbt() {
        // 3-leaf LBBT: root at tree[3], left subtree is tree[1] (parent of
        // leaf[0] and leaf[1]), right subtree is leaf[2] directly.
        let t = TreeState::new(
            vec![leaf(true), leaf(true), leaf(true)],
            vec![parent_occ(&[]), parent_blank()], // tree[1], tree[3]=root
        );
        let s = t.to_string();
        assert!(s.contains("root [blank]"), "got: {s}");
        assert!(s.contains("tree[1] [occ, unmerged=[]]"), "got: {s}");
        assert!(s.contains("leaf[0]"), "got: {s}");
        assert!(s.contains("leaf[1]"), "got: {s}");
        // leaf[2] is the direct right child of the root
        assert!(s.contains("leaf[2]"), "got: {s}");
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    #[test]
    fn leaf_state_accessor() {
        let t = TreeState::new(
            vec![leaf(true), leaf(false)],
            vec![parent_blank()],
        );
        assert_eq!(t.leaf_state(LeafIndex(0)), &LeafState::Occupied);
        assert_eq!(t.leaf_state(LeafIndex(1)), &LeafState::Blank);
    }

    #[test]
    fn parent_state_accessor() {
        let t = TreeState::new(
            vec![leaf(true), leaf(true), leaf(true), leaf(true)],
            vec![parent_blank(), parent_occ(&[1]), parent_occ(&[])],
        );
        assert_eq!(t.parent_state(0), &parent_blank());
        assert_eq!(t.parent_state(1), &parent_occ(&[1]));
        assert_eq!(t.parent_state(2), &parent_occ(&[]));
    }

    #[test]
    fn leaves_iterator() {
        let t = TreeState::new(vec![leaf(true), leaf(false)], vec![parent_blank()]);
        let pairs: Vec<_> = t.leaves().collect();
        assert_eq!(pairs[0].0, LeafIndex(0));
        assert_eq!(pairs[0].1, &LeafState::Occupied);
        assert_eq!(pairs[1].0, LeafIndex(1));
        assert_eq!(pairs[1].1, &LeafState::Blank);
    }

    #[test]
    fn parents_iterator() {
        let t = TreeState::new(
            vec![leaf(true), leaf(true)],
            vec![parent_occ(&[1])],
        );
        let pairs: Vec<_> = t.parents().collect();
        // k=0 → tree-node index 1
        assert_eq!(pairs[0].0, 1);
    }
}
