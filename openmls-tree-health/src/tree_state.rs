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

// ── Commit simulation result ──────────────────────────────────────────────────

/// Per-leaf cost information returned by [`TreeState::simulate_all_commits`].
#[derive(Debug, Clone)]
pub struct CommitInfo {
    /// The candidate committer.
    pub leaf: LeafIndex,
    /// Number of HPKE ciphertexts this commit would produce.
    pub commit_size: usize,
    /// Commit cost for every occupied leaf in the resulting tree (in
    /// leaf-index order), showing how expensive each next-round commit
    /// would be after this leaf commits.
    pub next_commit_sizes: Vec<(LeafIndex, usize)>,
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

    // ── Resolution and commit size ────────────────────────────────────────

    /// Resolution size of tree-node `x`.
    ///
    /// The resolution of a node is the set of nodes that can decrypt a secret
    /// encrypted to it (RFC 9420 §7.7):
    ///
    /// - Blank leaf → 0 (no member, nothing to encrypt to).
    /// - Occupied leaf → 1.
    /// - Blank parent → recursive sum over children.
    /// - Occupied parent → 1 (the node itself) + number of unmerged leaves.
    fn resolution_size(&self, x: usize) -> usize {
        if x % 2 == 0 {
            // Leaf node: tree index x = 2 * leaf_index.
            match &self.leaves[x / 2] {
                LeafState::Blank => 0,
                LeafState::Occupied => 1,
            }
        } else {
            // Parent node: parents[k] at tree-node index 2k+1, so k = x/2.
            let n = self.leaves.len();
            match &self.parents[x / 2] {
                ParentState::Blank => {
                    let left = Self::left_child(x);
                    let right = Self::right_child(x, n);
                    self.resolution_size(left) + self.resolution_size(right)
                }
                ParentState::Occupied { unmerged_leaves } => 1 + unmerged_leaves.len(),
            }
        }
    }

    /// Number of HPKE ciphertexts a commit from `leaf` would produce.
    ///
    /// When a leaf commits with an UpdatePath it encrypts a path secret to the
    /// **resolution** of each node on its **co-path** — the sibling of each
    /// node on the direct path from `leaf` up to, but not including, the root
    /// (the root has no sibling).  The total commit size is the sum of those
    /// resolution sizes.
    ///
    /// A smaller value means the commit is cheaper to produce and to process
    /// for every other group member.
    ///
    /// # Panics
    ///
    /// Panics if `leaf.0 >= self.num_leaves() as u32`.
    pub fn commit_size(&self, leaf: LeafIndex) -> usize {
        let n = self.leaves.len();
        assert!(
            (leaf.0 as usize) < n,
            "leaf index {} out of range (tree has {} leaves)",
            leaf.0,
            n,
        );
        if n <= 1 {
            return 0;
        }

        // Walk the direct path top-down from the root.  At each parent node x:
        //   - if leaf_tree_idx < x the leaf is in the left subtree  → co-path node is the right child
        //   - if leaf_tree_idx > x the leaf is in the right subtree → co-path node is the left child
        // Stop once we find the direct child that equals the leaf itself.
        //
        // This avoids the parent() formula, which is only correct for perfect
        // binary trees and breaks for non-power-of-2 leaf counts.
        let leaf_tree_idx = leaf.0 as usize * 2;
        let mut total = 0;
        let mut x = Self::root_index(n);

        loop {
            let left = Self::left_child(x);
            let right = Self::right_child(x, n);

            if leaf_tree_idx < x {
                // Leaf is in the left subtree; co-path node is the right child.
                total += self.resolution_size(right);
                if left == leaf_tree_idx {
                    break;
                }
                x = left;
            } else {
                // Leaf is in the right subtree; co-path node is the left child.
                total += self.resolution_size(left);
                if right == leaf_tree_idx {
                    break;
                }
                x = right;
            }
        }

        total
    }

    // ── Subtree membership ────────────────────────────────────────────────

    /// Returns `true` if `target` is a node in the subtree rooted at
    /// `subtree_root` in a tree with `n_leaves` leaf slots.
    ///
    /// Walks from `subtree_root` toward `target` using the child formulas;
    /// hits a leaf and stops when no further descent is possible.
    fn is_in_subtree(target: usize, subtree_root: usize, n_leaves: usize) -> bool {
        let mut x = subtree_root;
        loop {
            if x == target {
                return true;
            }
            let level = Self::level(x);
            if level == 0 {
                return false; // hit a leaf that is not the target
            }
            let left = Self::left_child(x);
            let right = Self::right_child(x, n_leaves);
            x = if target < x { left } else { right };
        }
    }

    // ── Proposal application and commit simulation ────────────────────────

    /// Apply Remove and Add proposals and return the resulting tree state as
    /// seen **before** any committer's UpdatePath.
    ///
    /// - Removed leaves → `Blank`.
    /// - Any parent node whose subtree contains a removed leaf → `Blank`
    ///   (RFC 9420 §8.4: removing a leaf blanks its entire direct path).
    /// - Occupied parents not affected by a remove: `removes` are filtered
    ///   from their unmerged list; `adds` that fall inside their subtree are
    ///   appended.
    /// - Added leaves → `Occupied`.
    /// - Already-blank parents stay `Blank` (blank nodes have no key material
    ///   to update, and adds do not implicitly re-key them).
    ///
    /// All leaf indices in `removes` and `adds` must be in `0..self.num_leaves()`.
    fn apply_proposals(&self, removes: &[LeafIndex], adds: &[LeafIndex]) -> TreeState {
        let n = self.leaves.len();

        let new_leaves = self
            .leaves
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let idx = LeafIndex(i as u32);
                if removes.contains(&idx) {
                    LeafState::Blank
                } else if adds.contains(&idx) {
                    LeafState::Occupied
                } else {
                    s.clone()
                }
            })
            .collect();

        let new_parents = (0..n.saturating_sub(1))
            .map(|k| {
                let tree_idx = 2 * k + 1;
                if removes
                    .iter()
                    .any(|r| Self::is_in_subtree(r.0 as usize * 2, tree_idx, n))
                {
                    // A removed leaf's direct path passes through this node.
                    ParentState::Blank
                } else {
                    match &self.parents[k] {
                        ParentState::Blank => ParentState::Blank,
                        ParentState::Occupied { unmerged_leaves } => {
                            let mut new_unmerged: Vec<LeafIndex> = unmerged_leaves
                                .iter()
                                .filter(|ul| !removes.contains(ul))
                                .copied()
                                .collect();
                            for &a in adds {
                                if Self::is_in_subtree(a.0 as usize * 2, tree_idx, n) {
                                    new_unmerged.push(a);
                                }
                            }
                            ParentState::Occupied {
                                unmerged_leaves: new_unmerged,
                            }
                        }
                    }
                }
            })
            .collect();

        TreeState {
            leaves: new_leaves,
            parents: new_parents,
        }
    }

    /// Apply one committer's UpdatePath on top of an intermediate tree state
    /// (the output of [`apply_proposals`]) and return the fully projected
    /// post-commit tree.
    ///
    /// Every parent on `committer`'s direct path is set to `Occupied`; its
    /// `unmerged_leaves` becomes the subset of `adds` that lie inside that
    /// node's subtree.  All other nodes are taken from `intermediate` unchanged.
    fn simulate_commit(
        intermediate: &TreeState,
        committer: LeafIndex,
        adds: &[LeafIndex],
    ) -> TreeState {
        let n = intermediate.leaves.len();
        if n <= 1 {
            return intermediate.clone();
        }

        let mut new_parents = intermediate.parents.clone();
        let root = Self::root_index(n);
        let committer_tree_idx = committer.0 as usize * 2;
        let mut x = root;

        loop {
            // x is a parent node on committer's direct path — re-key it.
            let k = x / 2;
            new_parents[k] = ParentState::Occupied {
                unmerged_leaves: adds
                    .iter()
                    .filter(|&&a| Self::is_in_subtree(a.0 as usize * 2, x, n))
                    .copied()
                    .collect(),
            };

            let left = Self::left_child(x);
            let right = Self::right_child(x, n);

            if committer_tree_idx < x {
                if left == committer_tree_idx {
                    break;
                }
                x = left;
            } else {
                if right == committer_tree_idx {
                    break;
                }
                x = right;
            }
        }

        TreeState {
            leaves: intermediate.leaves.clone(),
            parents: new_parents,
        }
    }

    /// Simulate a commit from every eligible leaf and return the per-leaf costs.
    ///
    /// An *eligible* committer is any currently-occupied leaf that is not in
    /// `removes`.  For each eligible leaf the function returns a [`CommitInfo`]
    /// containing:
    ///
    /// - Its **commit size** — the total number of HPKE ciphertexts the commit
    ///   would produce (sum of co-path resolution sizes in the tree after
    ///   proposals are applied but before the UpdatePath).
    ///
    /// - The **next-round commit sizes** — for every leaf that would be
    ///   occupied in the resulting tree (after the commit and proposals), the
    ///   cost of *their* commit in that resulting tree (with no further
    ///   proposals).
    ///
    /// The two-level view lets you answer "who should commit now *and* what
    /// does the tree look like for the next round?" in a single pass.
    ///
    /// All leaf indices in `removes` and `adds` must be in `0..self.num_leaves()`.
    pub fn simulate_all_commits(
        &self,
        removes: &[LeafIndex],
        adds: &[LeafIndex],
    ) -> Vec<CommitInfo> {
        // Build the shared intermediate state once: proposals applied, no
        // UpdatePath yet.  Every candidate committer's commit_size is evaluated
        // against this state.
        let intermediate = self.apply_proposals(removes, adds);

        self.leaves()
            .filter(|(idx, state)| matches!(state, LeafState::Occupied) && !removes.contains(idx))
            .map(|(leaf, _)| {
                let commit_size = intermediate.commit_size(leaf);

                // Project the full post-commit tree for this specific committer.
                let resulting = Self::simulate_commit(&intermediate, leaf, adds);

                let next_commit_sizes = resulting
                    .leaves()
                    .filter(|(_, state)| matches!(state, LeafState::Occupied))
                    .map(|(next_leaf, _)| (next_leaf, resulting.commit_size(next_leaf)))
                    .collect();

                CommitInfo {
                    leaf,
                    commit_size,
                    next_commit_sizes,
                }
            })
            .collect()
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

    // ── commit_size ───────────────────────────────────────────────────────

    /// Fully merged 4-leaf tree: every leaf sends exactly 2 ciphertexts.
    ///
    /// Tree topology:
    /// ```text
    ///         root [occ, u=[]]
    ///         /              \
    ///     tree[1] [occ, u=[]]   tree[5] [occ, u=[]]
    ///     /    \               /    \
    /// leaf[0] leaf[1]     leaf[2] leaf[3]
    /// ```
    /// Leaf 0 co-path: [leaf[1] (res=1), tree[5] (res=1)] → 2
    /// Leaf 2 co-path: [leaf[3] (res=1), tree[1] (res=1)] → 2
    #[test]
    fn commit_size_fully_merged_4_leaves() {
        let t = TreeState::new(
            vec![leaf(true); 4],
            vec![parent_occ(&[]), parent_occ(&[]), parent_occ(&[])],
        );
        for i in 0..4u32 {
            assert_eq!(t.commit_size(LeafIndex(i)), 2, "leaf {i}");
        }
    }

    /// Blank sibling: the blank leaf contributes 0 to its parent's resolution,
    /// so when the blank parent itself is the co-path node we recurse into the
    /// occupied children.
    ///
    /// Leaf[1] is blank, tree[1] is blank (no key set because leaf[1] is gone).
    /// Leaf[2] co-path: [leaf[3] (res=1), tree[1] → recurse → leaf[0](1) + leaf[1](0) = 1] → 2
    /// Leaf[0] co-path: [leaf[1](0), tree[5](res=1)] → 1
    #[test]
    fn commit_size_blank_leaf_and_parent() {
        let t = TreeState::new(
            vec![leaf(true), leaf(false), leaf(true), leaf(true)],
            //   tree[1]=blank   tree[3]=root occ  tree[5]=occ
            vec![parent_blank(), parent_occ(&[]), parent_occ(&[])],
        );
        assert_eq!(t.commit_size(LeafIndex(0)), 1); // co-path: leaf[1](0) + tree[5](1)
        assert_eq!(t.commit_size(LeafIndex(2)), 2); // co-path: leaf[3](1) + tree[1]→1+0=1
        assert_eq!(t.commit_size(LeafIndex(3)), 2); // co-path: leaf[2](1) + tree[1]→1
    }

    /// Unmerged leaves inflate the root's resolution.
    ///
    /// leaf[2] is unmerged at tree[5] and at the root (both have u=[2]).
    /// Leaf[0] co-path: [leaf[1](1), tree[5](1+1=2)] → 3
    /// Leaf[2] co-path: [leaf[3](1), tree[1](1)] → 2   (leaf[2] is NOT in tree[1]'s unmerged list)
    #[test]
    fn commit_size_with_unmerged_leaves() {
        let t = TreeState::new(
            vec![leaf(true); 4],
            vec![
                parent_occ(&[]),   // tree[1]: no unmerged
                parent_occ(&[2]),  // tree[3]=root: leaf[2] unmerged
                parent_occ(&[2]),  // tree[5]: leaf[2] unmerged
            ],
        );
        // Leaf[0]: co-path = [leaf[1](1), tree[5](1+1=2)] → 3
        assert_eq!(t.commit_size(LeafIndex(0)), 3);
        // Leaf[1]: co-path = [leaf[0](1), tree[5](2)] → 3
        assert_eq!(t.commit_size(LeafIndex(1)), 3);
        // Leaf[2]: co-path = [leaf[3](1), tree[1](1+0=1)] → 2
        assert_eq!(t.commit_size(LeafIndex(2)), 2);
        // Leaf[3]: co-path = [leaf[2](1), tree[1](1)] → 2
        assert_eq!(t.commit_size(LeafIndex(3)), 2);
    }

    /// Single-leaf tree: no path, no ciphertexts.
    #[test]
    fn commit_size_single_leaf() {
        let t = TreeState::new(vec![leaf(true)], vec![]);
        assert_eq!(t.commit_size(LeafIndex(0)), 0);
    }

    /// Two-leaf tree: one ciphertext in each direction.
    #[test]
    fn commit_size_two_leaves() {
        let t = TreeState::new(vec![leaf(true), leaf(true)], vec![parent_occ(&[])]);
        assert_eq!(t.commit_size(LeafIndex(0)), 1);
        assert_eq!(t.commit_size(LeafIndex(1)), 1);
    }

    /// Non-power-of-2 tree (3 leaves, LBBT):
    /// ```text
    ///       root [tree[3]]
    ///      /            \
    ///  tree[1]         leaf[2]   ← right child of root is a leaf
    ///  /    \
    /// leaf[0] leaf[1]
    /// ```
    /// Leaf[0] co-path: [leaf[1](1), leaf[2](1)] → 2
    /// Leaf[2] co-path: [tree[1](1)] → 1
    #[test]
    fn commit_size_three_leaves_lbbt() {
        let t = TreeState::new(
            vec![leaf(true), leaf(true), leaf(true)],
            vec![parent_occ(&[]), parent_occ(&[])], // tree[1], tree[3]=root
        );
        assert_eq!(t.commit_size(LeafIndex(0)), 2);
        assert_eq!(t.commit_size(LeafIndex(1)), 2);
        assert_eq!(t.commit_size(LeafIndex(2)), 1);
    }

    // ── is_in_subtree ─────────────────────────────────────────────────────

    #[test]
    fn subtree_perfect_tree() {
        // 4-leaf tree: tree[1] spans leaves 0-1 (tree nodes 0,1,2)
        assert!(TreeState::is_in_subtree(0, 1, 4)); // leaf[0] in tree[1]
        assert!(TreeState::is_in_subtree(2, 1, 4)); // leaf[1] in tree[1]
        assert!(!TreeState::is_in_subtree(4, 1, 4)); // leaf[2] NOT in tree[1]
        assert!(!TreeState::is_in_subtree(6, 1, 4)); // leaf[3] NOT in tree[1]
        assert!(TreeState::is_in_subtree(1, 1, 4)); // root of subtree itself
        // tree[3] (root) spans everything
        for x in [0usize, 1, 2, 3, 4, 5, 6] {
            assert!(TreeState::is_in_subtree(x, 3, 4), "node {x} should be in root's subtree");
        }
    }

    #[test]
    fn subtree_lbbt() {
        // 3-leaf tree: right child of root is leaf[2] at tree index 4
        assert!(TreeState::is_in_subtree(4, 3, 3)); // leaf[2] in root
        assert!(!TreeState::is_in_subtree(4, 1, 3)); // leaf[2] NOT in tree[1]
    }

    // ── simulate_all_commits ──────────────────────────────────────────────

    /// Fully merged 4-leaf tree, no proposals: every leaf costs 2, and after
    /// any commit the tree remains fully merged so every next-round leaf also
    /// costs 2.
    #[test]
    fn simulate_no_proposals_fully_merged() {
        let t = TreeState::new(
            vec![leaf(true); 4],
            vec![parent_occ(&[]), parent_occ(&[]), parent_occ(&[])],
        );
        let infos = t.simulate_all_commits(&[], &[]);
        assert_eq!(infos.len(), 4);
        for info in &infos {
            assert_eq!(info.commit_size, 2, "leaf {:?}", info.leaf);
            assert_eq!(info.next_commit_sizes.len(), 4);
            for &(_, sz) in &info.next_commit_sizes {
                assert_eq!(sz, 2);
            }
        }
    }

    /// Remove leaf[1]: the sibling slot of leaf[0] goes blank.
    ///
    /// Leaf[0] co-path after remove: [leaf[1](res=0), tree[5](res=1)] → cost 1.
    /// Leaf[2] and leaf[3] co-path: [sibling leaf(1), tree[1](blank→resolves
    /// to leaf[0](1)+leaf[1](0)=1)] → cost 2.
    ///
    /// After leaf[0] commits it re-keys tree[1], so it is occupied again.
    /// Next-round costs: leaf[0]=1 (sibling still blank), leaf[2]=2, leaf[3]=2.
    ///
    /// After leaf[2] or leaf[3] commit they re-key tree[5] but tree[1] stays
    /// blank.  Next-round costs: leaf[0]=1, leaf[2]=2, leaf[3]=2 (unchanged).
    #[test]
    fn simulate_remove_sibling() {
        let t = TreeState::new(
            vec![leaf(true); 4],
            vec![parent_occ(&[]), parent_occ(&[]), parent_occ(&[])],
        );
        let infos = t.simulate_all_commits(&[LeafIndex(1)], &[]);

        // Only leaves 0, 2, 3 are eligible (leaf[1] is being removed).
        assert_eq!(infos.len(), 3);
        let by_leaf: std::collections::HashMap<u32, &CommitInfo> =
            infos.iter().map(|i| (i.leaf.0, i)).collect();

        assert_eq!(by_leaf[&0].commit_size, 1);
        assert_eq!(by_leaf[&2].commit_size, 2);
        assert_eq!(by_leaf[&3].commit_size, 2);

        // After leaf[0] commits: tree[1] is re-keyed (occupied, unmerged=[]).
        // Remaining leaves: 0, 2, 3.
        let next0: std::collections::HashMap<u32, usize> = by_leaf[&0]
            .next_commit_sizes
            .iter()
            .map(|&(l, s)| (l.0, s))
            .collect();
        assert_eq!(next0[&0], 1); // leaf[0]: sibling still blank, tree[5] occ → 1
        assert_eq!(next0[&2], 2); // leaf[2]: leaf[3](1) + tree[1](1) → 2
        assert_eq!(next0[&3], 2);

        // After leaf[2] commits: tree[5] re-keyed, tree[1] still blank.
        let next2: std::collections::HashMap<u32, usize> = by_leaf[&2]
            .next_commit_sizes
            .iter()
            .map(|&(l, s)| (l.0, s))
            .collect();
        assert_eq!(next2[&0], 1);
        assert_eq!(next2[&2], 2);
        assert_eq!(next2[&3], 2);
    }

    /// Add leaf[1] to a tree where that slot is blank.
    ///
    /// Starting state: leaf[1]=blank, tree[1]=blank, tree[3]=occ(u=[]),
    /// tree[5]=occ(u=[]).
    ///
    /// After applying add=[1]:
    ///   leaf[1]=occ; tree[1] stays blank (was blank, adds don't un-blank);
    ///   tree[3] gains leaf[1] in its unmerged list → occ(u=[1]);
    ///   tree[5]: leaf[1] is NOT in tree[5]'s subtree → unchanged occ(u=[]).
    ///
    /// Leaf[0] commit size: co-path=[leaf[1](1), tree[5](1)] → 2.
    /// After leaf[0] commits: tree[1] re-keyed with unmerged=[1] (leaf[1]
    /// is in tree[1]'s subtree); tree[3] re-keyed with unmerged=[1].
    /// Next-round costs: leaf[0]=2, leaf[1]=2, leaf[2]=3, leaf[3]=3.
    /// (leaf[2]/leaf[3] co-path includes tree[1] which has unmerged=[1] →
    /// resolution 2 instead of 1.)
    ///
    /// Leaf[2] commit size: co-path=[leaf[3](1), tree[1](blank→leaf[0](1)
    /// +leaf[1](1)=2)] → 3.
    #[test]
    fn simulate_add_to_blank_slot() {
        let t = TreeState::new(
            vec![leaf(true), leaf(false), leaf(true), leaf(true)],
            vec![parent_blank(), parent_occ(&[]), parent_occ(&[])],
        );
        let infos = t.simulate_all_commits(&[], &[LeafIndex(1)]);

        // Eligible committers: leaves 0, 2, 3 (leaf[1] is being added, not yet occupied).
        assert_eq!(infos.len(), 3);
        let by_leaf: std::collections::HashMap<u32, &CommitInfo> =
            infos.iter().map(|i| (i.leaf.0, i)).collect();

        assert_eq!(by_leaf[&0].commit_size, 2);
        assert_eq!(by_leaf[&2].commit_size, 3);
        assert_eq!(by_leaf[&3].commit_size, 3);

        // After leaf[0] commits with add=[1]: four occupied leaves remain.
        let next0: std::collections::HashMap<u32, usize> = by_leaf[&0]
            .next_commit_sizes
            .iter()
            .map(|&(l, s)| (l.0, s))
            .collect();
        assert_eq!(next0.len(), 4);
        assert_eq!(next0[&0], 2);
        assert_eq!(next0[&1], 2);
        assert_eq!(next0[&2], 3); // tree[1] now has unmerged=[1] → res=2
        assert_eq!(next0[&3], 3);
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
