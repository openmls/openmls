pub mod tree_state;

use openmls::prelude::LeafNodeIndex;
use std::cmp::Ordering;

/// Find the leaves best placed to re-key the path blanked by removing `removed`.
///
/// When a leaf is removed its direct path to the root is blanked, degrading
/// tree efficiency. Any member who sends a commit with an `update_path` that
/// passes through that blanked region restores it. The closer a leaf is to
/// `removed` in the tree topology, the more of the blanked path their
/// `update_path` covers.
///
/// This function returns the leaf index (or indices, in case of a tie) of the
/// member(s) best placed to do so, measured by
/// `(index XOR removed).leading_zeros()` — more leading zeros means the two
/// leaves share a deeper common subtree.
///
/// Two natural uses:
/// - **Pick who should commit the Remove** — call before the Remove commit is
///   issued; the chosen member's mandatory `update_path` re-keys the shared
///   path in the same commit, at no extra cost.
/// - **Pick who should self-update after the Remove** — call after the Remove
///   commit has been applied; the chosen member sends a follow-up commit whose
///   `update_path` re-keys the now-blank region.
///
/// ```ignore
/// let candidates = find_update_candidates(
///     leaf_to_remove,
///     group.treesync().full_leaves().map(|(idx, _)| idx),
/// );
/// ```
///
/// `removed` is filtered out defensively if it appears in `leaves`, so the
/// function may be called before or after the Remove has been applied.
pub fn find_update_candidates(
    removed: LeafNodeIndex,
    leaves: impl Iterator<Item = LeafNodeIndex>,
) -> Vec<LeafNodeIndex> {
    leaves
        .filter(|&idx| idx != removed)
        .map(|idx| ((idx.u32() ^ removed.u32()).leading_zeros(), idx))
        .fold(
            (0u32, Vec::new()),
            |(max_dist, mut acc), (dist, idx)| match dist.cmp(&max_dist) {
                Ordering::Greater => (dist, vec![idx]),
                Ordering::Equal => {
                    acc.push(idx);
                    (dist, acc)
                }
                Ordering::Less => (max_dist, acc),
            },
        )
        .1
}

/// Compute the root resolution size in a hypothetical state where `leaf` has
/// committed a self-update.
///
/// Uses a simplified model: only `leaf` is removed from the root's unmerged
/// leaves; other unmerged leaves remain. A smaller result means `leaf` is a
/// better self-update candidate.
///
/// `root_unmerged_leaves` is obtained from `group.treesync().root_unmerged_leaves()`.
///
/// Returns 1 when the root is blank (any self-update sets the root key with an
/// empty unmerged list).
pub fn hypothetical_root_resolution_size(
    leaf: LeafNodeIndex,
    root_unmerged_leaves: &[LeafNodeIndex],
) -> usize {
    let base = 1 + root_unmerged_leaves.len();
    if root_unmerged_leaves.contains(&leaf) {
        base - 1
    } else {
        base
    }
}

/// Project the root's unmerged-leaf list after a set of pending proposals.
///
/// Given the current `root_unmerged_leaves`, a slice of leaf indices that will
/// be **added** (`adds`), and a slice of leaf indices that will be **removed**
/// (`removes`), returns the unmerged-leaf list that the root will have once
/// those proposals are committed.
///
/// The projection rules follow the simplified model used by
/// [`hypothetical_root_resolution_size`]:
///
/// - Removed leaves are dropped from the current list (they leave the group).
/// - Added leaves are appended (they become unmerged at the root because the
///   committer's UpdatePath sets the root with the new members excluded from
///   the HPKE ciphertexts).
///
/// Pass the result to [`hypothetical_root_resolution_size`] for each candidate
/// committer to find who should issue the commit:
///
/// ```ignore
/// let projected = project_root_unmerged_leaves(
///     group.treesync().root_unmerged_leaves(),
///     &added_leaf_indices,
///     &removed_leaf_indices,
/// );
/// let best = group
///     .treesync()
///     .full_leaves()
///     .map(|(idx, _)| (idx, hypothetical_root_resolution_size(idx, &projected)))
///     .min_by_key(|&(_, size)| size);
/// ```
pub fn project_root_unmerged_leaves(
    current: &[LeafNodeIndex],
    adds: &[LeafNodeIndex],
    removes: &[LeafNodeIndex],
) -> Vec<LeafNodeIndex> {
    current
        .iter()
        .copied()
        .filter(|leaf| !removes.contains(leaf))
        .chain(adds.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx(n: u32) -> LeafNodeIndex {
        LeafNodeIndex::new(n)
    }

    // 4-leaf tree: leaves at indices 0, 1, 2, 3.
    // Topology: (0,1) share parent, (2,3) share parent, root covers all.
    //
    // remove=0: 0^1=1 → lz=31, 0^2=2 → lz=30, 0^3=3 → lz=30 → closest is leaf 1
    #[test]
    fn four_leaf_remove_first() {
        let leaves = [idx(1), idx(2), idx(3)].into_iter();
        let result = find_update_candidates(idx(0), leaves);
        assert_eq!(result, vec![idx(1)]);
    }

    // remove=2: 2^3=1 → lz=31, 2^0=2 → lz=30, 2^1=3 → lz=30 → closest is leaf 3
    #[test]
    fn four_leaf_remove_third() {
        let leaves = [idx(0), idx(1), idx(3)].into_iter();
        let result = find_update_candidates(idx(2), leaves);
        assert_eq!(result, vec![idx(3)]);
    }

    // remove rightmost leaf (3): 3^2=1 → lz=31 → candidate is leaf 2
    #[test]
    fn remove_rightmost() {
        let leaves = [idx(0), idx(1), idx(2)].into_iter();
        let result = find_update_candidates(idx(3), leaves);
        assert_eq!(result, vec![idx(2)]);
    }

    // Empty iterator → empty result
    #[test]
    fn empty_leaves() {
        let result = find_update_candidates(idx(0), std::iter::empty());
        assert!(result.is_empty());
    }

    // Single remaining leaf → returns that leaf
    #[test]
    fn single_remaining_leaf() {
        let result = find_update_candidates(idx(0), [idx(1)].into_iter());
        assert_eq!(result, vec![idx(1)]);
    }

    // Defensive: if removed appears in leaves it is filtered out
    #[test]
    fn removed_filtered_out() {
        let leaves = [idx(0), idx(1), idx(2)].into_iter();
        let result = find_update_candidates(idx(0), leaves);
        assert!(!result.contains(&idx(0)));
    }

    // hypothetical_root_resolution_size tests

    // Blank root (empty unmerged list): any leaf yields 1.
    #[test]
    fn hrrs_blank_root() {
        assert_eq!(hypothetical_root_resolution_size(idx(0), &[]), 1);
        assert_eq!(hypothetical_root_resolution_size(idx(5), &[]), 1);
    }

    // Leaf is in the unmerged list: base=3, result=2.
    #[test]
    fn hrrs_leaf_in_unmerged() {
        let unmerged = [idx(1), idx(2)];
        assert_eq!(hypothetical_root_resolution_size(idx(1), &unmerged), 2);
    }

    // Leaf is not in the unmerged list: base=3, result=3.
    #[test]
    fn hrrs_leaf_not_in_unmerged() {
        let unmerged = [idx(1), idx(2)];
        assert_eq!(hypothetical_root_resolution_size(idx(0), &unmerged), 3);
    }

    // Single-element list, queried with the same leaf: base=2, result=1.
    #[test]
    fn hrrs_single_element_match() {
        assert_eq!(hypothetical_root_resolution_size(idx(0), &[idx(0)]), 1);
    }

    // Single-element list, queried with a different leaf: base=2, result=2.
    #[test]
    fn hrrs_single_element_no_match() {
        assert_eq!(hypothetical_root_resolution_size(idx(1), &[idx(0)]), 2);
    }

    // project_root_unmerged_leaves tests

    // No proposals: list is unchanged.
    #[test]
    fn project_no_proposals() {
        let current = [idx(1), idx(2)];
        let result = project_root_unmerged_leaves(&current, &[], &[]);
        assert_eq!(result, vec![idx(1), idx(2)]);
    }

    // Remove a leaf that is in the unmerged list.
    #[test]
    fn project_remove_unmerged() {
        let current = [idx(1), idx(2)];
        let result = project_root_unmerged_leaves(&current, &[], &[idx(1)]);
        assert_eq!(result, vec![idx(2)]);
    }

    // Remove a leaf that is NOT in the unmerged list: list is unchanged.
    #[test]
    fn project_remove_non_unmerged() {
        let current = [idx(1), idx(2)];
        let result = project_root_unmerged_leaves(&current, &[], &[idx(0)]);
        assert_eq!(result, vec![idx(1), idx(2)]);
    }

    // Add new leaves: they are appended.
    #[test]
    fn project_add() {
        let current = [idx(0)];
        let result = project_root_unmerged_leaves(&current, &[idx(3), idx(4)], &[]);
        assert_eq!(result, vec![idx(0), idx(3), idx(4)]);
    }

    // Combined: remove one existing unmerged leaf, add two new ones.
    #[test]
    fn project_add_and_remove() {
        let current = [idx(1), idx(2)];
        let result = project_root_unmerged_leaves(&current, &[idx(5), idx(6)], &[idx(1)]);
        assert_eq!(result, vec![idx(2), idx(5), idx(6)]);
    }
}
