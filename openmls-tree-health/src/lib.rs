use openmls::prelude::LeafNodeIndex;
use std::cmp::Ordering;

/// Find leaves that are the best candidates for a self-update commit after
/// `removed` was removed from the group.
///
/// When a leaf is removed, the path from it to the root is blanked, degrading
/// tree efficiency. A self-update from a nearby leaf re-keys that shared path.
/// This function returns the leaf indices that are **closest** to `removed` in
/// the tree topology, measured by `(index XOR removed).leading_zeros()`.
///
/// **Typical usage:**
/// ```ignore
/// let candidates = find_self_update_candidates(
///     removed_index,
///     group.treesync().full_leaves().map(|(idx, _)| idx),
/// );
/// ```
///
/// `removed` must not appear in `leaves`; it is filtered out defensively.
pub fn find_self_update_candidates(
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
        let result = find_self_update_candidates(idx(0), leaves);
        assert_eq!(result, vec![idx(1)]);
    }

    // remove=2: 2^3=1 → lz=31, 2^0=2 → lz=30, 2^1=3 → lz=30 → closest is leaf 3
    #[test]
    fn four_leaf_remove_third() {
        let leaves = [idx(0), idx(1), idx(3)].into_iter();
        let result = find_self_update_candidates(idx(2), leaves);
        assert_eq!(result, vec![idx(3)]);
    }

    // remove rightmost leaf (3): 3^2=1 → lz=31 → candidate is leaf 2
    #[test]
    fn remove_rightmost() {
        let leaves = [idx(0), idx(1), idx(2)].into_iter();
        let result = find_self_update_candidates(idx(3), leaves);
        assert_eq!(result, vec![idx(2)]);
    }

    // Empty iterator → empty result
    #[test]
    fn empty_leaves() {
        let result = find_self_update_candidates(idx(0), std::iter::empty());
        assert!(result.is_empty());
    }

    // Single remaining leaf → returns that leaf
    #[test]
    fn single_remaining_leaf() {
        let result = find_self_update_candidates(idx(0), [idx(1)].into_iter());
        assert_eq!(result, vec![idx(1)]);
    }

    // Defensive: if removed appears in leaves it is filtered out
    #[test]
    fn removed_filtered_out() {
        let leaves = [idx(0), idx(1), idx(2)].into_iter();
        let result = find_self_update_candidates(idx(0), leaves);
        assert!(!result.contains(&idx(0)));
    }
}
