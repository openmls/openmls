# openmls-tree-health

Tree maintenance helpers for [OpenMLS](https://github.com/openmls/openmls) groups.

## Background

MLS groups can degrade in efficiency over time. After Add and Remove operations,
unmerged leaves accumulate on parent nodes, growing resolution sizes. This makes
commits more expensive (more HPKE ciphertexts).

When a leaf is removed its direct path to the root is blanked, degrading tree
efficiency. Any member who sends a commit with an `update_path` through that
region restores it. The closer a leaf is to the removed slot in the tree
topology, the more of the blanked path their `update_path` covers.

When a leaf is added it is listed as unmerged on its non-blank ancestor nodes.
The resolution of a node (RFC 9420 §4.1.1) includes all its unmerged leaves, so
each unmerged entry adds one extra HPKE ciphertext to commits. A self-update by
the newly added member removes it from those lists.

This crate provides two tools for managing this:

- **`find_update_candidates`** — a lightweight heuristic that identifies which
  leaf is structurally closest to a removed slot and therefore best placed to
  re-key the blanked path.
- **`TreeState`** — a full tree-state model that snapshots every node's
  blank/occupied status and unmerged-leaf lists, then computes exact commit
  costs and projects the resulting tree for every possible committer.

## Usage

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
openmls-tree-health = "0.1.0"
```

### Picking who should commit a Remove

Call `find_update_candidates` with the leaf to be removed and an iterator over
the current (non-blank) leaves:

```rust
use openmls_tree_health::find_update_candidates;

let candidates = find_update_candidates(
    leaf_to_remove,
    group.treesync().full_leaves().map(|(idx, _)| idx),
);

// candidates contains the leaf index (or indices, in case of a tie) of the
// member(s) whose update_path best covers the path blanked by the removal.
```

The chosen member can commit the Remove (their mandatory `update_path` re-keys
the shared path at no extra cost), or — if the Remove was already committed by
someone else — send a follow-up self-update.

### Computing exact commit costs with TreeState

`find_update_candidates` uses only leaf indices. For a precise picture —
including how much each possible commit costs and what the tree looks like
afterwards — build a `TreeState` snapshot and call `simulate_all_commits`:

```rust
use openmls_tree_health::{LeafIndex, LeafState, ParentState, TreeState};

// Construct the snapshot. parents[k] sits at MLS tree-node index 2k+1.
let state = TreeState::new(
    vec![
        LeafState::Occupied,
        LeafState::Occupied,
        LeafState::Blank,    // removed member, slot kept
        LeafState::Occupied,
    ],
    vec![
        ParentState::Blank,                                             // tree[1]
        ParentState::Occupied { unmerged_leaves: vec![LeafIndex(2)] }, // tree[3] (root)
        ParentState::Occupied { unmerged_leaves: vec![] },             // tree[5]
    ],
);

let removes = vec![LeafIndex(1)];
let adds    = vec![];

let infos = state.simulate_all_commits(&removes, &adds);

// Find the cheapest committer for the current round.
let best = infos.iter().min_by_key(|i| i.commit_size).unwrap();
println!("commit leaf {:?} (cost {})", best.leaf, best.commit_size);

// Inspect what the tree looks like in the next round after that commit.
for (leaf, cost) in &best.next_commit_sizes {
    println!("  next leaf {:?}: {cost} ciphertexts", leaf);
}
```

## API

```rust
pub fn find_update_candidates(
    removed: LeafNodeIndex,
    leaves: impl Iterator<Item = LeafNodeIndex>,
) -> Vec<LeafNodeIndex>
```

- **`removed`** — the index of the leaf being (or already) removed.
- **`leaves`** — an iterator over the indices of the current (non-blank) leaves.
- **Returns** — the leaf indices closest to `removed` by XOR distance. Empty if
  `leaves` yields no elements after filtering.

```rust
pub fn TreeState::new(
    leaves:  Vec<LeafState>,
    parents: Vec<ParentState>,   // must have leaves.len() - 1 elements
) -> TreeState
```

```rust
// Number of HPKE ciphertexts leaf would produce when committing in the
// current tree state (sum of co-path resolution sizes).
pub fn TreeState::commit_size(leaf: LeafIndex) -> usize
```

```rust
// For every eligible committer (occupied, not in removes), return:
//   • commit_size       — cost of their commit after proposals are applied.
//   • next_commit_sizes — cost for each remaining leaf in the resulting tree.
pub fn TreeState::simulate_all_commits(
    removes: &[LeafIndex],
    adds:    &[LeafIndex],
) -> Vec<CommitInfo>

pub struct CommitInfo {
    pub leaf:              LeafIndex,
    pub commit_size:       usize,
    pub next_commit_sizes: Vec<(LeafIndex, usize)>,
}
```

`simulate_all_commits` models the full RFC 9420 commit mechanics:
removing a leaf blanks its entire direct path; the committer's UpdatePath
re-keys every node on their own direct path (clearing old unmerged leaves and
setting them to the newly added members that fall in each node's subtree).

All types (`LeafIndex`, `LeafState`, `ParentState`, `TreeState`, `CommitInfo`)
are available directly from the crate root as well as from the `tree_state`
submodule.

## License

MIT
