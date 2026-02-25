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

This crate provides helpers to identify those candidates, covering two workflows:

- **Proactive** — pick who should commit the Remove; their mandatory
  `update_path` re-keys the shared path in the same commit, at no extra cost.
- **Reactive** — pick who should self-update after someone else committed the
  Remove; their follow-up commit re-keys the now-blank region.
- **Unmerged leaves** — pick who should self-update to most reduce the root
  resolution size after one or more Add operations.

## Usage

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
openmls-tree-health = "0.1.0"
```

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

The application can then ask the chosen member to commit the Remove, or — if
the Remove was already committed by someone else — to send a self-update.

To identify who should self-update to reduce unmerged-leaf overhead at the root,
iterate over all leaves and pick those with the smallest hypothetical size:

```rust
use openmls_tree_health::hypothetical_root_resolution_size;

let root_unmerged = group.treesync().root_unmerged_leaves();

let best = group
    .treesync()
    .full_leaves()
    .map(|(idx, _)| (idx, hypothetical_root_resolution_size(idx, root_unmerged)))
    .min_by_key(|&(_, size)| size);
```

When a set of proposals is ready to be committed, use
`project_root_unmerged_leaves` to compute what the root's unmerged list will
look like after those proposals are applied, then feed the result into
`hypothetical_root_resolution_size` to find the best committer:

```rust
use openmls_tree_health::{project_root_unmerged_leaves, hypothetical_root_resolution_size};

let projected = project_root_unmerged_leaves(
    group.treesync().root_unmerged_leaves(),
    &added_leaf_indices,   // leaf slots the new members will occupy
    &removed_leaf_indices,
);

let best = group
    .treesync()
    .full_leaves()
    .filter(|(idx, _)| !removed_leaf_indices.contains(idx))
    .map(|(idx, _)| (idx, hypothetical_root_resolution_size(idx, &projected)))
    .min_by_key(|&(_, size)| size);
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
- **Returns** — the leaf indices closest to `removed`. Empty if `leaves` yields
  no elements after filtering.

```rust
pub fn hypothetical_root_resolution_size(
    leaf: LeafNodeIndex,
    root_unmerged_leaves: &[LeafNodeIndex],
) -> usize
```

- **`leaf`** — the leaf considering a self-update.
- **`root_unmerged_leaves`** — obtained from `group.treesync().root_unmerged_leaves()`.
- **Returns** — the root resolution size under a simplified model where only
  `leaf` is removed from the unmerged list. Returns 1 when the list is empty.
  A lower value means `leaf` is a better self-update candidate.

```rust
pub fn project_root_unmerged_leaves(
    current: &[LeafNodeIndex],
    adds: &[LeafNodeIndex],
    removes: &[LeafNodeIndex],
) -> Vec<LeafNodeIndex>
```

- **`current`** — the current `root_unmerged_leaves`, from `group.treesync().root_unmerged_leaves()`.
- **`adds`** — leaf indices that will be added by the pending proposals.
- **`removes`** — leaf indices that will be removed by the pending proposals.
- **Returns** — the projected unmerged-leaf list after those proposals are
  applied. Pass this to `hypothetical_root_resolution_size` for each candidate
  committer.

## Tree state model

The functions above only look at the root's unmerged-leaf list. A more precise
picture of tree health requires knowing the **co-path resolution size** for each
potential committer — the total number of HPKE ciphertexts that committer would
have to produce, summed over the entire path from leaf to root.

The `tree_state` module provides a lightweight, OpenMLS-independent model for
this. It captures the blank/occupied status of every node and the unmerged-leaf
list of every occupied parent, and uses that snapshot to compute exact commit
costs and to project the tree state after a hypothetical commit.

### Key types

| Type | Description |
|------|-------------|
| `LeafIndex(u32)` | A leaf's index in the tree (leaf `i` is at tree-node `2i`). |
| `LeafState` | `Blank` (empty slot) or `Occupied` (member present). |
| `ParentState` | `Blank` (no key material) or `Occupied { unmerged_leaves }`. |
| `TreeState` | A snapshot of the full tree: one `LeafState` per leaf slot and one `ParentState` per parent node. |
| `CommitInfo` | Output of `simulate_all_commits`: per-committer cost now and next-round costs for every remaining leaf. |

`TreeState` does not depend on any OpenMLS type. To bridge from OpenMLS, convert
`LeafNodeIndex` values with `LeafIndex(idx.u32())` and read the node states from
`group.treesync()`.

### Usage

Build a `TreeState` from the current group's ratchet tree, then query it:

```rust
use openmls_tree_health::tree_state::{LeafIndex, LeafState, ParentState, TreeState};

// Construct the snapshot for a 4-leaf tree.
// parents[k] corresponds to MLS tree-node index 2k+1.
let state = TreeState::new(
    vec![
        LeafState::Occupied,
        LeafState::Occupied,
        LeafState::Occupied,
        LeafState::Occupied,
    ],
    vec![
        ParentState::Blank,                                             // tree[1]
        ParentState::Occupied { unmerged_leaves: vec![LeafIndex(2)] }, // tree[3] (root)
        ParentState::Occupied { unmerged_leaves: vec![LeafIndex(2)] }, // tree[5]
    ],
);
println!("{state}"); // ASCII tree with per-node state
```

**Commit cost for one leaf:**

```rust
// Number of HPKE ciphertexts leaf[0] would produce when committing.
let cost = state.commit_size(LeafIndex(0));
```

**Simulate all possible committers with pending proposals:**

```rust
use openmls_tree_health::tree_state::LeafIndex;

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

### API

```rust
// Build a snapshot.
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
//   • commit_size  — cost of their commit after proposals are applied.
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

## License

MIT
