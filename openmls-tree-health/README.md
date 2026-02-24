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

This crate provides helpers to identify those candidates, covering two workflows:

- **Proactive** — pick who should commit the Remove; their mandatory
  `update_path` re-keys the shared path in the same commit, at no extra cost.
- **Reactive** — pick who should self-update after someone else committed the
  Remove; their follow-up commit re-keys the now-blank region.

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

## License

MIT
