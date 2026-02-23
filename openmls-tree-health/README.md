# openmls-tree-health

Tree maintenance helpers for [OpenMLS](https://github.com/openmls/openmls) groups.

## Background

MLS groups can degrade in efficiency over time. After Add and Remove operations,
unmerged leaves accumulate on parent nodes, growing resolution sizes. This makes
commits more expensive (more HPKE ciphertexts).

A self-update commit from a leaf that is close in the tree to a recently
removed leaf re-keys the shared path between them, restoring efficiency for that
subtree. This crate provides helpers that tell an application which group
member(s) are the best candidates to perform such a self-update.

## Usage

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
openmls-tree-health = "0.1.0"
```

After processing a Remove proposal, call `find_self_update_candidates` with the
removed leaf index and an iterator over the remaining leaves:

```rust
use openmls_tree_health::find_self_update_candidates;

let candidates = find_self_update_candidates(
    removed_index,
    group.treesync().full_leaves().map(|(idx, _)| idx),
);

// candidates contains the leaf index (or indices, in case of a tie) of the
// group member(s) best placed to restore tree efficiency with a self-update.
```

The application can then signal the chosen member to send a commit with an
update_path.

## API

```rust
pub fn find_self_update_candidates(
    removed: LeafNodeIndex,
    leaves: impl Iterator<Item = LeafNodeIndex>,
) -> Vec<LeafNodeIndex>
```

- **`removed`** — the index of the leaf that was just or is about to be removed.
- **`leaves`** — an iterator over the indices of the remaining (non-blank) leaves.
- **Returns** — the leaf indices closest to `removed`. Empty if `leaves` yields
  no elements after filtering.

## License

MIT
