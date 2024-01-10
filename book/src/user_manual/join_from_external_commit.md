# Join a group with an external commit

To join a group with an external commit message, a new `MlsGroup` can be instantiated directly from the `GroupInfo`.
The `GroupInfo`/Ratchet Tree should be shared over a secure channel.
If the RatchetTree extension is not included in the `GroupInfo` as a `GroupInfoExtension`, then the ratchet tree needs to be provided.

The `GroupInfo` can be obtained either from a call to `export_group_info`from the `MlsGroup`:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_adds_bob}}
```

Or from a call to a function that results in a staged commit:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_exports_group_info}}
```

Calling `join_by_external_commit` requires an `MlsGroupJoinConfig` (see [Group configuration](./group_config.md) for more details). The function creates an `MlsGroup` and leave it with a commit pending to be merged.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:charlie_joins_external_commit}}
```

The resulting external commit message needs to be fanned out to the Delivery Service and accepted by the other members before merging this external commit.
