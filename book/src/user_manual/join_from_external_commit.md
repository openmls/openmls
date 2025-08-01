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

External commits can be created using a builder pattern via `MlsGroup::external_commit_builder()`. The `ExternalCommitBuilder` provides more options than `join_by_external` in that it allows the inclusion of SelfRemove or PSK proposals. After its first stage, the `ExternalCommitBuilder` turns into a regular `CommitBuilder`. As external commits come with a few restrictions relative to regular commits, not all `CommitBuilder` capabilities are exposed for external commits. Also, instead of `stage_commit` this `CommitBuilder` requires a call to `finalize` before it returns the new `MlsGroup`, as well as a `CommitMessageBundle` containing the external commit, as well as a potential `GroupInfo`.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:external_commit_builder}}
```

The resulting external commit message needs to be fanned out to the Delivery Service and accepted by the other members before merging this external commit.
