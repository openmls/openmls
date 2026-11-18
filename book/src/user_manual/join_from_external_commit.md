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

## Rejoining a group

A member can also use an external commit to rejoin a group it is already a member of, for example because its group state became unusable. The group built by the external commit then replaces the state the member already holds — including the message secrets of past epochs retained according to the `PastEpochDeletionPolicy`, so application messages the member could still have decrypted a moment before the rejoin would become undecryptable. To avoid that, the previous group state can be passed to the `ExternalCommitBuilder` via `retain_past_epochs_from`, which carries its past epoch message secrets over into the new group:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:retain_past_epochs}}
```

Carrying the secrets over is bounded by the join config's `PastEpochDeletionPolicy`, measured against the epoch the external commit creates: a member that missed more epochs than the policy retains has no valid past epochs left at the time of the rejoin, and nothing is carried over. Note that the default policy retains no past epochs at all.

The previous group state has to be this member's own state for the group being rejoined, and it is consumed: aside from its retained message secrets it is discarded. What the storage provider holds for the group is only overwritten once the external commit is finalized, so if `build_group` fails, the previous state can be reloaded via `MlsGroup::load`.
