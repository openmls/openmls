# Past epoch secret deletion

The Delivery Service may not be able to guarantee that application messages from one epoch are sent before the beginning of the next epoch. To address this, applications can configure their groups to keep the necessary key material around for past epochs by configuring the past epoch deletion policy on the `MlsGroupCreateConfig`.

The `PastEpochDeletionPolicy` will be applied to the group automatically when a commit is merged.

## Setting a past epoch secrets deletion policy for a group

As part of creating a group, the `PastEpochDeletionPolicy` can be set on a group creation config:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_past_epoch.rs:config_max_epochs}}
```

The policy can also be updated on an existing group:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_past_epoch.rs:set_policy_on_existing_group}}
```

## Time-based deletion schedules

It is possible to configure time-based deletion schedules for past epoch secrets. The application can periodically apply a `PastEpochDeletion` using the `MlsGroup::delete_past_epoch_secrets()` API.

Generally, when time-based deletion schedules are used, it can be helpful to configure the group to use `PastEpochDeletionPolicy::KeepAll`, to ensure that automatic deletion conducted by the group is not applied early to a past epoch secret.

Delete all past epoch secrets before a provided timestamp:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_past_epoch.rs:timestamp}}
```

Delete all past epoch secrets before a provided timestamp, leaving at most a provided number of epochs:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_past_epoch.rs:timestamp_with_max_epochs}}
```

Delete all past epoch secrets older than a provided duration:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_past_epoch.rs:duration}}
```

Delete all past epoch secrets older than a provided duration, leaving at most a provided number of epochs:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_past_epoch.rs:duration_with_max_epochs}}
```

## Migration and deleting legacy entries

Epoch secrets that were created using `openmls=0.8.1` or earlier will not yet include a timestamp.

After migration, these may not always be deleted by applying a time-based `PastEpochDeletion`. Only if a new secret that does include a timestamp is added later, and it matches the time-based condition in the `PastEpochDeletion`, all earlier past epoch secrets without timestamps will be deleted, as well. However, otherwise, past epoch secrets without timestamps will not be affected by applying time-based `PastEpochDeletion`s.

After migration, it is possible to manually delete all past epoch secrets without timestamps:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_past_epoch.rs:delete_all_past_secrets_with_none_timestamps}}
```

## Deleting all past epoch secrets

All past epoch secrets can also be deleted at once:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_past_epoch.rs:delete_all}}
```

Setting the group's `PastEpochDeletionPolicy` to `PastEpochDeletionPolicy::MaxEpochs(0)` will also delete all past epoch secrets.
