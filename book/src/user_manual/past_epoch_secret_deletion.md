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

## Deleting past epoch secrets using time-based APIs

In some cases, it is useful to clean up past epoch secrets manually. For example, when a group is configured with `PastEpochDeletionPolicy::KeepAll`, all past epoch secrets will be kept automatically.

Delete all past epoch secrets:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_past_epoch.rs:delete_all}}
```

APIs are also provided for deleting past epoch secrets before a provided timestamp, or that are older than a provided duration. These APIs can be used with any `PastEpochDeletionPolicy` set on the group.

The manual past epoch deletion APIs take a `PastEpochDeletion` as an argument.

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

