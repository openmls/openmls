# Past epoch secret deletion


## Setting a past epoch secrets deletion policy

The Delivery Service may not be able to guarantee that application messages from one epoch are sent before the beginning of the next epoch. To address this, applications can configure their groups to keep the necessary key material around for past epochs by configuring the past epoch deletion policy on the `MlsGroupCreateConfig`.

The `PastEpochDeletionPolicy` will be applied to the group automatically when a commit is merged.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_past_epoch.rs:config_max_epochs}}
```

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_past_epoch.rs:config_keep_all}}
```

## Deleting past epoch secrets using time-based APIs

Time-based APIs can also be used by the application to delete past epoch secrets.

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

Delete all past epoch secrets:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_past_epoch.rs:delete_all}}
```
