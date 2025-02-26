# Examining a welcome message

When a client is invited to join a group, the application can allow the client to decide whether or not to join the group. In order to determine whether to join the group, the application can inspect information provided in the welcome message, such as [list here]. If the application decides not to join the group, data must be cleaned up in the storage provider.

After receiving a `MlsMessageIn` from the delivery service, the first step is to extract the `MlsMessageBodyIn`, and determine whether it is a welcome message.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_welcome}}
```

At this stage, the welcome's `&[EncryptedGroupSecrets]` can be investigated:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_welcome_inspect}}
```

The next step is to process the `Welcome`.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_processed_welcome}}
```

After this, some (unverified) information contained in the `ProcessedWelcome` can be investigated.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_processed_welcome_inspect}}
```

Staging the `ProcessedWelcome` causes some state to be updated in the `StorageProvider`. 
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_staged_welcome}}
```

Information about the welcome messages sender, such as the credential, signature public key, and encryption public key can also be individually inspected.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_welcome_sender}}
```
Additionally, information about the other group members can be examined:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_members}}
```

Several other pieces of information can be accessed via the `GroupContext`.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_group_context}}
```

# Cleaning up after not joining the group

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_cleanup}}
```
