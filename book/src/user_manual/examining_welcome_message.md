# Examining a welcome message

When a client is invited to join a group, the application can allow the client to decide whether or not to join the group. In order to determine whether to join the group, the application can inspect information provided in the welcome message, such as who invited them, who else is in the group, what extensions are available, and more. If the application decides not to join the group, the welcome must be discarded to ensure that the local state is cleaned up.

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

The next step is to stage the `ProcessedWelcome`. This causes some state to be updated in the `StorageProvider`. 
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_staged_welcome}}
```

Then, more information about the welcome messages sender, such as the credential, signature public key, and encryption public key can also be individually inspected.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_welcome_sender}}
```
Additionally, some information about the other group members is available.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_members}}
```

Lastly, the `GroupContext` contains several other useful pieces of information, including the protocol version, the extensions enabled on the group, and the required extension, proposal, and credential types. 
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_group_context}}
```

# Cleaning up after not joining the group

After deciding not to join the group, some information that was stored in the `StorageProvider` by the staging process can be discarded.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:not_join_group_cleanup}}
```
