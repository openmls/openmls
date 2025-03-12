# Join a group from a Welcome message

To join a group from a `Welcome` message, a new `MlsGroup` can be instantiated from
the `MlsMessageIn` message containing the `Welcome` and an `MlsGroupJoinConfig`
(see [Group configuration](./group_config.md) for more details).  This is a
two-step process: a `StagedWelcome` is constructed from the `Welcome`
and can then be turned into an `MlsGroup`.  If the group configuration does not
use the ratchet tree extension, the ratchet tree needs to be provided.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:bob_joins_with_welcome}}
```

The reason for this two-phase process is to allow the recipient of a `Welcome`
to inspect the message, e.g. to determine the identity of the sender.

Pay attention not to forward a Welcome message to a client before its associated
commit has been accepted by the Delivery Service.  Otherwise, you would end up
with an invalid MLS group instance.

# Examining a welcome message

When a client is invited to join a group, the application can allow the client to decide whether or not to join the group. In order to determine whether to join the group, the application can inspect information provided in the welcome message, such as who invited them, who else is in the group, what extensions are available, and more. If the application decides not to join the group, the welcome must be discarded to ensure that the local state is cleaned up.

After receiving a `MlsMessageIn` from the delivery service, the first step is to extract the `MlsMessageBodyIn`, and determine whether it is a welcome message.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_discard_welcome.rs:not_join_group_welcome}}
```

The next step is to process the `Welcome`. This removes the consumed `KeyPackage` from the `StorageProvider`, unless it is a last resort `KeyPackage`.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_discard_welcome.rs:not_join_group_processed_welcome}}
```

At this stage, there are some more pieces of information in the `ProcessedWelcome` that could be useful to the application. For example, it can be useful to check which extensions are available. However, the pieces of information that are retrieved from the `ProcessedWelcome` are unverified, and verified values are only available from the `StagedWelcome` that is produced in the next step.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_discard_welcome.rs:not_join_group_processed_welcome_inspect}}
```

The next step is to stage the `ProcessedWelcome`.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_discard_welcome.rs:not_join_group_staged_welcome}}
```

Then, more information about the welcome message's sender, such as the credential, signature public key, and encryption public key can also be individually inspected. The welcome message sender's credential can be validated at this stage.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_discard_welcome.rs:not_join_group_welcome_sender}}
```
Additionally, some information about the other group members is made available, e.g. credentials and signature public keys for credential validation.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_discard_welcome.rs:not_join_group_members}}
```

Lastly, the `GroupContext` contains several other useful pieces of information, including the protocol version, the extensions enabled on the group, and the required extension, proposal, and credential types. 
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_discard_welcome.rs:not_join_group_group_context}}
```
