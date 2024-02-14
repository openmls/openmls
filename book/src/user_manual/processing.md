# Processing incoming messages

Processing of incoming messages happens in different phases:

## Deserializing messages

Incoming messages can be deserialized from byte slices into an `MlsMessageIn`:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:mls_message_in_from_bytes}}
```

If the message is malformed, the function will fail with an error.

## Processing messages in groups

In the next step, the message needs to be processed in the context of the
corresponding group.

`MlsMessageIn` can carry all MLS messages, but only `PrivateMessageIn` and
`PublicMessageIn` are processed in the context of a group. In OpenMLS these two
message types are combined into a `ProtocolMessage` `enum`. There are 3 ways to
extract the messages from an `MlsMessageIn`:

1. `MlsMessageIn.try_into_protocol_message()` returns a `Result<ProtocolMessage, ProtocolMessageError>`
2. `ProtocolMessage::try_from(m: MlsMessageIn)` returns a `Result<ProtocolMessage, ProtocolMessageError>`
3. `MlsMessageIn.extract()` returns an `MlsMessageBodyIn` `enum` that has two
   variants for `PrivateMessageIn` and `PublicMessageIn`

`MlsGroup.process_message()` accepts either a `ProtocolMessage`, a
`PrivateMessageIn`, or a `PublicMessageIn` and processes the message.
`ProtocolMessage.group_id()` exposes the group ID that can help the application
find the right group. 

If the message was encrypted (i.e. if it was a `PrivateMessageIn`), it will be
decrypted automatically. The processing performs all syntactic and semantic
validation checks and verifies the message's signature. The function finally
returns a `ProcessedMessage` object if all checks are successful.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:process_message}}
```

## Interpreting the processed message

In the last step, the message is ready for inspection. The `ProcessedMessage`
obtained in the previous step exposes header fields such as group ID, epoch,
sender, and authenticated data. It also exposes the message's content. There are
3 different content types:

### Application messages

Application messages simply return the original byte slice:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:inspect_application_message}}
```

### Proposals

Standalone proposals are returned as a `QueuedProposal`, indicating that they are pending proposals. The proposal can be inspected through the `.proposal()` function. After inspection, applications should store the pending proposal in the proposal store of the group:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:inspect_add_proposal}}
```

#### Rolling back proposals

Operations that add a proposal to the proposal store, will return its reference. This reference can be used to remove
a proposal from the proposal store. This can be useful for example to roll back in case of errors.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:rollback_proposal_by_ref}}
```

### Commit messages

Commit messages are returned as `StagedCommit` objects. The proposals they cover can be inspected through different functions, depending on the proposal type. After the application has inspected the `StagedCommit` and approved all the proposals it covers, the `StagedCommit` can be merged in the current group state by calling the `.merge_staged_commit()` function. For more details, see the `StagedCommit` documentation.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:inspect_staged_commit}}
```

### Interpreting remove operations

Remove operations can have different meanings, such as:

- We left the group (by our own wish)
- We were removed from the group (by another member or a pre-configured sender)
- We removed another member from the group
- Another member left the group (by their own wish)
- Another member was removed from the group (by a member or a pre-configured sender, but not by us)

Since all remove operations only appear as a `QueuedRemoveProposal`, the `RemoveOperation` enum can be constructed from the remove proposal and the current group state to reflect the scenarios listed above.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:remove_operation}}
```
