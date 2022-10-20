# Processing incoming messages

Processing of incoming messages happens in different phases:

## Deserializing messages

Incoming messages can be deserialized from byte slices into an `MlsMessageIn`:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:mls_message_in_from_bytes}}
```

If the message is malformed, the function will fail with an error.

## Parsing messages

In the next step, the incoming message needs to be parsed. If the message was encrypted, it will be decrypted automatically:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:parse_message}}
```

Parsing can fail if, e.g., decrypting the message fails. The exact reason for failure is returned in the error value.

## Processing messages

In the next step, the unverified message needs to be processed. This step performs all remaining validity checks and verifies the message's signature. Optionally, a signature key can be provided to verify the message's signature. This can be used when processing external messages. By default, the sender's credential is used to verify the signature.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:process_message}}
```

## Interpreting the processed message

In the last step, the message is ready for inspection. There are 3 different kinds of messages:

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
