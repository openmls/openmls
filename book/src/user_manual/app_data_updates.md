# Working with AppData

> [!IMPORTANT]
> Currently this functionality is behind the `extensions-draft-08` feature. 

So far, applications could store group state that all members should agree on in custom
extensions.
The [MLS Extensions] draft specifies a new mechanism to encode application data in the
group state via the `AppDataDictionary` extension.
When using custom extensions for this purpose, every update message contains the full new state,
for example in a `GroupContextExtensionProposal`.
The `AppDataUpdate` proposal allows sending only a diff, which the application interprets to produce
the new state in the `AppDataDictionary`.


This is very flexible and allows implementing a wide range of diff-style approaches.
However, it puts more burden on the application, since it needs to validate and process the updates itself to produce the new state.

> [!NOTE]
> The extensions draft specifies ComponentIDs to be 32 bit, but after publishing this was reduced
> to 16 bit. We are using 16 bit ComponentIDs. More context in issue [mls-extensions#69]

To demonstrate the API, we need a custom component that we keep in the group.

## Setting up a custom Component

Each application component needs:
- A unique `ComponentId` (we'll use `0xf042`, which is in the private range `0x8000..0xffff`)
- A data format for the stored state
- A data format for updates (the "diff")
- Application logic to process updates and compute new state

For this example, we'll build a simple counter where:
- The stored state is the counter value as a big-endian `u32`
- Updates are a single byte: `0x01` = increment, `0x02` = decrement
- Incrementing a counter that hasn't been set yet initializes it to 1
- Decrementing below zero is invalid and will cause the commit to be rejected
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_app_data.rs:component_definition}}
```

Next, we crate the group.

## Group Setup

Both the group and its members must advertise support for `AppDataUpdate` proposals and the `AppDataDictionary` extension. This is done through capabilities and required capabilities.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_app_data.rs:group_setup}}
```

## Sending and receiving proposals

This part doesn't really change.

Alice sends a proposal to increment the counter:
```rust,no_run,noplayground
./tests/book_code_app_data.rs:send_proposal}}
```

Bob receives and stores the proposal:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_app_data.rs:receive_proposal}}
```

## Sending Commits

Now, Alice creates a commit that includes:
- The previously sent proposal (by reference, from her proposal store)
- One additional increment proposal (inline)

An important change is that Alice must compute the resulting state herself before building the commit:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_app_data.rs:create_commit}}
```

## Receiving Commits

Bob receives the commit and must independently compute the same new state. He iterates over the proposals in the commit, resolving references from his proposal store:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_app_data.rs:process_commit}}
```



After both parties merge, they should have identical state:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_app_data.rs:verify_consistency}}
```

## Error Handling: Invalid Updates

If an update would result in invalid state (e.g., decrementing below zero), the application should reject the commit. Here's what happens when Alice tries to decrement an unset counter:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_app_data.rs:invalid_update}}
```

The application detects the invalid state during proposal processing and can choose not to proceed with the commit (on the sender side) or reject the message (on the receiver side).



[MLS Extensions]: https://datatracker.ietf.org/doc/draft-ietf-mls-extensions/08/
[mls-extensions#69]: https://github.com/mlswg/mls-extensions/issues/69

---

## Verifying Consistency



