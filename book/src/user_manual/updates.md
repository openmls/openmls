# Updating own leaf node

## Immediate operation

Members can update their own leaf node atomically with the `.self_update()` function.
By default, only the HPKE encryption key is updated. The application can however also provide more parameters like a new credential, capabilities and extensions using the `LeafNodeParameters` struct.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:self_update}}
```

The function returns the tuple `(MlsMessageOut, Option<Welcome>)`. The `MlsMessageOut` contains a Commit message that needs to be fanned out to existing group members.
Even though the member updates its own leaf node only in this operation, the Commit message could potentially also cover Add Proposals that were previously received in the epoch. Therefore the function can also optionally return a `Welcome` message. The `Welcome` message must be sent to the newly added members.

## Proposal

Members can also update their leaf node as a proposal (without the corresponding Commit message) by using the `.propose_self_update()` function. Just like with the `.self_update()` function, optional parameters can be set through `LeafNodeParameters`:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:propose_self_update}}
```

In this case, the function returns an `MlsMessageOut` that needs to be fanned out to existing group members.
