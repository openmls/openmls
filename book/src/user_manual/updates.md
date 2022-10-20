# Updating own key package

## Immediate operation

Members can update their own leaf key package atomically with the `.self_update()` function.
The application can optionally provide a `KeyPackage` manually. If not, a key package will be created on the fly with the same extensions as the current one but with a fresh HPKE init key.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:self_update}}
```

The function returns the tuple `(MlsMessageOut, Option<Welcome>)`. The `MlsMessageOut` contains a Commit message that needs to be fanned out to existing group members.
Even though the member updates its own key package only in this operation, the Commit message could potentially also cover Add Proposals that were previously received in the epoch. Therefore the function can also optionally return a `Welcome` message. The `Welcome` message must be sent to the newly added members.

## Proposal

Members can also update their key package as a proposal (without the corresponding Commit message) by using the `.propose_self_update()` function. Just like with the `.self_update()` function, an optional key package can be provided:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:propose_self_update}}
```

In this case, the function returns an `MlsMessageOut` that needs to be fanned out to existing group members.
