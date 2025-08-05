# Updating own leaf node

## Immediate operation

Members can update their own leaf node atomically with the `.self_update()` function.
By default, only the HPKE encryption key is updated. The application can however also provide more parameters like a new credential, capabilities and extensions using the `LeafNodeParameters` struct.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:self_update}}
```

The function returns a `CommitMessageBundle`, which consists of the Commit message that needs to be fanned out to existing group members.
Even though the member updates its own leaf node only in this operation, the Commit message could potentially also cover Add Proposals that were previously received in the epoch. Therefore the `CommitMessagBundle` can also contain a `Welcome` message. The `Welcome` message must be sent to the newly added members.

Members can use the `.self_update_with_new_signer()` function to also update the `Signer` used to sign future MLS messages.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_rotates_signature_key}}
```

When constructing the `NewSignerBundle`, the `Signer` must match the public key and credential in the `CredentialWithKey`. When using `self_update_with_new_signer`, `LeafNodeParameters` may not contain a `CredentialWithKey`.


## Proposal

Members can also update their leaf node as a proposal (without the corresponding Commit message) by using the `.propose_self_update()` function. Just like with the `.self_update()` function, optional parameters can be set through `LeafNodeParameters`:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:propose_self_update}}
```

In this case, the function returns an `MlsMessageOut` that needs to be fanned out to existing group members.
