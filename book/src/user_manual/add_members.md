# Adding members to a group

## Immediate operation

Members can be added to the group atomically with the `.add_members()` function. The application needs to fetch the corresponding key packages from every new member from the Delivery Service first.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_adds_bob}}
```

The function returns the tuple `(MlsMessageOut, Welcome)`. The `MlsMessageOut` contains a Commit message that needs to be fanned out to existing group members. The `Welcome` message must be sent to the newly added members.

### Adding members without update

The `.add_members_without_update()` function functions the same as the `.add_members()` function, except that it will only include an update to the sender's key material if the sender's proposal store includes a proposal that requires a path. For a list of proposals and an indication whether they require a `path` (i.e. a key material update) see [Section 17.4 of RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html#section-17.4).

Not sending an update means that the sender will not achieve post-compromise security with this particular commit. However, not sending an update saves on performance both in terms of computation and bandwidth. Using `.add_members_without_update()` can thus be a useful option if the ciphersuite of the group features large public keys and/or expensive encryption operations.

## Proposal

Members can also be added as a proposal (without the corresponding Commit message) by using the `.propose_add_member()` function:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:propose_add}}
```

In this case, the function returns an `MlsMessageOut` that needs to be fanned out to existing group members.

## External proposal

Parties outside the group can also make proposals to add themselves to the group with an external proposal. Since those
proposals are crafted by outsiders, they are always plaintext messages.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:external_join_proposal}}
```

It is then up to the group members to validate the proposal and commit it.
Note that in this scenario it is up to the application to define a proper authorization policy to grant the sender.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:decrypt_external_join_proposal}}
```
