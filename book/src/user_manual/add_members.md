# Adding members to a group

## Immediate operation

Members can be added to the group atomically with the `.add_members()` function. The application needs to fetch the corresponding key packages from every new member from the Delivery Service first.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_adds_bob}}
```

The function returns the tuple `(MlsMessageOut, Welcome)`. The `MlsMessageOut` contains a Commit message that needs to be fanned out to existing group members. The `Welcome` message must be sent to the newly added members.

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
