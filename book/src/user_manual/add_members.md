# Adding members to a group

## Immediate operation

Members can be added to the group atomically with the `.add_members()` function. The application needs to fetch the corresponding key packages from every new member from the Delivery Service first.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_adds_bob}}
```

The function returns the tuple `(MlsMessageOut, Welcome)`. The `MlsMessageOut` contains a Commit message that needs to be fanned out to existing members of the group. The `Welcome` message needs to be sent to the newly added members.

## Proposal

Members can also be added as a proposal (without the corresponding Commit message) by using the `.propose_add_member()` function:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:propose_add}}
```

In this case the the function returns an `MlsMessageOut` that needs to be fanned out to existing group members.
