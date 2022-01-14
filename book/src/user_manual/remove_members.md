# Removing members from a group

## Immediate operation

Members can be removed from the group atomically with the `.remove_members()` function.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:charlie_removes_bob}}
```

The function returns the tuple `(MlsMessageOut, Option<Welcome>)`. The `MlsMessageOut` contains a Commit message that needs to be fanned out to existing members of the group.
Despite the fact that members were only removed in this operation, the Commit message could potentially also cover Add Proposals that were previously received in the epoch. Therefore the function can also optionally return a `Welcome` message. The `Welcome` message needs to be sent to the newly added members.

## Proposal

Members can also be removed as a proposal (without the corresponding Commit message) by using the `.propose_remove_member()` function:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:propose_remove}}
```

In this case the the function returns an `MlsMessageOut` that needs to be fanned out to existing group members.
