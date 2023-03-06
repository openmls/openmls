# Removing members from a group

## Immediate operation

Members can be removed from the group atomically with the `.remove_members()` function, which takes the `KeyPackageRef` of group member as input. References to the `KeyPackage`s of group members can be obtained using the `.members()` function, from which one can in turn compute the `KeyPackageRef` using their `.hash_ref()` function.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:charlie_removes_bob}}
```

The function returns the tuple `(MlsMessageOut, Option<Welcome>)`. The `MlsMessageOut` contains a Commit message that needs to be fanned out to existing group members.
Even though members were removed in this operation, the Commit message could potentially also cover Add Proposals previously received in the epoch. Therefore the function can also optionally return a `Welcome` message. The `Welcome` message must be sent to the newly added members.

## Proposal

Members can also be removed as a proposal (without the corresponding Commit message) by using the `.propose_remove_member()` function:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:propose_remove}}
```

In this case, the function returns an `MlsMessageOut` that needs to be fanned out to existing group members.

## Getting removed from a group

A member is removed from a group if another member commits to a remove proposal targeting the member's leaf. Once the to-be-removed member merges that commit via `merge_staged_commit()`, all other proposals in that commit will still be applied, but the group will be marked as inactive afterward. The group remains usable, e.g., to examine the membership list after the final commit was processed, but it won't be possible to create or process new messages.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:getting_removed}}
```

## External Proposal

Parties outside the group can also make proposals to remove members as long as they are registered as part of the `ExternalSendersExtension` extension.
Since those proposals are crafted by outsiders, they are always public messages.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:external_remove_proposal}}
```

It is then up to one of the group members to process the proposal and commit it.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:decrypt_external_external_proposal}}
```
