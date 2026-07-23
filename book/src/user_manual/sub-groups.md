# Sub-group branching

Sometimes a subset of the members in a group want to continue in a separate, smaller
group without going through a full fresh key exchange. MLS supports this with
*sub-group branching* ([RFC 9420 §11.3]): a new group is created with the same
parameters as an existing (parent) group, and its key schedule is seeded with a
resumption PSK derived from the parent. This cryptographically ties the new
sub-group to the parent epoch it branched from.

The rest of this chapter assumes you already have a parent group (`alice_group`
on the sender side, `bob_group` on the receiver side).

## Exporting `BranchInfo` from the parent

Both the sender and each receiver export a `BranchInfo` from their own parent group.
`BranchInfo` is an owned snapshot of the values a branch needs (protocol version,
ciphersuite, group id, epoch, the parent's resumption PSK secret, and the parent
members' credentials).

> [!WARNING]
> The `BranchInfo` carries the parent's resumption PSK secret, which is
> sensitive key material.

The sender and every receiver must use a `BranchInfo` exported from the *same*
parent epoch — the branch's key schedule is derived from that epoch's resumption
PSK. A receiver's view of the parent group may advance in the meantime (an
unrelated commit arrives before the branch `Welcome` is processed), so its current
`branch_info()` might no longer match the epoch the branch was taken from.
Applications that need to tolerate this should keep the `BranchInfo` of several
recent epochs (a sliding window) and join with the one for the parent epoch the
branch was taken from. Because `BranchInfo` is an owned snapshot, this is just a
matter of holding on to the values. The window size is bounded by how many
resumption PSKs the group retains (`number_of_resumption_psks`).

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_sub_groups.rs:export_branch_info}}
```

## Sender: creating and branching the sub-group

Creating the sub-group and its branch commit is a single builder operation:
`MlsGroup::builder()...branch(branch_info).build_branch(...)`. The sub-group is
created with the parent's ciphersuite automatically (from `BranchInfo`); set any
other group configuration on the `MlsGroupBuilder` before calling `branch`. The
branch commit adds the given members, mixes the parent's resumption PSK secret
into the sub-group's key schedule, and generates the `Welcome` message to add the
other members to the group.

`build_branch` returns the new sub-group and the commit bundle, but does not
merge the commit: as with any commit, merge it only once you're certain it goes
through, e.g. the delivery service has confirmed it.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_sub_groups.rs:sender_branch}}
```

## Receiver: joining the sub-group

A receiver joins the branched sub-group with `StagedWelcome::build_from_branch`,
which returns a `JoinBuilder`. In addition to the regular join processing, this
injects the parent's resumption PSK secret and enforces the [RFC 9420 §11.3]
receiver checks. `build_from_branch` itself verifies that the branch PSK in the
`Welcome` references the same parent group and epoch as the `BranchInfo` you
passed in (before that secret is mixed into the key schedule). The remaining
checks run when `build` is called: the protocol version and ciphersuite must
match the parent, the sub-group must be at epoch 1, and every sub-group member
must also be a member of the parent group. The membership check is on by default
and can be disabled with `.check_members(false)`.

If the `BranchInfo` is from a different parent epoch than the one the sender
branched from, `build_from_branch` fails with
`WelcomeError::SubgroupParentMismatch`. Handle this by retrying with the
`BranchInfo` for the parent epoch the branch was taken from (see the
sliding-window note above).

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_sub_groups.rs:receiver_join_branch}}
```

In the end, both sides have derived the same sub-group:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_sub_groups.rs:verify}}
```

[RFC 9420 §11.3]: https://www.rfc-editor.org/rfc/rfc9420.html#name-subgroup-branching
