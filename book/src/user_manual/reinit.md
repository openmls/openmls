# Reinitializing a group

Reinitialization (ReInit) replaces a group with a new *successor* group
that carries over the same members but may use different parameters — a new
group id, protocol version, ciphersuite, or group context extensions. This is
the mechanism to use when, for example, a group needs to migrate to a stronger
ciphersuite. See [RFC 9420 §11.2](https://www.rfc-editor.org/rfc/rfc9420.html#name-reinitialization).

Reinitialization happens in two phases:

1. A member proposes a ReInit and someone commits it. A commit that references a
   ReInit proposal must contain no other proposals. Once the commit is merged,
   the old group is **suspended**: it becomes inactive and can no longer be used
   for regular operations. Its only remaining purpose is to seed the successor
   group exactly once.
2. One member creates the successor group with the parameters from the ReInit
   proposal, adds all the other members, and mixes in a resumption PSK from the
   old group's final epoch. The other members join the successor group from the
   resulting Welcome.

## Committing a ReInit

A commit containing a ReInit proposal cannot contain other proposals, and merging
it suspends the old group. After this, `MlsGroup::is_active` returns `false` and
further operations on the old group fail — the only remaining use of the old group
is to seed the successor.

Since the ReInit proposal must be committed alone, it is advisable to commit it
directly by value:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_commit_value}}
```

Alternatively to commit-by-value, the ReInit can be proposed and committed separately:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_propose}}
```

Commit the proposal:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_commit}}
```

Every other member processes and merges the commit, which suspends their view of
the group as well:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_process}}
```

## Creating the successor group

All members export a `ReInitInfo` from their suspended old group
with [`MlsGroup::reinit_info`](https://docs.rs/openmls/latest/openmls/group/struct.MlsGroup.html),
passing the ReInit proposal the suspending commit covered. `reinit_info` returns
`None` if the group is still active. The `ReInitInfo` contains all details needed to complete the
reinit, so the old group can be discarded. The info carries the old group's
resumption PSK secret and must be handled as sensitive key material.

The committer or any ther member uses [`CommitBuilder::reinit`](https://docs.rs/openmls/latest/openmls/group/struct.CommitBuilder.html)
to seed the new group with it. The application is responsible for
seeding only a single successor from a suspended group:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_successor}}
```

## Joining the successor group

The other members then join the successor group from the Welcome with
[`StagedWelcome::build_from_reinit`](https://docs.rs/openmls/latest/openmls/group/struct.StagedWelcome.html).
This injects the old group's resumption PSK and verifies that the reinit PSK in
the Welcome references the old group and its final epoch; otherwise it fails with
`WelcomeError::ReInitPredecessorMismatch`. The remaining checks run when `build`
is called on the returned `JoinBuilder`: the successor's protocol version,
ciphersuite, group id and extensions must match the ReInit proposal, the
successor must be at epoch 1.

New group's members must be identical to the old group's. A simple membership check by
equal credential is on by default and can be disabled with
`JoinBuilder::check_members(false)`. In that case, the application **must** ensure that the new
member credentials match the old ones captured in `ReInitInfo::member_credentials()`.
This is the case when the application uses credentials that don't allow checking
equivalence of members by checking exact equality of credentials.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_join}}
```

If the receiver does not yet know which old group a Welcome belongs to or whether it
is a reinit at all, it can decrypt the Welcome once with `StagedWelcome::process_psk_welcome`,
read the reinit PSK's old group id and epoch with `required_resumption_secret()`, select the
matching `ReInitInfo`, and finish with `PendingPskWelcome::build_from_reinit`.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:pending_welcome}}
```
