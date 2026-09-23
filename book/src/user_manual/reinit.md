# Reinitializing a group

Reinitialization (ReInit) replaces a group with a brand-new *successor* group
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

## Proposing a ReInit

A member proposes the reinitialization with
[`MlsGroup::propose_reinit`](https://docs.rs/openmls/latest/openmls/group/struct.MlsGroup.html),
describing the successor group's parameters:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_propose}}
```

## Committing the ReInit (suspending the old group)

Committing and merging the ReInit proposal suspends the old group. After this,
`MlsGroup::is_active` returns `false` and further operations on the old group
fail — the only remaining use of the old group is to seed the successor:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_commit}}
```

Every other member processes and merges the commit, which suspends their view of
the group as well:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_process}}
```

The ReInit may also be committed *by value* by adding the proposal directly to
the commit with `CommitBuilder::add_proposal(Proposal::re_init(..))` instead of
proposing it separately first.

## Creating the successor group

The committer (or any member) creates a fresh group with the ReInit parameters
and uses [`CommitBuilder::reinit`](https://docs.rs/openmls/latest/openmls/group/struct.CommitBuilder.html)
to seed it from the suspended old group. The application is responsible for
seeding only a single successor from a suspended group:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_successor}}
```

## Joining the successor group

The other members first export a `ReInitInfo` from their suspended old group
with [`MlsGroup::reinit_info`](https://docs.rs/openmls/latest/openmls/group/struct.MlsGroup.html),
passing the ReInit proposal the suspending commit covered. `reinit_info` returns
`None` if the group is still active. The `ReInitInfo` is an owned snapshot, so the
old group is not needed to complete the join. It carries the old group's
resumption PSK secret and must be handled as sensitive key material.

They then join the successor group from the Welcome with
[`StagedWelcome::build_from_reinit`](https://docs.rs/openmls/latest/openmls/group/struct.StagedWelcome.html).
This injects the old group's resumption PSK and verifies that the reinit PSK in
the Welcome references the old group and its final epoch; otherwise it fails with
`WelcomeError::ReInitPredecessorMismatch`. The remaining checks run when `build`
is called on the returned `JoinBuilder`: the successor's protocol version,
ciphersuite, group id and extensions must match the ReInit proposal, the
successor must be at epoch 1, and its members' credentials must be identical to
the old group's. The membership check is on by default and can be disabled with
`.check_members(false)`.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_join}}
```

If the receiver does not yet know which old group the Welcome belongs to, it can
decrypt the Welcome once with `StagedWelcome::process_psk_welcome`, read the reinit
PSK's old group id and epoch with `required_resumption_secret()`, select the
matching `ReInitInfo`, and finish with `PendingPskWelcome::build_from_reinit`.
