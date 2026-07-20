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
to seed it from the suspended old group. This consumes the old group's pending
ReInit, so a suspended group can seed only a single successor:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_successor}}
```

## Joining the successor group

The other members join the successor group from the Welcome with
[`StagedWelcome::new_from_reinit`](https://docs.rs/openmls/latest/openmls/group/struct.StagedWelcome.html),
passing their suspended old group so the library can inject the resumption PSK
and check that the successor's parameters and membership match the ReInit:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reinit_join}}
```
