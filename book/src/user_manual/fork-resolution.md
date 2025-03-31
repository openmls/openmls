# Fork Resolution

If members of a group merge different commits, the group state is called forked.
At this point, the group members have different keys and will not be able to decrypt
each others' messages. While this should not happen in normal operation, it may
still occur due to bugs. When enabling the `fork-resolution-helpers` feature,
OpenMLS comes with helpers to get a working group again. There are two helpers,
and they use different mechanisms.

The `readd` helper removes and then re-adds members that are forked. This requires
that the caller knows the set of members that are forked. It is relatively
efficient, especially if only a small number of members forked.

The `reboot` helper creates a new group and helps with migrating the entire group
state over. This includes extensions in the group context, as well as re-inviting
all the members.

We provide examples for how to use both, and in the end provide some guidance on
detecting forks.

## `readd` Example

First, let's create a forked group. In this example, Alice creates a group and
adds Bob. Then, they both merge different commits to add Charlie.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_fork_resolution.rs:readd_prepare_group}}
```

Then, Alice removes and re-adds Bob using the helper.
We assume here that Alice knows that only Bob merged the wrong commit. This
information needs to be transferred somehow, see [Fork Detection].
Notice how Alice needs to provide a new key package for Bob.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_fork_resolution.rs:readd_do_it}}
```

In the end, they all can communicate again.

## `reboot` Example

Again, let's create a forked group. In this example, Alice creates a group and
adds Bob. Then, they both merge different commits to add Charlie.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_fork_resolution.rs:reboot_prepare_group}}
```

Then, Alice sets up a new group and adds everyone from the old group. In this
approach, she not only needs to provide key packages for all members, but also
set a new group id and migrate the group context extensions, because these might
be contain e.g. the old group id. This is the responsibility of the application,
so the API just exposes the old extensions and expects the new ones.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_fork_resolution.rs:reboot_do_it}}
```

In the end, they all can communicate again.

## Fork Detection

Before initiating fork resolution, we first need to detect that a fork happened.
In addition, for using the `readd` mechanism, we also need to know the members
that forked.

One simple technique that may work, depending on how the delivery service works,
is to consider all incoming non-decryptable messages as a sign that there is a fork.
However, this may lead to false positives and is not enough to know the membership.

One way to learn about this that every member send a message when they merges a
commit, encrypted for the old epoch, that contains the hash of the commit they are
merging. This way, all group members know which commits are merged, and the `readd`
strategy can be used to resolve possible forks.

[Fork Detection]: #fork-detection
