# Pending Commits

This document describes the lifecycle of pending commits in OpenMLS:
when a pending commit is created, when it should be merged or cleared,
and what happens when another commit is processed.

The terminology and examples follow the OpenMLS API and are intended to
describe behavior rather than prescribe an application-specific delivery
architecture.

> **Version note.** Some behavior described here depends on the OpenMLS
> release. In particular, `ProcessedMessageContent::OwnPendingCommit`
> (Section 5) requires **OpenMLS 0.9.0 or later**. Method names in the
> list in Section 1 should be checked against the version you target.

## 1. Creating a pending commit

A pending commit is created when a local operation creates a `Commit`
without immediately applying that commit to the local group state.

Commit-producing operations include:

-   `add_members`
-   `add_members_without_update`
-   `remove_members`
-   `swap_members`
-   `self_update`
-   `commit_to_pending_proposals`
-   `commit_builder`

For example, if the group is currently at epoch 10:

``` text
Epoch 10
   |
   | add_members(...)
   v
Pending commit
   |
   v
Group remains at epoch 10
```

The commit represents the transition to the next epoch, but the local
group does not advance until the pending commit is merged.

Only one pending commit can exist at a time. While a pending commit
exists, another operation that creates a commit returns an error.

## 2. Merging a pending commit

Call `merge_pending_commit()` when the locally created commit has been
accepted by the application-level delivery mechanism.

``` text
Create commit
     |
     v
Pending commit
     |
     | commit accepted
     v
merge_pending_commit()
     |
     v
New group state / new epoch
```

For example:

``` text
Before:

Current epoch: 10
Pending commit: Commit for epoch 11

After merge_pending_commit():

Current epoch: 11
Pending commit: none
```

The important distinction is that **creating a commit and merging a
commit are separate operations**.

Creating the commit stages the state transition. Merging it makes that
state the current local group state.

If the group has no pending commit (for example, it is already
`Operational` because the commit was superseded), calling
`merge_pending_commit()` does not apply anything. Do not rely on this as
a safety net; track the state of your own commits explicitly.

## 3. Clearing a pending commit

Call `clear_pending_commit()` when the locally created commit should be
abandoned.

A typical example is a delivery failure or an application-level
rejection:

``` text
Create commit
     |
     v
Pending commit
     |
     | rejected / abandoned
     v
clear_pending_commit()
     |
     v
Original group state remains
```

For example:

``` text
Before:

Current epoch: 10
Pending commit: Commit for epoch 11

After clear_pending_commit():

Current epoch: 10
Pending commit: none
```

Clearing a pending commit does not advance the group epoch.

**Only clear a commit that is known not to have been accepted.** If the
commit may already have been delivered to other members (for example, a
publish that timed out but actually succeeded), clearing it can leave
you out of sync with the rest of the group, because they may advance to
epoch 11 while you remain at epoch 10. 

After clearing, proposals and other state that fed into the abandoned
commit are not automatically re-committed. If those changes are still
wanted, create a new commit.

## 4. Another member's commit arrives first

A pending commit does not reserve the next epoch for the local member.

Consider two members, Alice and Bob:

``` text
Alice                           Bob

Epoch 10                        Epoch 10
   |                               |
   | create commit                 | create commit
   v                               v
Pending Alice commit          Bob's commit
   |                               |
   |                               |
   |<--------- Bob's commit -------|
   |
   v
process Bob's commit
```

Processing another member's commit takes two steps:

1.  `process_message()` validates the commit and returns it as a staged
    commit. At this point the group state has not changed, and Alice's
    pending commit still exists.
2.  Merging the staged commit (`merge_staged_commit()`) applies Bob's
    commit. This advances the epoch and sets the group state back to
    `Operational`, which clears Alice's pending commit.

The resulting state is:

``` text
Before:

Epoch 10
Pending Alice commit

        |
        | process_message(Bob's commit)  -> staged commit
        | merge_staged_commit()
        v

After:

Epoch 11
No pending commit
Bob's commit is the current commit
```

The application must not subsequently call `merge_pending_commit()` for
Alice's old pending commit. That pending commit has already been
superseded.

The clearing of the pending commit is performed by OpenMLS as part of
merging the other member's staged commit; the application does not need
to call `clear_pending_commit()` itself. If your application declines to
merge the staged commit, Alice's pending commit remains in place.

## 5. The local commit is received back

In a delivery-service architecture, the commit created by a member may
be delivered back to that same member.

**Requires OpenMLS 0.9.0 or later.** From 0.9.0, if the received commit
was authored by this client and matches the group's pending commit,
`process_message()` returns
`ProcessedMessageContent::OwnPendingCommit` rather than treating it as
an unrelated remote commit. Callers should then merge the existing
pending commit with `merge_pending_commit()`. In earlier versions this
variant does not exist, and the application is responsible for
recognizing its own echoed messages and merging the pending commit
itself.

The processing flow is:

``` text
Create local commit
       |
       v
Pending commit
       |
       | send to delivery service
       v
Commit delivered back to creator
       |
       v
process_message() -> OwnPendingCommit
       |
       v
merge_pending_commit()
       |
       v
New group epoch
```

The application should merge the existing pending commit rather than
create or process a second local state transition.

Notes:

-   Echoed own messages that are not matching commits (for example,
    application messages sent by this client) are reported through a
    separate variant, `ProcessedMessageContent::OwnPrivateMessage`,
    which was also introduced in 0.9.0. In earlier versions these
    surfaced as a `CannotDecryptOwnMessage` error.
-   With the default wire format policy (ciphertext), an own commit
    sent as a `PrivateMessage` may be reported as an echoed own private
    message, because the sender is identified from the message's sender
    data before the commit is inspected. Applications have reported
    that in this configuration `OwnPendingCommit` is not reached, so
    verify which variant your configuration produces and handle both.
-   From 0.9.0, an own commit without an update path that does **not**
    match the pending commit is staged as a regular commit instead of
    being rejected.

## 6. Proposals are not pending commits

Proposal-producing operations do not create a pending commit.

For example:

``` text
propose_add_member(...)
```

creates a proposal:

``` text
Proposal
   |
   v
No pending commit
```

A later commit can include that proposal.

Therefore:

``` text
Proposal != Pending commit
```

A proposal does not require `merge_pending_commit()` or
`clear_pending_commit()`.

## 7. External commits

External commits have a different lifecycle.

A group created by joining through an external commit (for example,
with `external_commit_builder` or `join_by_external_commit`) starts with
a pending commit that must be merged. Until it is merged, the only
functionality available on the group is `merge_pending_commit()`.

Unlike an ordinary pending commit, an external commit cannot be cleared
with `clear_pending_commit()`.

The recovery path when an external commit is rejected is to discard the
`MlsGroup` and create a new group state from the latest group
information.

``` text
external_commit_builder()
          |
          v
Pending commit
          |
          +----------------------+
          |                      |
          | accepted             | rejected
          v                      v
merge_pending_commit()      discard MlsGroup
          |                 and recreate
          v
New group state
```

## 8. Lifecycle summary

### Local commit accepted

``` text
Create commit
    |
    v
Pending commit
    |
    | accepted
    v
merge_pending_commit()
    |
    v
Epoch advances
```

### Local commit rejected

``` text
Create commit
    |
    v
Pending commit
    |
    | rejected (known not accepted) / abandoned
    v
clear_pending_commit()
    |
    v
Epoch unchanged
```

### Another member commits first

``` text
Create local commit
    |
    v
Pending commit
    |
    | receive another member's commit
    v
process_message() -> staged commit
    |
    | merge_staged_commit()
    v
Pending commit cleared by OpenMLS
    |
    v
Other commit becomes current
    |
    v
Epoch advances
```

### Own commit is received back (OpenMLS 0.9.0+)

``` text
Create local commit
    |
    v
Pending commit
    |
    | own commit received
    v
OwnPendingCommit
    |
    v
merge_pending_commit()
    |
    v
Epoch advances
```

## 9. Key points

-   Commit creation stages a local state transition.
-   A pending commit does not by itself advance the local group state.
-   `merge_pending_commit()` applies the staged local commit.
-   `clear_pending_commit()` abandons an ordinary pending commit. Only
    use it when the commit is known not to have been accepted.
-   Processing another member's commit stages it; merging that staged
    commit (`merge_staged_commit()`) automatically clears a local
    pending commit.
-   An old pending commit must not be merged after it has been
    superseded by another member's commit.
-   From OpenMLS 0.9.0, a member receiving its own pending commit is
    notified through `OwnPendingCommit` and can then merge the existing
    pending commit.
-   Proposals do not create pending commits.
-   External commits have a special pending-commit lifecycle and cannot
    be cleared using `clear_pending_commit()`.