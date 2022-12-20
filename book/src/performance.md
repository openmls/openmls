# Performance

How does OpenMLS (and MLS in general) perform in different settings?

Performance measurements are implemented [here](https://github.com/openmls/openmls/blob/franziskus/benchmarks/benches/group.rs) and can be run with `cargo bench --bench group`.
Check which scenarios and group sizes are enabled in the code.

[OpenMLS Performance Spreadsheet](https://docs.google.com/spreadsheets/d/1nZv8lpT28JctDVo4ARBLZCKcIdvo-h8cIyN3_dIedFU)

## Real World Scenarios

### Stable group

Many private groups follow this model.

- Group is created by user P1
- P1 invites a set of N other users
- The group is used for messaging between the N+1 members
- Every X messages, one user in the group sends an update

### Somewhat stable group

This can model a company or team-wide group where regularly but infrequently, users are added, and users leave.

- Group is created by user P1
- P1 invites a set of N other users
- The group is used for messaging between the members
- Every X messages, one user in the group sends an update
- Every Y messages, Q users are added
- Every Z messages, R users are removed

### High fluctuation group

This models public groups where users frequently join and leave.
Real-time scenarios such as [gather.town](https://gather.town) are examples of high-fluctuation groups.
It is the same scenario as the somewhat stable group but with a very small Y and Z.

## Extreme Scenarios

In addition to the three scenarios above extreme and corner cases are interesting.

### Every second leave is blank

Only every second leave in the tree is non-blank.

## Use Case Scenarios

A collection of common use cases/flows from everyday scenarios.

### Long-time offline device

Suppose a device has been offline for a while. In that case, it has to process a large number of application and protocol messages.

## Tree scenarios

In addition to the scenarios above, it is interesting to look at the same scenario but with different states of the tree.
For example, take the stable group with N members messaging each other.
What is the performance difference between a message sent right after group setup, i.e., each member only joined the group without other messages being sent, and a tree where every member has sent an update before the message?

## Measurements

- Group creation
  - create group
  - create proposals
  - create welcome
  - apply commit
- Join group
  - create group from welcome
- Send application message
- Receive application message
- Send update
  - create proposal
  - create commit
  - apply commit
- Receive update
  - apply commit
- Add user sender
  - create proposal
  - create welcome
  - apply commit
- Existing user getting an add
  - apply commit
- Remove user sender
  - create proposal
  - create commit
  - apply commit
- Existing user getting a remove
  - apply commit
