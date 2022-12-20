# Leaving a group

Members can indicate to other group members that they wish to leave the group using the `leave_group()` function, which creates a remove proposal targeting the member's own leaf. The member can't create a Commit message that covers this proposal, as that would violate the Post-compromise Security guarantees of MLS because the member would know the epoch secrets of the next epoch.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:leaving}}
```

After successfully sending the proposal to the DS for fanout, there is still the possibility that the remove proposal is not covered in the following commit. The member leaving the group thus has two options:

- tear down the local group state and ignore all subsequent messages for that group, or
- wait for the commit to come through and process it (see also [Getting Removed](remove_members.md#getting-removed-from-a-group)).

For details on creating Remove Proposals, see [Removing members from a group](remove_members.md).
