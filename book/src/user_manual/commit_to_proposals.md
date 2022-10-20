# Committing to pending proposals

During an epoch, members can create proposals that are not immediately committed. These proposals are called "pending proposals". They will automatically be covered by any operation that creates a Commit message (like `.add_members(),` `.remove_members()`, etc.).

Some operations (like creating application messages) are not allowed as long as pending proposals exist for the current epoch. In that case, the application must first commit to the pending proposals by creating a Commit message that covers these proposals. This can be done with the `commit_to_pending_proposals()` function:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:commit_to_proposals}}
```

The function returns the tuple `(MlsMessageOut, Option<Welcome>)`. The `MlsMessageOut` contains a Commit message that needs to be fanned out to existing group members.
If the Commit message also covers Add Proposals previously received in the epoch, a `Welcome` message is required to invite the new members. Therefore the function can also optionally return a `Welcome` message that must be sent to the newly added members.
