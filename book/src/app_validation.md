# App Validation

> **NOTE:** This chapter described the validation steps an application, using OpenMLS, has to perform for safe operation of the MLS protocol.
>
> **⚠️** This chapter is work in progress.

## Proposal Validation

When processing a commit, the application has to ensure that the application
specific semantic checks for the validity of the committed proposals are performed.

This should be done on the `StagedCommit`. Also see the [Message Processing](./user_manual/processing.md)
chapter

```rust,no_run,noplayground
{{#include ../../openmls/tests/book_code.rs:inspect_staged_commit}}
```

### External Commits

The RFC requires the following check

> At most one Remove proposal, with which the joiner removes an old version of themselves. If a Remove proposal is present, then the LeafNode in the path field of the external Commit MUST meet the same criteria as would the LeafNode in an Update for the removed leaf (see Section 12.1.2). In particular, the credential in the LeafNode MUST present a set of identifiers that is acceptable to the application for the removed participant.

Since OpenMLS does not know the relevant policies, the application MUST ensure
that the credentials are checked according to the policy.
