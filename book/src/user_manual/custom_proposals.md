# Custom proposals

OpenMLS allows the creation and use of application-defined proposals. To create such a proposal, the application needs to define a Proposal Type in such a way that its value doesn't collide with any Proposal Types defined in Section 17.4. of RFC 9420. If the proposal is meant to be used only inside of a particular application, the value of the Proposal Type is recommended to be in the range between `0xF000` and `0xFFFF`, as that range is reserved for private use.

Custom proposals can contain arbitrary octet-strings as defined by the application. Any policy decisions based on custom proposals will have to be made by the application, such as the decision to include a given custom proposal in a commit, or whether to accept a commit that includes one or more custom proposals. To decide the latter, applications can inspect the queued proposals in a `ProcessedMessageContent::StagedCommitMessage(staged_commit)`.

Example on how to use custom proposals:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:custom_proposal_type}}
```

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:custom_proposal_usage}}
```
