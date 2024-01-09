# Credential validation

Credential validation is a process that allows a member to verify the validity
of the credentials of other members in the group.  The process is described in
detail in the [MLS protocol
specification](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-credential-validation).

In practice, the application should check the validity of the credentials of
other members in two instances when joining the group and when [processing messages].

The precise checks that need to be done are:

#### When joining a Group

A group can be joined from a `Welcome` message using
`MlsGroup::new_from_welcome`. After joining the group, the credentials of the
tree leaves need to be validated:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:bob_joins_with_welcome}}

{{#include ../../../openmls/tests/book_code.rs:welcome_validate_credentials}}
```

#### When processing Messages

Once a group is created, the credentials contained in incoming commit messages,
as well as the contained proposals, need to be validated:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:process_message}}

{{#include ../../../openmls/tests/book_code.rs:staged_commit_validate_credentials}}
```

[processing messages]: ./processing.md
