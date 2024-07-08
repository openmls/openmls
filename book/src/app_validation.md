# App Validation

> **NOTE:** This chapter described the validation steps an application, using OpenMLS, has to perform for safe operation of the MLS protocol.
>
> **⚠️** This chapter is work in progress (see [#1504](https://github.com/openmls/openmls/issues/1504)).

## Credential Validation

### Acceptable Presented Identifiers

> The application using MLS is responsible for specifying which identifiers
> it finds acceptable for each member in a group. In other words, following
> the model that [[RFC6125]] describes for TLS, the application maintains a list
> of "reference identifiers" for the members of a group, and the credentials
> provide "presented identifiers". A member of a group is authenticated by first
> validating that the member's credential legitimately represents some presented
> identifiers, and then ensuring that the reference identifiers for the member
> are authenticated by those presented identifiers
>
> -- [RFC9420, Section 5.3.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3.1-1)
>
### Validity of Updated Presented Identifiers

> In cases where a member's credential is being replaced, such as the Update and
> Commit cases above, the AS MUST also verify that the set of presented identifiers
> in the new credential is valid as a successor to the set of presented identifiers
> in the old credential, according to the application's policy.
>
> -- [RFC9420, Section 5.3.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3.1-5)

### Application ID is Not Authenticed by AS

> However, applications MUST NOT rely on the data in an application_id extension
> as if it were authenticated by the Authentication Service, and SHOULD gracefully
> handle cases where the identifier presented is not unique.
>
> -- [RFC9420, Section 5.3.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3.3-6)

## LeafNode Validation

### Specifying the Maximum Total Acceptable Lifetime

> Applications MUST define a maximum total lifetime that is acceptable for a
> LeafNode, and reject any LeafNode where the total lifetime is longer than this
> duration. In order to avoid disagreements about whether a LeafNode has a valid
> lifetime, the clients in a group SHOULD maintain time synchronization (e.g.,
> using the Network Time Protocol [[RFC5905]]).
>
> -- [RFC9420, Section 7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2-10)

## PrivateMessage Validation

### Structure of AAD is Application-Defined

> It is up to the application to decide what authenticated_data to provide and
> how much padding to add to a given message (if any). The overall size of the
> AAD and ciphertext MUST fit within the limits established for the group's AEAD
> algorithm in [[CFRG-AEAD-LIMITS]].
>
> -- [RFC9420, Section 6.3.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.3.1-11)

Therefore, the application must also validate whether the AAD adheres to the
prescribed format.

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

[RFC6125]: https://www.rfc-editor.org/rfc/rfc6125.html
[RFC5905]: https://www.rfc-editor.org/rfc/rfc5905.html
[CFRG-AEAD-LIMITS]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aead-limits-08
