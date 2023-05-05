# Credential validation

Credential validation is a process that allows a member to verify the validity
of the credentials of other members in the group.  The process is described in
detail in the [MLS protocol
specification](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-credential-validation).

In practice, the application should check the validity of the credentials of
other members in two instances:

 - When joining a new group (by looking at the ratchet tree)
 - When [processing messages](./processing.md) (by looking at a add & update proposals of a StagedCommit)