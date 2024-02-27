# Join a group from a Welcome message

To join a group from a `Welcome` message, a new `MlsGroup` can be instantiated from
the `MlsMessageIn` message containing the `Welcome` and an `MlsGroupJoinConfig`
(see [Group configuration](./group_config.md) for more details).  This is a
two-step process: a `StagingMlsJoinFromWelcome` is constructed from the `Welcome`
and can then be turned into an `MlsGroup`.  If the group configuration does not
use the ratchet tree extension, the ratchet tree needs to be provided.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:bob_joins_with_welcome}}
```

The reason for this two-phase process is to allow the recipient of a `Welcome`
to inspect the message, e.g. to determine the identity of the sender.

Pay attention not to forward a Welcome message to a client before its associated
commit has been accepted by the Delivery Service.  Otherwise, you would end up
with an invalid MLS group instance.
