# Join a group from a Welcome message

To join a group from a `Welcome` message, a new `MlsGroup` can be instantiated directly from the `Welcome` message.
If the group configuration does not use the ratchet tree extension, the ratchet tree needs to be provided.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:bob_joins_with_welcome}}
```

Pay attention not to forward a Welcome message to a client before its associated commit has been accepted by the
Delivery Service. Otherwise, you would end up with an invalid MLS group instance.
