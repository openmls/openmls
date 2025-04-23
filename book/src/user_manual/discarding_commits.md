# Discarding commits

The delivery service may reject a commit sent by a client. In this case, the application needs to ensure that the local state remains the same as it was before the commit was staged.

## Cleaning up local state after discarded commits
Generally, if a commit is discarded (e.g. due to being rejected by the Delivery Service), it can be cleaned up by the application in the following way:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_discard_commit.rs:discard_commit_example}}
```

In general, the application only needs to complete the cleanup above in order to fully restore the local state to the way it was before the commit was staged.

In several other cases, additional cleanup may need to be done.

### ExternalJoin
If a staged commit containing an external join proposal must be discarded, the entire `MlsGroup` instance should be discarded by the application.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_discard_commit.rs:discard_commit_external_join}}
```
### PreSharedKey
In addition to clearing the staged commit, the application may also clear the pre-shared key from storage.
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code_discard_commit.rs:discard_commit_psk}}
```

### Self Update
The storage provider may also be used by the application to store signature keypairs. For self updates that update a signature keypair for the client, if the application has stored a new keypair in the storage provider at this point, it can be deleted from the storage provider here.
