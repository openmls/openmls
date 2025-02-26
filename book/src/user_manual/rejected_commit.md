# Rejected commits

The delivery service may reject a commit sent by a client. In this case, the application needs to ensure that the local state remains the same as it was before the commit was staged.

In general, when a commit is discarded, the application needs to clear the pending commit in the `MlsGroup` and reset its state. 
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reject_commit_add}}
```

## Update commit
When a commit containing an Update proposal was created, as in the following example:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reject_commit_update_setup}}
```
If the commit is discarded, the local state can be cleaned up in the following way:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reject_commit_update}}
```

## Add commit
If a commit containing and Add proposal was created, as in the following example:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reject_commit_add_setup}}
```
If the commit is discarded, the local state can be cleaned up in the following way:
```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:reject_commit_add}}
```
