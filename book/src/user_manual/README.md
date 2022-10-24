# User manual 

The user manual describes how to use the different parts of the OpenMLS API.

## Prerequisites

Most operations in OpenMLS require a `backend` object that provides all required cryptographic algorithms via the [`OpenMlsCryptoProvider`] trait.
Currently, there are two implementations available through the [openmls_rust_crypto] and [openmls_evercrypt] crates.

Thus, you can create the `backend` object for the following examples using ...

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:create_backend_rust_crypto}}
```

... or ...

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:create_backend_evercrypt}}
```

[`OpenMlsCryptoProvider`]: https://docs.rs/openmls/latest/openmls/prelude/trait.OpenMlsCryptoProvider.html
[openmls_rust_crypto]: https://crates.io/crates/openmls_rust_crypto
[openmls_evercrypt]: https://crates.io/crates/openmls_evercrypt
