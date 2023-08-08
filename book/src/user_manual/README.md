# User manual

The user manual describes how to use the different parts of the OpenMLS API.

## Prerequisites

Most operations in OpenMLS require a `provider` object that provides all required cryptographic algorithms via the [`OpenMlsCryptoProvider`] trait.
Currently, there are two implementations available through the [openmls_rust_crypto] crate.

Thus, you can create the `provider` object for the following examples using ...

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:create_provider_rust_crypto}}
```

[`openmlscryptoprovider`]: https://docs.rs/openmls/latest/openmls/prelude/trait.OpenMlsCryptoProvider.html
[openmls_rust_crypto]: https://crates.io/crates/openmls_rust_crypto
