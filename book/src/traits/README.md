# Traits & External Types

OpenMLS defines several traits that have to be implemented to use
OpenMLS.
The main goal is to allow OpenMLS to use different implementations for its
cryptographic primitives, persistence, and random number generation.
This should make it possible to plug in anything from [WebCrypto] to secure
enclaves.

- [Traits](./traits.md)
- [External Types](./types.md)

## Using storage

The store is probably one of the most interesting traits because applications
that use OpenMLS will interact with it.
See the [StorageProvider trait](./traits.md#storageprovider) description for details.

In the following examples, we have a `ciphersuite` and a `provider` (`OpenMlsProvider`).

```rust,no_run,noplayground
{{#include ../../../openmls/tests/store.rs:store_store}}
```

Retrieving a value from the store is as simple as calling `read`.
The retrieved key package bundles the private keys for the init and encryption keys
as well.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/store.rs:store_read}}
```

The `delete` is called with the identifier to delete a value.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/store.rs:store_delete}}
```

[//]: # "links"
[webcrypto]: https://www.w3.org/TR/WebCryptoAPI/
