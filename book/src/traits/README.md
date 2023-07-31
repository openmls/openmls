# Traits & External Types

OpenMLS defines several traits that have to be implemented to use
OpenMLS.
The main goal is to allow OpenMLS to use different implementations for its
cryptographic primitives, persistence, and random number generation.
This should make it possible to plug in anything from [WebCrypto] to secure
enclaves.

- [Traits](./traits.md)
- [External Types](./types.md)

## Using the key store

The key store is probably one of the most interesting traits because applications
that use OpenMLS will interact with it.
See the [OpenMlsKeyStore trait](./traits.md#openmlskeystore) description for details
but note that the key used to store, read, and delete values in the key store has
to be provided as a byte slice.

In the following examples, we have a `ciphersuite` and a `provider` (`OpenMlsCryptoProvider`).

```rust,no_run,noplayground
{{#include ../../../openmls/tests/key_store.rs:key_store_store}}
```

The `delete` is called with the identifier to delete a value.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/key_store.rs:key_store_delete}}
```

Retrieving a value from the key store is as simple as calling `read`.
In this example, we assume we got a `credential` where we want to retrieve the credential bundle, i.e., the private key material.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/key_store.rs:key_store_read}}
```

[//]: # "links"
[webcrypto]: https://www.w3.org/TR/WebCryptoAPI/
