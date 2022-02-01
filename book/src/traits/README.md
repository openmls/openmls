# Traits & External Types

OpenMLS defines a number of traits that have to be implemented in order to use
OpenMLS.

- [Traits](./traits.md)
- [External Types](./types.md)

## Using the key store

The key store is probably one of the most interesting traits because applications
that use OpenMLS will interact with it.

In the following examples we have a `ciphersuite` and a `backend` (`OpenMlsCryptoProvider`).

```rust,no_run,noplayground
{{#include ../../../openmls/tests/key_store.rs:10:32}}
```

In order to delete a value the `delete` is called with the identifier.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/key_store.rs:36:39}}
```

Retrieving a value from the key store is as simple as calling `read`.
In this example we assume that we got a `credential` where we want to retrieve
the credential bundle for, i.e. the private key material.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/key_store.rs:69:79}}
```
