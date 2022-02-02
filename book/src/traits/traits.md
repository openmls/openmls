# OpenMLS Traits

The OpenMLS project provides two default implementations for these traits

- [Rust Crypto]
- [Evercrypt]

> **⚠️☣️  These traits are responsible for all cryptographic operations and randomness
> within OpenMLS.
> Please ensure you know what you're doing when implementing your own versions.**

## The Traits

There are 4 different traits defined in the [OpenMLS traits crate].

### OpenMlsRand

This trait defines two functions to generate arrays and vectors, and is used by
OpenMLS to generate randomness.

```rust,no_run,noplayground
{{#include ../../../traits/src/random.rs:8:16}}
```

### OpenMlsCrypto

This trait defines all cryptographic functions required by OpenMLS, in particular

- HKDF
- Hashing
- AEAD
- Signatures
- HPKE

```rust,no_run,noplayground
{{#include ../../../traits/src/crypto.rs:10}}
```

### OpenMlsKeyStore

This trait defines a CRUD API for a key store that is used to store long-term
key material from OpenMLS.

The key store provides functions to `store`, `read` and `delete` values.
Note that it does not allow to update values.
Instead entries must be deleted and newly stored.

```rust,no_run,noplayground
{{#include ../../../traits/src/key_store.rs:15:40}}
```

### OpenMlsCryptoProvider

Additionally, there's a wrapper trait defined that is expected to be passed into
the public OpenMLS API.

```rust,no_run,noplayground
{{#include ../../../traits/src/traits.rs:15:28}}
```

[rust crypto]: https://crates.io/crates/openmls_rust_crypto
[evercrypt]: https://crates.io/crates/openmls_evercrypt_backend
[openmls traits crate]: https://crates.io/crates/openmls_traits
