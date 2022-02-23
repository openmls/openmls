# OpenMLS Traits

> **⚠️  These traits are responsible for all cryptographic operations and randomness
> within OpenMLS.
> Please ensure you know what you're doing when implementing your own versions.**

Because implementing the `OpenMLSCryptoProvider` is challenging, requires
tremendous care, and is not what the average OpenMLS consumer wants to (or should) do,
we provide two implementations that can be used.

- [Rust Crypto]
- [Evercrypt]

**Rust Crypto Provider**
The go-to default at the moment is an implementation using commonly used, native Rust
crypto implementations.

**Evercrypt Provider**
In addition to the Rust Crypto Provider there's the Evercrypt provider that uses
the formally verified HACL\*/Evercrypt library.
Note that this provider does not work equally well on all platforms yet.

## The Traits

There are 4 different traits defined in the [OpenMLS traits crate].

### OpenMlsRand

This trait defines two functions to generate arrays and vectors, and is used by
OpenMLS to generate randomness for key generation and random identifiers.
While there is the commonly used [rand crate] not all implementations use it.
OpenMLS therefore defines its own randomness trait that needs to be implemented
by an OpenMLS crypto provider.
It simply needs to implement two functions to generate cryptographically secure
randomness and store it into an array or vector.

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

**NOTE:** Right now key material needs to be extractable from the key store.
This will most likely change in future.

### OpenMlsCryptoProvider

Additionally, there's a wrapper trait defined that is expected to be passed into
the public OpenMLS API.
Some OpenMLS APIs require only one of the sub-traits though.

```rust,no_run,noplayground
{{#include ../../../traits/src/traits.rs:15:28}}
```

## Implementation Notes

It is not necessary to implement all sub-traits if one functionality is missing.
If you want to use a persisting key store for example, it is sufficient to do a new implementation of the key store trait and combine it with one of the provided crypto and randomness trait implementations.

[rust crypto]: https://crates.io/crates/openmls_rust_crypto
[evercrypt]: https://crates.io/crates/openmls_evercrypt_backend
[openmls traits crate]: https://crates.io/crates/openmls_traits
[rand crate]: https://crates.io/crates/rand
