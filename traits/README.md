# OpenMLS Traits

This crate defines a number of traits that have to be implemented in order to use OpenMLS.

The OpenMLS repository provides a default implementation for these traits

- [Rust Crypto](../openmls_rust_crypto/README.md)

**⚠️ These traits are responsible for all cryptographic operations and randomness within OpenMLS. Please ensure you know what you're doing when implementing your own versions.**

## Traits

There are 3 different traits.

### OpenMlsCrypto

This [trait](./src/crypto.rs) defines all cryptographic functions required by OpenMLS, in particular

- HKDF
- Hashing
- AEAD
- Signatures
- HPKE
- Randomness

### StorageProvider

This [trait](./src/storage.rs) defines a CRUD API for a key store that is used to store long-term key material from OpenMLS.

### OpenMlsProvider

Additionally, there's a wrapper [trait](./src/traits.rs) defined that is expected to be passed into the public OpenMLS API.

## Types

For interoperability this crate also defines a number of [types](./src/types.rs) and algorithm identifiers.
