# OpenMLS Traits

This crate defines a number of crates that have to be implemented in order to use OpenMLS.

The OpenMLS repository provides a default implementation for these traits

- [Rust Crypto](../openmls_rust_crypto/README.md)

**⚠️ These traits are responsible for all cryptographic operations and randomness within OpenMLS. Please ensure you know what you're doing when implementing your own versions.**

## Traits

There are 4 different traits.

### OpenMlsRand

This [trait](./src/random.rs) defines two functions to generate arrays and vectors, and is used by OpenMLS to generate randomness.

### OpenMlsCrypto

This [trait](./src/crypto.rs) defines all cryptographic functions required by OpenMLS, in particular

- HKDF
- Hashing
- AEAD
- Signatures
- HPKE

### StorageProvider

This [trait](./src/storage.rs) defines a CRUD API for a key store that is used to store long-term key material from OpenMLS. It is also used to store state for groups.

OpenMLS APIs should be used with StorageProviders that guarantee that group operations are performed atomically, and that access to each single group's data in the storage provider (for both reads and writes) is exclusive. However, the OpenMLS library does not guarantee that these properties hold.

### OpenMlsCryptoProvider

Additionally, there's a wrapper [trait](./src/traits.rs) defined that is expected to be passed into the public OpenMLS API.

## Types

For interoperability this crate also defines a number of [types](./src/types.rs) and algorithm identifiers.
