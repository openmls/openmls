# OpenMLS Traits

> **⚠️ These traits are responsible for all cryptographic operations and randomness
> within OpenMLS.
> Please ensure you know what you're doing when implementing your own versions.**

Because implementing the `OpenMLSCryptoProvider` is challenging, requires
tremendous care, and is not what the average OpenMLS consumer wants to (or should)
do, we provide two implementations that can be used.

- [Rust Crypto]
- [Libcrux Crypto]

**Rust Crypto Provider**
The go-to default at the moment is an implementation using commonly used, native
Rust crypto implementations.

**Libcrux Crypto Provider**
A crypto provider backed by the high-assurance cryptography library [libcrux].
Currently only supports relatively modern x86 and amd64 CPUs, as it requires
AES-NI, SIMD and AVX.

## The Traits

There are 4 different traits defined in the [OpenMLS traits crate].

### OpenMlsRand

This trait defines two functions to generate arrays and vectors, and is used by
OpenMLS to generate randomness for key generation and random identifiers.
While there is the commonly used [rand crate], not all implementations use it.
OpenMLS, therefore, defines its own randomness trait that needs to be implemented
by an OpenMLS crypto provider.
It simply needs to implement two functions to generate cryptographically secure
randomness and store it in an array or vector.

```rust,no_run,noplayground
{{#include ../../../traits/src/random.rs:openmls_rand}}
```

### OpenMlsCrypto

This trait defines all cryptographic functions required by OpenMLS. In particular:

- HKDF
- Hashing
- AEAD
- Signatures
- HPKE

### StorageProvider

This trait defines an API for a storage backend that is used for all OpenMLS
persistence.

The store provides functions for reading and updating stored values.
Each sort of value has separate methods for accessing or mutating the state.
In order to decouple the provider from the OpenMLS implementation, while still
having legible types at the provider, there are traits that mirror all the types
stored by OpenMLS. The provider methods use values constrained by these traits as
as arguments.

```rust,no_run,noplayground
{{#include ../../../traits/src/storage.rs:traits}}
```

The traits are generic over a `VERSION`, which is used to ensure that the values
that are persisted can be upgraded when OpenMLS changes the stored structs.

The traits used as arguments to the storage methods are constrained to implement
the `Key` or `Entity` traits as well, depending on whether they are only used for
addressing (in which case they are a `Key`) or whether they represent a stored
value (in which case they are an `Entity`).

```rust,no_run,noplayground
{{#include ../../../traits/src/storage.rs:key_trait}}
```

```rust,no_run,noplayground
{{#include ../../../traits/src/storage.rs:entity_trait}}
```

An implementation of the storage trait should ensure that it can address and
efficiently handle values.

#### Example: Key packages

This is only an example, but it illustrates that the application may need to do more
when it comes to implementing storage.

Key packages are only deleted by OpenMLS when they are used and _not_ last resort
key packages (which may be used multiple times).
The application needs to implement some logic to manage last resort key packages.

```rust,no_run,noplayground
{{#include ../../../traits/src/storage.rs:write_key_package}}
```

The application may store the hash references in a separate list with a validity
period.

```rust,ro_run,noplayground
fn write_key_package<
    HashReference: traits::HashReference<VERSION>,
    KeyPackage: traits::KeyPackage<VERSION>,
>(
    &self,
    hash_ref: &HashReference,
    key_package: &KeyPackage,
) -> Result<(), Self::Error> {
    // Get the validity from the application in some way.
    let validity = self.get_validity(hash_ref);

    // Store the reference and its validity period.
    self.store_hash_ref(hash_ref, validity);

    // Store the actual key package.
    self.store_key_package(hash_ref, key_package);
}
```

This allows the application to iterate over the hash references and delete outdated
key packages.

### OpenMlsProvider

Additionally, there's a wrapper trait defined that is expected to be passed into
the public OpenMLS API.
Some OpenMLS APIs require only one of the sub-traits, though.

```rust,no_run,noplayground
{{#include ../../../traits/src/traits.rs:openmls_provider}}
```

## Implementation Notes

It is not necessary to implement all sub-traits if one functionality is missing.
Suppose you want to use a persisting storage provider. In that case, it is
sufficient to do a new implementation of the `StorageProvider` trait and
combine it with one of the provided crypto and randomness trait implementations.

[rust crypto]: https://crates.io/crates/openmls_rust_crypto
[libcrux crypto]: https://crates.io/crates/openmls_libcrux_crypto
[openmls traits crate]: https://crates.io/crates/openmls_traits
[rand crate]: https://crates.io/crates/rand
