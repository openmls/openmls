# Key packages

To enable the asynchronous establishment of groups through pre-publishing key material, as well as to represent clients in the group, MLS relies on key packages. Key packages hold several pieces of information:

- a public HPKE encryption key to enable MLS' basic group key distribution feature
- the lifetime throughout which the key package is valid
- information about the client's capabilities (i.e., which features of MLS it supports)
- any extension that the client wants to include
- one of the client's [credentials](./identity.md), as well as a signature over the whole key package using the private key corresponding to the credential's signature public key

## Creating key packages

Before clients can communicate with each other using OpenMLS, they need to generate key packages and publish them with the Delivery Service. Clients can generate an arbitrary number of key packages ahead of time.

Clients keep the private key material corresponding to a key package locally in the key store and fetch it from there when a key package was used to add them to a new group.

Clients need to choose a few parameters to create a `KeyPackageBundle`:

- `ciphersuites: &[CiphersuiteName]`: A list of ciphersuites supported by the client.
- `extensions: Vec<Extensions>`: A list of supported extensions.

Clients must specify at least one ciphersuite and not advertise ciphersuites they do not support.

Clients should specify all extensions they support. See the documentation of extensions for more details.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:create_key_package}}
```

This will also store the private key for the key package in the key store.

All functions and structs related to key packages can be found in the [`key_packages`](https://docs.rs/crate/openmls/latest/key_packages/index.html) module.
