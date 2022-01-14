# Creating key packges

Before clients can communicate with each other usind OpenMLS they need to generate key packages and publish them with the Delivery Service. Clients can generate an arbirary number of key packages ahead of time.

Clients keep the private key material corresponding to a key package locally in the key store and fetch it from there when a key package was used to add them to a new group.

Clients need to choose a few parameters to create a `KeyPackageBundle`:

- `ciphersuites: &[CiphersuiteName]`: A list of ciphersuites supported by the client.
- `extensions: Vec<Extensions>`: A list of supported extensions.

Clients must specify at least one ciphersuite, and must not advertize ciphersuites they do not support.

Clients should specify all extensions they support. Mandatory extensions, like the `LifetimeExtension` can be specified here with specific values. If no extensions are specified, mandatory extensions are created on the fly with default values. See the documentation of extensions for more details.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:create_key_package_bundle}}
```

After creating the key package bundle, clients should store it in the key store so that it can be reused during group operations:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:store_key_package_bundle}}
```
