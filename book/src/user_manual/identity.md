# Credentials

MLS relies on credentials to encode the identity of clients in the context of a group.
There are different types of credentials, with the OpenMLS library currently only supporting the `BasicCredential` credential type (see below).
Credentials are used to authenticate messages by the owner in the context of a group.
Note that the link between the credential and its signature keys depends on the credential type.
For example, the link between the `BasicCredential`'s and its keys is not defined by MLS.

A credential is always embedded in a leaf node, which is ultimately used to represent a client in a group and signed by the private key corresponding to the signature public key of the leaf node.
Clients can decide to use the same credential in multiple leaf nodes (and thus multiple groups) or to use distinct credentials per group.

The binding between a given credential and owning client's identity is, in turn, authenticated by the Authentication Service, an abstract authentication layer defined by the [MLS architecture document](https://github.com/mlswg/mls-architecture).
Note that the implementation of the Authentication Service and, thus, the details of how the binding is authenticated are not specified by MLS.

## Creating and using credentials

OpenMLS allows clients to create `Credentials`.
A `BasicCredential`, currently the only credential type supported by OpenMLS, consists only of the `identity`.
Thus, to create a fresh `Credential`, the following inputs are required:

- `identity: Vec<u8>`: An octet string that uniquely identifies the client.
- `credential_type: CredentialType`: The type of the credential, in this case `CredentialType::Basic`.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:create_basic_credential}}
```

After creating the credential bundle, clients should create keys for it.
OpenMLS provides a simple implementation of [`BasicCredential`](https://github.com/openmls/openmls/tree/main/basic-credential) for tests and to demonstrate how to use credentials.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:create_credential_keys}}
```

All functions and structs related to credentials can be found in the [`credentials`](https://docs.rs/crate/openmls/latest/credentials/index.html) module.
