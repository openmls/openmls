# Credentials

MLS relies on credentials to encode the identity of clients in the context of a group. There are different types of credential, with the OpenMLS currently only supporting the `BasicCredential` credential type (see below). All credentials have in common that they contain a signature public key (with the owner of the credential holding the corresponding private key) which is used to authenticate messages by the owner in the context of one or more groups.

A credential is always embedded in a [key package](./create_key_package.md), which is ultimately used to represent a client in a group and which is signed by the private key corresponding to the signature public key of the credential it contains. Clients can decide to use the same credential in multiple key packages (and thus multiple groups) or to use distinct credential per key package.

The binding between a given credential and owning client's identity is in turn authenticated by the Authentication Service, an abstract authentication layer defined by the [MLS architecture document](https://github.com/mlswg/mls-architecture). Note, that the implementation of the Authentication Service and thus the details of how the binding is authenticated is not specified by MLS.

## Creating and using credentials

OpenMLS allows clients to create `CredentialBundles`, each bundling a credential and the private key corresponding to the signature public key inside it. A `BasicCredential`, which is currently the only credential type supported by MLS, consists only of the `identity`, an opaque byte-vector, as well as the signature public key and the corresponding signature scheme. Thus, to create a fresh `CredentialBundle`, the following inputs are required:

- `identity: Vec<u8>`: An octet string that uniquely identifies the client.
- `credential_type: CredentialType`: The type of the credential, in this case `CredentialType::Basic`.
- `signature_scheme: SignatureScheme`: The signature scheme of the signature keypair, e.g. `SignatureScheme::ED25519`.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:create_credential_bundle}}
```

After creating the credential bundle, clients should store it in the key store so that it can be automatically retrieved when performing a group operation through the `MlsGroup` API that requires the client to sign a message.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:store_credential_bundle}}
```

All functions and structs related to credentials can be found in the [`credentials`](https://docs.rs/crate/openmls/latest/credentials/index.html) module.
