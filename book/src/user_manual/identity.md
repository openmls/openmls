# Creating an identity

Every client that wants to use OpenMLS needs to create an identity keypair initially.
Clients need to choose a few parameters to create a `CredentialBundle`:

- `identity: Vec<u8>`: An octet string that uniquely identifies the client.
- `credential_type: CredentialType`: The type of the credential, e.g. `CredentialType::Basic`.
- `signature_scheme: SignatureScheme`: The cryptographic primitive of the identity keypair, e.g. `SignatureScheme::ED25519`.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:create_credential_bundle}}
```

After creating the credential bundle, clients should store it in the key store so that it can be reused during group operations:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:store_credential_bundle}}
```
