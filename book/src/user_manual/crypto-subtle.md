# crypto-subtle feature

This feature of the OpenMLS crate allows importing and exporting private signature keys that can be used with credentials.

⚠️ Note that no checks are performed on the keys. Use this feature at your own risk. If you create a credential from an existing key
or export key material, you are responsible for deleting that key. If that key is kept outside OpenMLS,
updating a leaf will not be enough to achieve Forward Secrecy/Post-compromise Security.

## Importing keys

A signature keypair can be created from existing raw keys with the following function call:

```rust,no_run,noplayground
SignatureKeypair::from_bytes(
    signature_scheme: SignatureScheme,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
) -> Self
```

## Exporting keys

The raw signature private key can be exported with the following functions call:

```rust,no_run,noplayground
SignaturePrivateKey::as_slice(&self) -> &[u8]
```

## Building a BasicCredential from existing keys

```rust,no_run,noplayground
let signature_scheme = SignatureScheme::ED25519;

let private_key = vec![1, 2, 3]; // Sample private key as raw bytes
let public_key = vec![4, 5, 6]; // Sample public key as raw bytes

let identity = vec![7, 8, 9]; // Sample identity

let signature_keypair
    = SignatureKeypair::from_bytes(signature_scheme, public_key, private_key);

let credential_bundle = CredentialBundle::from_parts(identity, signature_keypair);
```
