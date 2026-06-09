# Key Packages

The MLS protocol is designed to be asynchronous: It allows members to be added to groups without said members being online.

The general flow is like this:

1. **Client A** generates key packages and registers them with the Delivery Service
2. **Client B** decides to add **Client A** to a group, so it contacts the Delivery Service and downloads one of **Client A**'s key packages
3. The delivery service marks the `KeyPackage` as consumed (more on this below)
4. **Client B** uses the **KeyPackage** to generate a commit that adds **Client A** to the group

Each key package has corresponding private keys that are meant to be stored locally only. Therefore OpenMLS defines a struct called `KeyPackageBundle`, which consists of:

- `key_package` (`KeyPackage`): The public material that should be registered at the Delivery Service
- `private_init_key` (`HpkePrivateKey`): Private stuff that should never leave the local database
- `private_encryption_key` (`EncryptionPrivateKey`): Private stuff that should never leave the local database

Key packages are meant to be used only once ([unless it's a last resort KeyPackage, if you implement those](https://www.rfc-editor.org/rfc/rfc9420.html#name-keypackage-reuse)), which means a few things:

1. The delivery service should make sure a key package can only be downloaded once (unless it's a last resort one)
2. Each client should maintain many key packages registered at the Delivery Service so the client can be added to many groups while it's offline (without using the last resort key package, if it exists)
3. Each client should continuously replenish the list of key packages registered at the Delivery Service, replacing any consumed / nearing expiry / expired ones

Each key package has a lifetime attached to it ([default is `3 * 28` days](../../../openmls/src/key_packages/lifetime.rs#L13)), so the client should keep that in mind when it comes to replenishing registered KeyPackages at the Delivery Service.

Finally, a key package is identified within the protocol by a ["hash reference"](https://www.rfc-editor.org/rfc/rfc9420.html#name-hash-based-identifiers).

## Creating `KeyPackageBundle`s

You need to choose a few parameters when creating `KeyPackageBundle`s:

- `ciphersuites: &[CiphersuiteName]`: A list of ciphersuites supported by the client.
- `extensions: Vec<Extensions>`: A list of supported extensions.

You must specify at least one ciphersuite and not advertise ciphersuites they do not support.

You should specify all extensions they support. See the documentation of extensions for more details.

Here's how you can generate a `KeyPackageBundle`:

```rust
// The following needs to be pre-defined:
// - CIPHERSUITE (`Ciphersuite`)
// - provider (`OpenMlsProvider`)
// - signature_key_pair (`SignatureKeyPair`)
// - credential (`BasicCredential`)

let key_package_bundle = KeyPackage::builder()
	.build(
		CIPHERSUITE,
		&provider, 
		&signature_key_pair,
		CredentialWithKey {
			credential: credential.clone().into(),
			signature_key: signature_key_pair.public().into(),
		},
	)?;

// This is the key package's identifier (upload this to the Delivery Service))
let hash_ref: Vec<u8> = key_package_bundle.key_package().hash_ref(provider.crypto())?.tls_serialize_detached()?

// This is the exact data another client would need to add this client to a group (upload this to the Delivery Service)
let key_package: Vec<u8> = key_package_bundle.key_package().tls_serialize_detached()?;

// This is the expiry date of the key pacakge
let expires_at: u64 = key_package_bundle.key_package().life_time().not_after();
```

The private parts of the key package are automatically stored in the database.

## Getting existing key packages

OpenMLS does not provide an API for this; While you're implementing `StorageProvider` for your local database, you can implement a `get_key_packages()` function that queries the storage to get that for you.

## Deleting a key package (identified by hash reference)

```rust
let hash_ref: Vec<u8> = ...;

provider.storage().delete_key_package(
	&KeyPackageRef::tls_deserialize_exact_bytes(hash_ref.as_slice())?
)?;
```

## Appendix: `KeyPackage` contents

A `KeyPackage` (the public part of `KeyPackageBundle`) consists of:

- A public HPKE encryption key to enable MLS' basic group key distribution feature
- The lifetime throughout which the key package is valid
- Information about the client's capabilities (i.e., which features of MLS it supports)
- Any extension that the client wants to include
- One of the client's [credentials](./identity.md), as well as a signature over the whole key package using the private key corresponding to the credential's signature public key