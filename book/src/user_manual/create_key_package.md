# Key Packages

The MLS protocol is designed in a way that allows members to be added to groups without the said members being online (because more generally: MLS communication is entirely designed to be asynchronous).


The general flow is like this:

1. **Client A** generates key packages and registers them with the "Delivery Service"
2. **Client B** decides to add **Client A** to a group, so it contacts the Delivery Service and downloads one of **Client A**'s key packages
3. The delivery service marks the `KeyPackage` as consumed (more on this below)
4. **Client B** uses the **KeyPackage** to generate a commit that adds **Client A** to the group

Each key package has corresponding private keys that are meant to be stored locally only. Therefore OpenMLS defines a struct called `KeyPackageBundle`, which consists of:

- `key_package`: The public material that should be registered at the Delivery Service
- `private_init_key`: Private stuff that should never leave the local database
- `private_encryption_key`: Private stuff that should never leave the local database

Key packages are meant to be used only once ([unless it's a last resort KeyPackage, if you implement those](https://www.rfc-editor.org/rfc/rfc9420.html#name-keypackage-reuse)), which means a few things:

1. The delivery service should make sure a key package can only be downloaded once (unless it's a last resort one)
2. Each client should maintain many key packages registered at the Delivery Service so the client can be added to many groups while it's offline (without using the last resort key package, if it exists)
3. Each client should continuously replenish the list of key packages registered at the Delivery Service, replacing any consumed / nearing expiry / expired ones

Each key package has a lifetime attached to it (default is `3 * 28` days), so the client should keep that in mind when it comes to replenishing registered KeyPackages at the Delivery Service.

Finally, a key package is identified within the protocol by a "hash reference".

## Creating key packages

Clients need to choose a few parameters to create a `KeyPackageBundle`:

- `ciphersuites: &[CiphersuiteName]`: A list of ciphersuites supported by the client.
- `extensions: Vec<Extensions>`: A list of supported extensions.

Clients must specify at least one ciphersuite and not advertise ciphersuites they do not support.

Clients should specify all extensions they support. See the documentation of extensions for more details.

Here's how you can generate a `KeyPackageBundle`:

```rust
// The following needs to be pre-defined:
// - CIPHERSUITE (`Ciphersuite`)
// - provider (`OpenMlsProvider`)
// - signatureKeyPair (`SignatureKeyPair`)
// - credential (`BasicCredential`)

let keyPackageBundle = KeyPackage::builder()
	.build(
		CIPHERSUITE,
		&provider, 
		&signatureKeyPair,
		CredentialWithKey {
			credential: credential.clone().into(),
			signature_key: signatureKeyPair.public().into(),
		},
	)?;

// This is the key package's identifier (upload this to the Delivery Service))
let hashRef: Vec<u8> = keyPackageBundle.key_package().hash_ref(provider.crypto())?.tls_serialize_detached()?

// This is the exact data another client would need to add this client to a group (upload this to the Delivery Service)
let keyPackage: Vec<u8> = keyPackageBundle.key_package().tls_serialize_detached()?;

// This is the expiry date of the key pacakge
let expiresAt: u64 = keyPackageBundle.key_package().life_time().not_after();
```

The private parts of the key package are automatically stored in the database

## Getting existing key packages

OpenMLS does not provide an API for this; While you're implementing `StorageProvider` for your local database, you can implement a `get_key_packages()` function that fetches that for you.

## Deleting a key package (identified by hash reference)

```rust
let hashRef: Vec<u8> = ...;

provider.storage().delete_key_package(
	&KeyPackageRef::tls_deserialize_exact_bytes(hashRef.as_slice())?
)?;
```

## Key Package contents

A key package (the public part of `KeyPackageBundle`) consists of:

- A public HPKE encryption key to enable MLS' basic group key distribution feature
- The lifetime throughout which the key package is valid
- Information about the client's capabilities (i.e., which features of MLS it supports)
- Any extension that the client wants to include
- One of the client's [credentials](./identity.md), as well as a signature over the whole key package using the private key corresponding to the credential's signature public key