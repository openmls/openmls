//! # Key Packages
//!
//! Key packages are pre-published public keys that provide some information
//! about a user in order to facilitate the asynchronous addition of clients to
//! a group.
//!
//! A key package object specifies:
//!
//! - A **protocol version** and ciphersuite that the client supports
//! - A **public key** that others can use for key agreement
//! - A **credential** authenticating the client's application-layer identity
//! - A list of **extensions** for the key package (see
//!   [Extensions](`mod@crate::extensions`) for details)
//!
//! Key packages are intended to be used only once and SHOULD NOT be reused
//! except in case of last resort, i.e. if there's no other key package
//! available. Clients MAY generate and publish multiple KeyPackages to support
//! multiple ciphersuites.
//!
//! The value for HPKE init key MUST be a public key for the asymmetric
//! encryption scheme defined by ciphersuite, and it MUST be unique among the
//! set of key packages created by this client. The whole structure is signed
//! using the client's signature key. A key package object with an invalid
//! signature field is considered malformed.
//!
//! ## Creating key package bundles
//!
//! Key package bundles are key packages including their private key. A key
//! package bundle can be created as follows:
//!
//! ```
//! use openmls::prelude::*;
//! use openmls_rust_crypto::OpenMlsRustCrypto;
//! use openmls_basic_credential::SignatureKeyPair;
//! use tokio::runtime::Runtime;
//!
//! let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
//! let backend = OpenMlsRustCrypto::default();
//!
//! let credential = Credential::new_basic("identity".into());
//! let signer =
//!     SignatureKeyPair::new(ciphersuite.signature_algorithm(), &mut *backend.rand().borrow_rand().unwrap())
//!         .expect("Error generating a signature key pair.");
//! let credential_with_key = CredentialWithKey {
//!     credential,
//!     signature_key: signer.public().into(),
//! };
//! let rt = Runtime::new().unwrap();
//! rt.block_on(async move {
//!     let key_package = KeyPackage::builder()
//!         .build(
//!             CryptoConfig {
//!                 ciphersuite,
//!                 version: ProtocolVersion::default(),
//!             },
//!             &backend,
//!             &signer,
//!             credential_with_key,
//!         )
//!         .await
//!         .unwrap();
//! });
//! ```
//!
//! See [`KeyPackage`] for more details on how to use key packages.

#[cfg(test)]
use crate::treesync::node::encryption_keys::EncryptionKey;
use crate::{
    ciphersuite::{
        hash_ref::{make_key_package_ref, KeyPackageRef},
        signable::*,
        *,
    },
    credentials::*,
    error::LibraryError,
    extensions::ExtensionType,
    extensions::Extensions,
    group::config::CryptoConfig,
    treesync::{
        node::{
            encryption_keys::EncryptionKeyPair,
            leaf_node::{Capabilities, LeafNodeSource, NewLeafNodeParams, TreeInfoTbs},
        },
        LeafNode,
    },
    versions::ProtocolVersion,
};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    key_store::{MlsEntity, MlsEntityId, OpenMlsKeyStore},
    signatures::Signer,
    types::Ciphersuite,
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
use tls_codec::{Serialize as TlsSerializeTrait, TlsSerialize, TlsSize};

// Private
use errors::*;

// Public
pub mod errors;
pub mod key_package_in;

mod lifetime;

// Tests
#[cfg(test)]
pub(crate) mod test_key_packages;

// Public types
pub use key_package_in::KeyPackageIn;
pub use lifetime::Lifetime;

/// The unsigned payload of a key package.
/// Any modification must happen on this unsigned struct. Use `sign` to get a
/// signed key package.
///
/// ```text
/// struct {
///     ProtocolVersion version;
///     CipherSuite cipher_suite;
///     HPKEPublicKey init_key;
///     LeafNode leaf_node;
///     Extension extensions<V>;
/// } KeyPackageTBS;
/// ```
#[derive(Debug, Clone, PartialEq, TlsSize, TlsSerialize, Serialize, Deserialize)]
struct KeyPackageTbs {
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    init_key: HpkePublicKey,
    leaf_node: LeafNode,
    extensions: Extensions,
}

impl Signable for KeyPackageTbs {
    type SignedOutput = KeyPackage;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        SIGNATURE_KEY_PACKAGE_LABEL
    }
}

impl From<KeyPackage> for KeyPackageTbs {
    fn from(kp: KeyPackage) -> Self {
        kp.payload
    }
}

/// The key package struct.
#[derive(Debug, Clone, Serialize, Deserialize, TlsSize, TlsSerialize)]
pub struct KeyPackage {
    payload: KeyPackageTbs,
    signature: Signature,
}

impl PartialEq for KeyPackage {
    fn eq(&self, other: &Self) -> bool {
        // We ignore the signature in the comparison. The same key package
        // may have different, valid signatures.
        self.payload == other.payload
    }
}

impl SignedStruct<KeyPackageTbs> for KeyPackage {
    fn from_payload(payload: KeyPackageTbs, signature: Signature) -> Self {
        Self { payload, signature }
    }
}

const SIGNATURE_KEY_PACKAGE_LABEL: &str = "KeyPackageTBS";

impl MlsEntity for KeyPackage {
    const ID: MlsEntityId = MlsEntityId::KeyPackage;
}

/// Helper struct containing a new [`KeyPackage`] and supporting data.
///
/// This is an opaque struct meant as a serialization helper: it contains all the fundamental
/// data associated with a [`KeyPackage`] which otherwise is kept in the keystore.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct KeyPackageSecretEncapsulation {
    pub(crate) key_package: KeyPackage,
    pub(crate) encryption_keypair: EncryptionKeyPair,
    pub(crate) init_private_key: HpkePrivateKey,
}

impl KeyPackageSecretEncapsulation {
    /// Store this encapsulation's data in the keystore, returning the contained key package.
    pub async fn store<KeyStore: OpenMlsKeyStore>(
        self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Result<KeyPackage, KeyPackageNewError<KeyStore::Error>> {
        let Self {
            key_package,
            encryption_keypair,
            init_private_key,
        } = self;

        // Store the key package in the key store with the hash reference as id
        // for retrieval when parsing welcome messages.
        backend
            .key_store()
            .store(
                key_package.hash_ref(backend.crypto())?.as_slice(),
                &key_package,
            )
            .await
            .map_err(KeyPackageNewError::KeyStoreError)?;

        // Store the encryption key pair in the key store.
        encryption_keypair
            .write_to_key_store(backend)
            .await
            .map_err(KeyPackageNewError::KeyStoreError)?;

        // Store the private part of the init_key into the key store.
        // The key is the public key.
        backend
            .key_store()
            .store::<HpkePrivateKey>(key_package.hpke_init_key().as_slice(), &init_private_key)
            .await
            .map_err(KeyPackageNewError::KeyStoreError)?;

        Ok(key_package)
    }

    /// Load the data associated with this key package from the keystore and wrap it all up as an encapsulated bundle.
    ///
    /// Note that this contains various secrets and should be protected!
    pub async fn load<KeyStore: OpenMlsKeyStore>(
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        key_package: KeyPackage,
    ) -> Result<Self, KeyPackageNewError<KeyStore::Error>> {
        let encryption_key = key_package.leaf_node().encryption_key();
        let encryption_keypair = EncryptionKeyPair::read_from_key_store(backend, encryption_key)
            .await
            .ok_or_else(|| {
                LibraryError::custom("bundling keypackage: relevant encryption keypair not foud")
            })?;

        let init_private_key = backend
            .key_store()
            .read(key_package.hpke_init_key().as_slice())
            .await
            .ok_or_else(|| {
                LibraryError::custom("bundling keypackage: relevant init_private_key not found")
            })?;

        Ok(Self {
            key_package,
            encryption_keypair,
            init_private_key,
        })
    }
}

// Public `KeyPackage` functions.
impl KeyPackage {
    /// Create a key package builder.
    ///
    /// This is provided for convenience. You can also use [`KeyPackageBuilder::new`].
    pub fn builder() -> KeyPackageBuilder {
        KeyPackageBuilder::new()
    }

    #[allow(clippy::too_many_arguments)]
    /// Create a new key package for the given `ciphersuite` and `identity`.
    pub(crate) fn create<KeyStore: OpenMlsKeyStore>(
        config: CryptoConfig,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        lifetime: Lifetime,
        extensions: Extensions,
        leaf_node_capabilities: Capabilities,
        leaf_node_extensions: Extensions,
    ) -> Result<KeyPackageSecretEncapsulation, KeyPackageNewError<KeyStore::Error>> {
        if config.ciphersuite.signature_algorithm() != signer.signature_scheme() {
            return Err(KeyPackageNewError::CiphersuiteSignatureSchemeMismatch);
        }

        // Create a new HPKE key pair
        let ikm = Secret::random(config.ciphersuite, backend, config.version)
            .map_err(LibraryError::unexpected_crypto_error)?;
        let init_key = backend
            .crypto()
            .derive_hpke_keypair(config.ciphersuite.hpke_config(), ikm.as_slice())
            .map_err(LibraryError::unexpected_crypto_error)?;
        let (key_package, encryption_keypair) = Self::new_from_keys(
            config,
            backend,
            signer,
            credential_with_key,
            lifetime,
            extensions,
            leaf_node_capabilities,
            leaf_node_extensions,
            init_key.public,
        )?;

        Ok(KeyPackageSecretEncapsulation {
            key_package,
            encryption_keypair,
            init_private_key: init_key.private,
        })
    }

    /// Create a new key package for the given `ciphersuite` and `identity`.
    ///
    /// The HPKE init key must have been generated before and the private part
    /// has to be stored in the key store.
    ///
    /// This function returns the new [`KeyPackage`] as well as the
    /// encryption key ([`HpkeKeyPair`]) of the leaf node.
    ///
    /// The caller is responsible for storing the new values.
    #[allow(clippy::too_many_arguments)]
    fn new_from_keys<KeyStore: OpenMlsKeyStore>(
        config: CryptoConfig,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        lifetime: Lifetime,
        extensions: Extensions,
        capabilities: Capabilities,
        leaf_node_extensions: Extensions,
        init_key: Vec<u8>,
    ) -> Result<(Self, EncryptionKeyPair), KeyPackageNewError<KeyStore::Error>> {
        // We don't need the private key here. It's stored in the key store for
        // use later when creating a group with this key package.

        let new_leaf_node_params = NewLeafNodeParams {
            config,
            leaf_node_source: LeafNodeSource::KeyPackage(lifetime),
            credential_with_key,
            capabilities,
            extensions: leaf_node_extensions,
            tree_info_tbs: TreeInfoTbs::KeyPackage,
        };

        let (leaf_node, encryption_key_pair) =
            LeafNode::new(backend, signer, new_leaf_node_params)?;

        let key_package_tbs = KeyPackageTbs {
            protocol_version: config.version,
            ciphersuite: config.ciphersuite,
            init_key: init_key.into(),
            leaf_node,
            extensions,
        };

        let key_package = key_package_tbs.sign(signer)?;

        Ok((key_package, encryption_key_pair))
    }

    /// Delete this key package and its private key from the key store.
    pub async fn delete<KeyStore: OpenMlsKeyStore>(
        &self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Result<(), KeyPackageDeleteError<KeyStore::Error>> {
        let kp_ref = self.hash_ref(backend.crypto())?;
        backend
            .key_store()
            .delete::<Self>(kp_ref.as_slice())
            .await
            .map_err(KeyPackageDeleteError::KeyStoreError)?;
        backend
            .key_store()
            .delete::<HpkePrivateKey>(self.hpke_init_key().as_slice())
            .await
            .map_err(KeyPackageDeleteError::KeyStoreError)?;
        Ok(())
    }

    /// Get a reference to the extensions of this key package.
    pub fn extensions(&self) -> &Extensions {
        &self.payload.extensions
    }

    /// Check whether the this key package supports all the required extensions
    /// in the provided list.
    pub fn check_extension_support(
        &self,
        required_extensions: &[ExtensionType],
    ) -> Result<(), KeyPackageExtensionSupportError> {
        for required_extension in required_extensions.iter() {
            if !self.extensions().contains(*required_extension) {
                return Err(KeyPackageExtensionSupportError::UnsupportedExtension);
            }
        }

        Ok(())
    }

    /// Compute the [`KeyPackageRef`] of this [`KeyPackage`].
    /// The [`KeyPackageRef`] is used to identify a new member that should get
    /// added to a group.
    pub fn hash_ref(&self, backend: &impl OpenMlsCrypto) -> Result<KeyPackageRef, LibraryError> {
        make_key_package_ref(
            &self
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?,
            self.payload.ciphersuite,
            backend,
        )
        .map_err(LibraryError::unexpected_crypto_error)
    }

    /// Get the [`Ciphersuite`].
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.payload.ciphersuite
    }

    /// Get the [`LeafNode`] reference.
    pub fn leaf_node(&self) -> &LeafNode {
        &self.payload.leaf_node
    }

    /// Get the public HPKE init key of this key package.
    pub fn hpke_init_key(&self) -> &HpkePublicKey {
        &self.payload.init_key
    }
}

/// Crate visible `KeyPackage` functions.
impl KeyPackage {
    /// Get the `ProtocolVersion`.
    pub(crate) fn protocol_version(&self) -> ProtocolVersion {
        self.payload.protocol_version
    }
}

/// Helpers for testing.
#[cfg(any(feature = "test-utils", test))]
#[allow(clippy::too_many_arguments)]
impl KeyPackage {
    /// Generate a new key package with a given init key
    pub async fn new_from_init_key<KeyStore: OpenMlsKeyStore>(
        config: CryptoConfig,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        extensions: Extensions,
        leaf_node_capabilities: Capabilities,
        leaf_node_extensions: Extensions,
        init_key: Vec<u8>,
    ) -> Result<Self, KeyPackageNewError<KeyStore::Error>> {
        let (key_package, encryption_key_pair) = Self::new_from_keys(
            config,
            backend,
            signer,
            credential_with_key,
            Lifetime::default(),
            extensions,
            leaf_node_capabilities,
            leaf_node_extensions,
            init_key,
        )?;

        // Store the key package in the key store with the hash reference as id
        // for retrieval when parsing welcome messages.
        backend
            .key_store()
            .store(
                key_package.hash_ref(backend.crypto())?.as_slice(),
                &key_package,
            )
            .await
            .map_err(KeyPackageNewError::KeyStoreError)?;

        // Store the encryption key pair in the key store.
        encryption_key_pair
            .write_to_key_store(backend)
            .await
            .map_err(KeyPackageNewError::KeyStoreError)?;

        Ok(key_package)
    }

    /// Create new key package with a leaf node encryption key set to the
    /// provided `encryption_key`.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new_from_encryption_key<KeyStore: OpenMlsKeyStore>(
        config: CryptoConfig,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        extensions: Extensions,
        leaf_node_capabilities: Capabilities,
        leaf_node_extensions: Extensions,
        encryption_key: EncryptionKey,
    ) -> Result<Self, KeyPackageNewError<KeyStore::Error>> {
        // Create a new HPKE init key pair
        let ikm = Secret::random(config.ciphersuite, backend, config.version).unwrap();
        let init_key = backend
            .crypto()
            .derive_hpke_keypair(config.ciphersuite.hpke_config(), ikm.as_slice())
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Store the private part of the init_key into the key store.
        // The key is the public key.
        backend
            .key_store()
            .store::<HpkePrivateKey>(&init_key.public, &init_key.private)
            .await
            .map_err(KeyPackageNewError::KeyStoreError)?;

        // We don't need the private key here. It's stored in the key store for
        // use later when creating a group with this key package.
        let leaf_node = LeafNode::create_new_with_key(
            encryption_key,
            credential_with_key,
            LeafNodeSource::KeyPackage(Lifetime::default()),
            leaf_node_capabilities,
            leaf_node_extensions,
            TreeInfoTbs::KeyPackage,
            signer,
        )
        .unwrap();

        let key_package = KeyPackageTbs {
            protocol_version: config.version,
            ciphersuite: config.ciphersuite,
            init_key: init_key.public.into(),
            leaf_node,
            extensions,
        };

        let key_package = key_package.sign(signer)?;

        // Store the key package in the key store with the hash reference as id
        // for retrieval when parsing welcome messages.
        backend
            .key_store()
            .store(
                key_package.hash_ref(backend.crypto())?.as_slice(),
                &key_package,
            )
            .await
            .map_err(KeyPackageNewError::KeyStoreError)?;

        Ok(key_package)
    }

    pub fn into_with_init_key(
        self,
        config: CryptoConfig,
        signer: &impl Signer,
        init_key: Vec<u8>,
    ) -> Result<Self, SignatureError> {
        let key_package_tbs = KeyPackageTbs {
            protocol_version: config.version,
            ciphersuite: config.ciphersuite,
            init_key: init_key.into(),
            leaf_node: self.leaf_node().clone(),
            extensions: self.extensions().clone(),
        };

        key_package_tbs.sign(signer)
    }

    /// Resign this key package with another credential.
    pub fn resign(mut self, signer: &impl Signer, credential_with_key: CredentialWithKey) -> Self {
        self.payload
            .leaf_node
            .set_credential(credential_with_key.credential.clone());
        self.payload
            .leaf_node
            .set_signature_key(credential_with_key.signature_key.clone());

        self.payload
            .leaf_node
            .resign(signer, credential_with_key, TreeInfoTbs::KeyPackage);

        self.payload.sign(signer).unwrap()
    }

    /// Replace the public key in the KeyPackage.
    pub fn set_init_key(&mut self, public_key: HpkePublicKey) {
        self.payload.init_key = public_key
    }

    /// Replace the version in the KeyPackage.
    pub fn set_version(&mut self, version: ProtocolVersion) {
        self.payload.protocol_version = version
    }

    /// Replace the ciphersuite in the KeyPackage.
    pub fn set_ciphersuite(&mut self, ciphersuite: Ciphersuite) {
        self.payload.ciphersuite = ciphersuite
    }

    /// Set the [`LeafNode`].
    pub fn set_leaf_node(&mut self, leaf_node: LeafNode) {
        self.payload.leaf_node = leaf_node;
    }
}

/// Builder that helps creating (and configuring) a [`KeyPackage`].
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackageBuilder {
    key_package_lifetime: Option<Lifetime>,
    key_package_extensions: Option<Extensions>,
    leaf_node_capabilities: Option<Capabilities>,
    leaf_node_extensions: Option<Extensions>,
}

impl KeyPackageBuilder {
    /// Create a key package builder.
    pub fn new() -> Self {
        Self {
            key_package_lifetime: None,
            key_package_extensions: None,
            leaf_node_capabilities: None,
            leaf_node_extensions: None,
        }
    }

    /// Set the key package lifetime.
    pub fn key_package_lifetime(mut self, lifetime: Lifetime) -> Self {
        self.key_package_lifetime.replace(lifetime);
        self
    }

    /// Set the key package extensions.
    pub fn key_package_extensions(mut self, extensions: Extensions) -> Self {
        self.key_package_extensions.replace(extensions);
        self
    }

    /// Set the leaf node capabilities.
    pub fn leaf_node_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.leaf_node_capabilities.replace(capabilities);
        self
    }

    /// Set the leaf node extensions.
    pub fn leaf_node_extensions(mut self, extensions: Extensions) -> Self {
        self.leaf_node_extensions.replace(extensions);
        self
    }

    pub(crate) fn build_without_key_storage<KeyStore: OpenMlsKeyStore>(
        self,
        config: CryptoConfig,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
    ) -> Result<KeyPackageSecretEncapsulation, KeyPackageNewError<KeyStore::Error>> {
        KeyPackage::create(
            config,
            backend,
            signer,
            credential_with_key,
            self.key_package_lifetime.unwrap_or_default(),
            self.key_package_extensions.unwrap_or_default(),
            self.leaf_node_capabilities.unwrap_or_default(),
            self.leaf_node_extensions.unwrap_or_default(),
        )
    }

    /// Finalize and build the key package.
    pub async fn build<KeyStore: OpenMlsKeyStore>(
        self,
        config: CryptoConfig,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
    ) -> Result<KeyPackage, KeyPackageNewError<KeyStore::Error>> {
        let encapsulation = KeyPackage::create(
            config,
            backend,
            signer,
            credential_with_key,
            self.key_package_lifetime.unwrap_or_default(),
            self.key_package_extensions.unwrap_or_default(),
            self.leaf_node_capabilities.unwrap_or_default(),
            self.leaf_node_extensions.unwrap_or_default(),
        )?;

        encapsulation.store(backend).await
    }
}

/// A [`KeyPackageBundle`] contains a [`KeyPackage`] and the corresponding private
/// key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct KeyPackageBundle {
    pub(crate) key_package: KeyPackage,
    pub(crate) private_key: HpkePrivateKey,
}

// Public `KeyPackageBundle` functions.
#[cfg(test)]
impl KeyPackageBundle {
    /// Get a reference to the public part of this bundle, i.e. the [`KeyPackage`].
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    /// Get a reference to the private key.
    pub fn private_key(&self) -> &HpkePrivateKey {
        &self.private_key
    }
}

#[cfg(test)]
impl KeyPackageBundle {
    pub(crate) async fn new_with_extensions(
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
        ciphersuite: Ciphersuite,
        credential_with_key: CredentialWithKey,
        extensions: Extensions,
        capabilities: Capabilities,
    ) -> Self {
        let key_package = KeyPackage::builder()
            .leaf_node_extensions(extensions)
            .leaf_node_capabilities(capabilities)
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                backend,
                signer,
                credential_with_key,
            )
            .await
            .unwrap();
        let private_key = backend
            .key_store()
            .read::<HpkePrivateKey>(key_package.hpke_init_key().as_slice())
            .await
            .unwrap();
        Self {
            key_package,
            private_key,
        }
    }
    pub(crate) async fn new(
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
        ciphersuite: Ciphersuite,
        credential_with_key: CredentialWithKey,
    ) -> Self {
        Self::new_with_extensions(
            backend,
            signer,
            ciphersuite,
            credential_with_key,
            Extensions::default(),
            Capabilities::default(),
        )
        .await
    }
}
