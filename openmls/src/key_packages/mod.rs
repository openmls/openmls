//! # Key Packages
//!
//! Key packages are pre-published public keys that carry information about a
//! user, allowing for the asynchronous addition of clients to an MLS group.
//!
//! A key package object specifies:
//!
//! - A **protocol version** and ciphersuite that the client supports
//! - A **public key** that others can use for key agreement
//! - A **credential** authenticating the client's application-layer identity
//! - A list of **extensions** for the key package (see
//!   [Extensions](`mod@crate::extensions`) for details)
//!
//! Key packages are meant to be used only once and SHOULD NOT be reused,
//! except as a last resort—i.e., when no other key package is available.
//! Clients MAY generate and publish multiple key packages to support multiple
//! ciphersuites.
//!
//! The HPKE init key MUST be a public key for the asymmetric encryption scheme
//! defined by the ciphersuite. It MUST be unique among key packages created by
//! the client. The entire structure is signed using the client's signature key.
//! A key package object with an invalid signature field is considered malformed.
//!
//! ## Creating key package bundles
//!
//! Key package bundles are key packages that include their private key. A key
//! package bundle can be created as follows:
//!
//! ```
//! use openmls::{prelude::{*, tls_codec::*}};
//! use openmls_rust_crypto::OpenMlsRustCrypto;
//! use openmls_basic_credential::SignatureKeyPair;
//!
//! let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
//! let provider = OpenMlsRustCrypto::default();
//!
//! let credential = BasicCredential::new("identity".into());
//! let signer =
//!     SignatureKeyPair::new(ciphersuite.signature_algorithm())
//!         .expect("Error generating a signature key pair.");
//! let credential_with_key = CredentialWithKey {
//!     credential: credential.into(),
//!     signature_key: signer.public().into(),
//! };
//! let key_package = KeyPackage::builder()
//!     .build(
//!         ciphersuite,
//!         &provider,
//!         &signer,
//!         credential_with_key,
//!     )
//!     .unwrap();
//! ```
//!
//! See [`KeyPackage`] for more details and other ways to create key packages.
//!
//! ## Loading key packages
//!
//! When getting key packages from another user the serialized bytes are parsed
//! as follows;
//!
//! ```
//! use openmls::prelude::{*, tls_codec::*};
//! use openmls::test_utils::hex_to_bytes;
//! use openmls_rust_crypto::OpenMlsRustCrypto;
//!
//! let provider = OpenMlsRustCrypto::default();
//! let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
//!
//! let key_package_bytes = hex_to_bytes(
//!         "0001000120D4F26FCA6EF6B1CA2FDD8DCAA501730FB003323AD8C781490B94782771\
//!         B22216208E9BF17CE632EC753A9BFC624F275AA745ACD7316A5CF18B8E39CE71A80EE\
//!         137205639176E415B378BA54B9E7C678FFAA860676CEFEDFA0DD3FF692F20AC7E2632\
//!         0001086964656E74697479020001060001000200030200010C0001000200030004000\
//!         50007020001010000000064A1986E00000000776DA97E004040A71F1B7A5F78D15C3F\
//!         B215D811BADB0BBBD78B582D42E5C3672085699DCA5F90DAA57BB74A3A973789E7006\
//!         887FCE85F0E64C19C1F26C28B5752B3C3312FF3040040407B5A96167512061E78414F\
//!         E3F29B89FF2A954CB8E0A6E976EA039E0A1A0AB91B80664BDDC62BC8CBE64BC9242C4\
//!         CDC33F56A10E425A384AED029C23E1D467C0E");
//!
//! let key_package_in = KeyPackageIn::tls_deserialize(&mut key_package_bytes.as_slice())
//!     .expect("Could not deserialize KeyPackage");
//!
//! let key_package = key_package_in
//!     .validate(provider.crypto(), ProtocolVersion::Mls10)
//!     .expect("Invalid KeyPackage");
//! ```
//!
//! See [`KeyPackage`] for more details on how to use key packages.

#[cfg(not(feature = "extensions-draft"))]
use crate::extensions::LastResortExtension;
use crate::{
    ciphersuite::{
        hash_ref::{make_key_package_ref, KeyPackageRef},
        signable::*,
        *,
    },
    credentials::*,
    error::LibraryError,
    extensions::{Extension, ExtensionType, Extensions},
    storage::OpenMlsProvider,
    treesync::{
        node::{
            encryption_keys::{EncryptionKeyPair, EncryptionPrivateKey},
            leaf_node::{Capabilities, LeafNodeSource, NewLeafNodeParams, TreeInfoTbs},
        },
        LeafNode,
    },
    versions::ProtocolVersion,
};
#[cfg(feature = "extensions-draft")]
use crate::{
    component::{ComponentId, ComponentType},
    extensions::AppDataDictionaryExtension,
};
use openmls_traits::{
    crypto::OpenMlsCrypto, signatures::Signer, storage::StorageProvider, types::Ciphersuite,
};
use serde::{Deserialize, Serialize};
use tls_codec::{
    Serialize as TlsSerializeTrait, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
};

// Private
use errors::*;

// Public
pub mod errors;
pub mod key_package_in;

mod lifetime;
#[cfg(feature = "virtual-clients-draft")]
mod vc;

// Tests
#[cfg(test)]
pub(crate) mod tests;

// Public types
pub use key_package_in::KeyPackageIn;
pub use lifetime::Lifetime;
#[cfg(feature = "virtual-clients-draft")]
pub use vc::{VcKeyPackageBatch, VcKeyPackageBatchBuilder};

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
    init_key: InitKey,
    leaf_node: LeafNode,
    extensions: Extensions<KeyPackage>,
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
#[derive(Debug, Clone, Serialize, Deserialize, TlsSize)]
pub struct KeyPackage {
    payload: KeyPackageTbs,
    signature: Signature,
    #[serde(skip)]
    #[tls_codec(skip)]
    serialized_payload: Option<Vec<u8>>,
}

impl TlsSerializeTrait for KeyPackage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = 0;
        if let Some(ref bytes) = self.serialized_payload {
            written += writer.write(bytes)?;
        } else {
            written += self.payload.tls_serialize(writer)?;
        }
        written += self.signature.tls_serialize(writer)?;
        Ok(written)
    }
}

impl PartialEq for KeyPackage {
    fn eq(&self, other: &Self) -> bool {
        // We ignore the signature in the comparison. The same key package
        // may have different, valid signatures.
        self.payload == other.payload
    }
}

impl SignedStruct<KeyPackageTbs> for KeyPackage {
    fn from_payload(
        payload: KeyPackageTbs,
        signature: Signature,
        serialized_payload: Vec<u8>,
    ) -> Self {
        Self {
            payload,
            signature,
            serialized_payload: Some(serialized_payload),
        }
    }
}

const SIGNATURE_KEY_PACKAGE_LABEL: &str = "KeyPackageTBS";

#[cfg(feature = "extensions-draft")]
fn last_resort_component_id() -> ComponentId {
    ComponentType::LastResortKeyPackage.into()
}

/// The leaf-node-specific parameters used when creating a [`KeyPackage`].
pub(crate) struct KeyPackageLeafNodeParams {
    pub(crate) lifetime: Lifetime,
    pub(crate) capabilities: Capabilities,
    pub(crate) extensions: Extensions<LeafNode>,
}

/// Helper struct containing the results of building a new [`KeyPackage`].
pub(crate) struct KeyPackageCreationResult {
    pub key_package: KeyPackage,
    pub encryption_keypair: EncryptionKeyPair,
    pub init_private_key: HpkePrivateKey,
}

/// Init key for HPKE.
#[derive(
    Debug,
    Clone,
    PartialEq,
    TlsSize,
    TlsSerialize,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
)]
pub struct InitKey {
    key: HpkePublicKey,
}

impl InitKey {
    /// Return the internal [`HpkePublicKey`].
    pub fn key(&self) -> &HpkePublicKey {
        &self.key
    }

    /// Return the internal [`HpkePublicKey`] as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.key.as_slice()
    }
}

impl From<Vec<u8>> for InitKey {
    fn from(key: Vec<u8>) -> Self {
        Self {
            key: HpkePublicKey::from(key),
        }
    }
}

impl From<HpkePublicKey> for InitKey {
    fn from(key: HpkePublicKey) -> Self {
        Self { key }
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

    /// Create a new key package for the given `ciphersuite` and `identity`.
    pub(crate) fn create(
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        extensions: Extensions<KeyPackage>,
        leaf_node_params: KeyPackageLeafNodeParams,
    ) -> Result<KeyPackageCreationResult, KeyPackageNewError> {
        if ciphersuite.signature_algorithm() != signer.signature_scheme() {
            return Err(KeyPackageNewError::CiphersuiteSignatureSchemeMismatch);
        }

        provider
            .crypto()
            .supports(ciphersuite)
            .map_err(|_| KeyPackageNewError::UnsupportedCiphersuite(ciphersuite))?;

        // Create a new HPKE key pair
        let ikm = Secret::random(ciphersuite, provider.rand())
            .map_err(LibraryError::unexpected_crypto_error)?;
        let init_key = provider
            .crypto()
            .derive_hpke_keypair(ciphersuite.hpke_config(), ikm.as_slice())
            .map_err(|e| {
                KeyPackageNewError::LibraryError(LibraryError::unexpected_crypto_error(e))
            })?;
        let (key_package, encryption_keypair) = Self::new_from_keys(
            ciphersuite,
            provider,
            signer,
            credential_with_key,
            extensions,
            leaf_node_params,
            init_key.public.into(),
        )?;

        Ok(KeyPackageCreationResult {
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
    fn new_from_keys(
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        extensions: Extensions<KeyPackage>,
        leaf_node_params: KeyPackageLeafNodeParams,
        init_key: InitKey,
    ) -> Result<(Self, EncryptionKeyPair), KeyPackageNewError> {
        // We don't need the private key here. It's stored in the key store for
        // use later when creating a group with this key package.

        let KeyPackageLeafNodeParams {
            lifetime,
            capabilities,
            extensions: leaf_node_extensions,
        } = leaf_node_params;

        let new_leaf_node_params = NewLeafNodeParams {
            ciphersuite,
            credential_with_key,
            leaf_node_source: LeafNodeSource::KeyPackage(lifetime),
            capabilities,
            extensions: leaf_node_extensions,
            tree_info_tbs: TreeInfoTbs::KeyPackage,
        };

        let (leaf_node, encryption_key_pair) =
            LeafNode::new(provider, signer, new_leaf_node_params)?;

        let key_package_tbs = KeyPackageTbs {
            protocol_version: ProtocolVersion::default(),
            ciphersuite,
            init_key,
            leaf_node,
            extensions,
        };

        let key_package = key_package_tbs.sign(signer)?;

        Ok((key_package, encryption_key_pair))
    }

    /// Create a new KeyPackage from caller-provided init and encryption keys.
    ///
    /// Mirrors [`KeyPackage::new_from_keys`] but takes a caller-provided
    /// encryption key pair for the leaf instead of generating a fresh one.
    /// Used by the virtual-clients KeyPackage build path, where both keys are
    /// derived from a per-operation secret so a sibling can reproduce them.
    #[cfg(feature = "virtual-clients-draft")]
    fn new_from_vc_keys(
        ciphersuite: Ciphersuite,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        extensions: Extensions<KeyPackage>,
        leaf_node_params: KeyPackageLeafNodeParams,
        init_key: InitKey,
        encryption_key_pair: EncryptionKeyPair,
    ) -> Result<(Self, EncryptionKeyPair), KeyPackageNewError> {
        let KeyPackageLeafNodeParams {
            lifetime,
            capabilities,
            extensions: leaf_node_extensions,
        } = leaf_node_params;

        let new_leaf_node_params = NewLeafNodeParams {
            ciphersuite,
            credential_with_key,
            leaf_node_source: LeafNodeSource::KeyPackage(lifetime),
            capabilities,
            extensions: leaf_node_extensions,
            tree_info_tbs: TreeInfoTbs::KeyPackage,
        };

        let (leaf_node, encryption_key_pair) = LeafNode::new_with_encryption_key_pair(
            signer,
            new_leaf_node_params,
            encryption_key_pair,
        )?;

        let key_package_tbs = KeyPackageTbs {
            protocol_version: ProtocolVersion::default(),
            ciphersuite,
            init_key,
            leaf_node,
            extensions,
        };

        let key_package = key_package_tbs.sign(signer)?;

        Ok((key_package, encryption_key_pair))
    }

    /// Get a reference to the extensions of this key package.
    pub fn extensions(&self) -> &Extensions<KeyPackage> {
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
    pub fn hash_ref(&self, crypto: &impl OpenMlsCrypto) -> Result<KeyPackageRef, LibraryError> {
        make_key_package_ref(
            &self
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?,
            self.payload.ciphersuite,
            crypto,
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
    pub fn hpke_init_key(&self) -> &InitKey {
        &self.payload.init_key
    }

    /// Check if this KeyPackage is a last-resort KeyPackage.
    ///
    /// When the `extensions-draft` feature is enabled, this recognizes the
    /// `last_resort_key_package` component in the KeyPackage's
    /// `app_data_dictionary`. The obsolete `last_resort` extension is also
    /// recognized so that previously stored KeyPackages remain usable.
    pub fn last_resort(&self) -> bool {
        #[cfg(feature = "extensions-draft")]
        if matches!(
            self.payload
                .extensions
                .app_data_dictionary()
                .and_then(|extension| extension.dictionary().get(&last_resort_component_id())),
            Some(data) if data.is_empty()
        ) {
            return true;
        }

        self.payload.extensions.contains(ExtensionType::LastResort)
    }

    #[cfg(feature = "extensions-draft")]
    fn has_malformed_last_resort_component(&self) -> bool {
        matches!(
            self.payload
                .extensions
                .app_data_dictionary()
                .and_then(|extension| extension.dictionary().get(&last_resort_component_id())),
            Some(data) if !data.is_empty()
        )
    }

    /// Get the lifetime of the KeyPackage
    pub fn life_time(&self) -> &Lifetime {
        // Leaf nodes contain a lifetime if an only if they are inside a KeyPackage. Since we are
        // in a KeyPackage, this can never be None and unwrap is safe.
        // TODO: get rid of the unwrap, see https://github.com/openmls/openmls/issues/1663.
        self.payload.leaf_node.life_time().unwrap()
    }
}

/// Crate visible `KeyPackage` functions.
impl KeyPackage {
    /// Get the `ProtocolVersion`.
    pub(crate) fn protocol_version(&self) -> ProtocolVersion {
        self.payload.protocol_version
    }
}

/// Builder that helps creating (and configuring) a [`KeyPackage`].
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackageBuilder {
    key_package_lifetime: Option<Lifetime>,
    key_package_extensions: Option<Extensions<KeyPackage>>,
    leaf_node_capabilities: Option<Capabilities>,
    leaf_node_extensions: Option<Extensions<LeafNode>>,
    last_resort: bool,
}

impl KeyPackageBuilder {
    /// Create a key package builder.
    pub fn new() -> Self {
        Self {
            key_package_lifetime: None,
            key_package_extensions: None,
            leaf_node_capabilities: None,
            leaf_node_extensions: None,
            last_resort: false,
        }
    }

    /// Set the key package lifetime.
    pub fn key_package_lifetime(mut self, lifetime: Lifetime) -> Self {
        self.key_package_lifetime.replace(lifetime);
        self
    }

    /// Set the key package extensions.
    pub fn key_package_extensions(mut self, extensions: Extensions<KeyPackage>) -> Self {
        self.key_package_extensions.replace(extensions);
        self
    }

    /// Mark the KeyPackage as a last-resort KeyPackage.
    ///
    /// With the `extensions-draft` feature enabled, this adds the
    /// `last_resort_key_package` component to the KeyPackage's
    /// `app_data_dictionary`. Otherwise, it adds the legacy `last_resort`
    /// extension.
    ///
    /// The leaf node capabilities must advertise support for the corresponding
    /// extension. Otherwise, building fails with
    /// [`KeyPackageNewError::MissingLastResortCapability`].
    pub fn mark_as_last_resort(mut self) -> Self {
        self.last_resort = true;
        self
    }

    /// Set the leaf node capabilities.
    pub fn leaf_node_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.leaf_node_capabilities.replace(capabilities);
        self
    }

    /// Set the leaf node extensions.
    ///
    /// Returns an error if one or more of the extensions is invalid in leaf nodes.
    pub fn leaf_node_extensions(mut self, extensions: Extensions<LeafNode>) -> Self {
        self.leaf_node_extensions.replace(extensions);
        self
    }

    fn ensure_last_resort_capability(
        &self,
        extension_type: ExtensionType,
    ) -> Result<(), KeyPackageNewError> {
        if self
            .leaf_node_capabilities
            .as_ref()
            .is_some_and(|capabilities| capabilities.contains_extension(extension_type))
        {
            Ok(())
        } else {
            Err(KeyPackageNewError::MissingLastResortCapability(
                extension_type,
            ))
        }
    }

    /// Ensure that a last-resort marker is present in the KeyPackage if the
    /// `last_resort` flag is set.
    #[cfg(feature = "extensions-draft")]
    fn ensure_last_resort(&mut self) -> Result<(), KeyPackageNewError> {
        if !self.last_resort {
            return Ok(());
        }

        self.ensure_last_resort_capability(ExtensionType::AppDataDictionary)?;

        let mut dictionary = self
            .key_package_extensions
            .as_ref()
            .and_then(Extensions::app_data_dictionary)
            .map(|extension| extension.dictionary().clone())
            .unwrap_or_default();
        dictionary.insert(last_resort_component_id(), Vec::new());

        let last_resort_component =
            Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
        if let Some(extensions) = self.key_package_extensions.as_mut() {
            extensions.remove(ExtensionType::LastResort);
            extensions
                .add_or_replace(last_resort_component)
                .expect("AppDataDictionary extensions are allowed in KeyPackages");
        } else {
            self.key_package_extensions = Some(
                Extensions::single(last_resort_component)
                    .expect("AppDataDictionary extensions are allowed in KeyPackages"),
            );
        }
        Ok(())
    }

    #[cfg(not(feature = "extensions-draft"))]
    fn ensure_last_resort(&mut self) -> Result<(), KeyPackageNewError> {
        if !self.last_resort {
            return Ok(());
        }

        self.ensure_last_resort_capability(ExtensionType::LastResort)?;

        let last_resort_extension = Extension::LastResort(LastResortExtension::default());
        if let Some(extensions) = self.key_package_extensions.as_mut() {
            extensions
                .add_or_replace(last_resort_extension)
                .expect("LastResort extensions are allowed in KeyPackages");
        } else {
            self.key_package_extensions = Some(
                Extensions::single(last_resort_extension)
                    .expect("LastResort extensions are allowed in KeyPackages"),
            );
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn build_without_storage(
        mut self,
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
    ) -> Result<KeyPackageCreationResult, KeyPackageNewError> {
        self.ensure_last_resort()?;
        let leaf_node_params = KeyPackageLeafNodeParams {
            lifetime: self.key_package_lifetime.unwrap_or_default(),
            capabilities: self.leaf_node_capabilities.unwrap_or_default(),
            extensions: self.leaf_node_extensions.unwrap_or_default(),
        };
        KeyPackage::create(
            ciphersuite,
            provider,
            signer,
            credential_with_key,
            self.key_package_extensions.unwrap_or_default(),
            leaf_node_params,
        )
    }

    /// Finalize and build the key package.
    pub fn build(
        mut self,
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
    ) -> Result<KeyPackageBundle, KeyPackageNewError> {
        self.ensure_last_resort()?;

        let leaf_node_params = KeyPackageLeafNodeParams {
            lifetime: self.key_package_lifetime.unwrap_or_default(),
            capabilities: self.leaf_node_capabilities.unwrap_or_default(),
            extensions: self.leaf_node_extensions.unwrap_or_default(),
        };
        let KeyPackageCreationResult {
            key_package,
            encryption_keypair,
            init_private_key,
        } = KeyPackage::create(
            ciphersuite,
            provider,
            signer,
            credential_with_key,
            self.key_package_extensions.unwrap_or_default(),
            leaf_node_params,
        )?;

        // Store the key package in the key store with the hash reference as id
        // for retrieval when parsing welcome messages.
        let full_kp = KeyPackageBundle {
            key_package,
            private_init_key: init_private_key,
            private_encryption_key: encryption_keypair.private_key().clone(),
        };
        provider
            .storage()
            .write_key_package(&full_kp.key_package.hash_ref(provider.crypto())?, &full_kp)
            .map_err(|_| KeyPackageNewError::StorageError)?;

        Ok(full_kp)
    }

    /// Build a batch of virtual-client KeyPackages a sibling can reproduce.
    ///
    /// Allocates a single generation of the `key_package` operation ratchet for
    /// the emulation epoch identified by `epoch_id`. For each
    /// `key_package_index` in `0..count` it derives a per-KeyPackage seed
    /// secret from that one operation secret and derives the KeyPackage's init
    /// key and leaf encryption key from the seed. Each leaf carries an
    /// encrypted `DerivationInfo` under
    /// [`VC_COMPONENT_ID`](crate::components::vc_derivation_info::VC_COMPONENT_ID)
    /// so a sibling can recover the emulation leaf index, generation, and
    /// index.
    ///
    /// The operation secret and the seeds are derived under the emulation
    /// epoch's ciphersuite (the operation tree's ciphersuite). The init and
    /// leaf-encryption keys are derived from each seed under the KeyPackage's
    /// own `ciphersuite`.
    ///
    /// Each leaf must declare `AppDataDictionary` support and list
    /// [`VC_COMPONENT_ID`](crate::components::vc_derivation_info::VC_COMPONENT_ID)
    /// in its `AppComponents` entry, otherwise this returns
    /// [`VirtualClientsError::AppDataDictionaryNotSupported`](crate::components::vc_derivation_info::VirtualClientsError::AppDataDictionaryNotSupported)
    /// or
    /// [`VirtualClientsError::VcComponentNotListed`](crate::components::vc_derivation_info::VirtualClientsError::VcComponentNotListed).
    ///
    /// Returns a [`VcKeyPackageBatch`] holding the batch's `generation` and one
    /// `(KeyPackageBundle, KeyPackageInfo)` per KeyPackage. Each bundle is also
    /// written to storage so the creating client can process its own Welcomes,
    /// and each
    /// [`KeyPackageInfo`](crate::components::vc_derivation_info::KeyPackageInfo)
    /// carries the index the client hands to its sibling.
    ///
    /// Returns [`KeyPackageNewError::EmptyBatch`] when `count` is 0, before
    /// loading any state or consuming a generation.
    #[cfg(feature = "virtual-clients-draft")]
    pub fn build_vc_batch(
        self,
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        epoch_id: crate::components::vc_derivation_info::EpochId,
        count: usize,
    ) -> Result<VcKeyPackageBatch, KeyPackageNewError> {
        // Reject an unsupported ciphersuite and an empty batch before loading
        // state or consuming a generation.
        provider
            .crypto()
            .supports(ciphersuite)
            .map_err(|_| KeyPackageNewError::UnsupportedCiphersuite(ciphersuite))?;

        if count == 0 {
            return Err(KeyPackageNewError::EmptyBatch);
        }
        let mut builder = VcKeyPackageBatchBuilder::with_capacity(provider, epoch_id, count)?;
        for _ in 0..count {
            builder.add_key_package(
                self.clone(),
                ciphersuite,
                provider.crypto(),
                signer,
                credential_with_key.clone(),
            )?;
        }
        builder.finalize(provider)
    }
}

/// A [`KeyPackageBundle`] contains a [`KeyPackage`] and the init and encryption
/// private key.
///
/// This is stored to ensure the private key is handled together with the key
/// package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackageBundle {
    pub(crate) key_package: KeyPackage,
    pub(crate) private_init_key: HpkePrivateKey,
    pub(crate) private_encryption_key: EncryptionPrivateKey,
}

// Public `KeyPackageBundle` functions.
impl KeyPackageBundle {
    /// Get a reference to the public part of this bundle, i.e. the [`KeyPackage`].
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    /// Extract the key package from the bundle.
    pub fn into_key_package(self) -> KeyPackage {
        self.key_package
    }

    /// Get a reference to the private init key.
    pub fn init_private_key(&self) -> &HpkePrivateKey {
        &self.private_init_key
    }

    /// Get the encryption key pair.
    pub(crate) fn encryption_key_pair(&self) -> EncryptionKeyPair {
        EncryptionKeyPair::from((
            self.key_package.leaf_node().encryption_key().clone(),
            self.private_encryption_key.clone(),
        ))
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl KeyPackageBundle {
    /// Generate a new key package bundle with the private key.
    pub fn new(
        key_package: KeyPackage,
        private_init_key: HpkePrivateKey,
        private_encryption_key: EncryptionPrivateKey,
    ) -> Self {
        Self {
            key_package,
            private_init_key,
            private_encryption_key,
        }
    }

    /// Get a reference to the private encryption key.
    pub fn encryption_private_key(&self) -> &HpkePrivateKey {
        self.private_encryption_key.key()
    }
}

#[cfg(test)]
impl KeyPackageBundle {
    pub(crate) fn generate(
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        ciphersuite: Ciphersuite,
        credential_with_key: CredentialWithKey,
    ) -> Self {
        KeyPackage::builder()
            .build(ciphersuite, provider, signer, credential_with_key)
            .unwrap()
    }
}
