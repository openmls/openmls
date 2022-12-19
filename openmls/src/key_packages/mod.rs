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
//! - A list of **extensions** for the key package (see [Extensions](`mod@crate::extensions`) for details)
//!
//! Key packages are intended to be used only once and SHOULD NOT be reused
//! except in case of last resort, i.e. if there's no other key package available.
//! Clients MAY generate and publish multiple KeyPackages to support multiple
//! ciphersuites.
//!
//! The value for HPKE init key MUST be a public key for the asymmetric
//! encryption scheme defined by ciphersuite, and it MUST be unique among the
//! set of key packages created by this client.
//! The whole structure is signed using the client's signature key.
//! A key package object with an invalid signature field is considered malformed.
//!
//! ## Creating key package bundles
//!
//! Key package bundles are key packages including their private key.
//! A key package bundle can be created as follows:
//!
//! ```
//! use openmls::prelude::*;
//! use openmls_rust_crypto::OpenMlsRustCrypto;
//!
//! let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
//! let backend = OpenMlsRustCrypto::default();
//!
//! let credential_bundle = CredentialBundle::new(
//!     b"Sasha".to_vec(),
//!     CredentialType::Basic,
//!     SignatureScheme::from(ciphersuite),
//!     &backend,
//! )
//! .expect("Error creating credential.");
//! let key_package_bundle =
//!     KeyPackageBundle::new(&[ciphersuite], &credential_bundle, &backend, vec![])
//!         .expect("Error creating key package bundle.");
//! ```
//!
//! See [`KeyPackageBundle`] for more details and other ways to create key
//! package bundles.
//!
//! ## Loading key packages
//!
//! When getting key packages from another user the serialized bytes are parsed
//! as follows;
//!
//! ```
//! use openmls::prelude::*;
//! use openmls::test_utils::hex_to_bytes;
//! use openmls_rust_crypto::OpenMlsRustCrypto;
//!
//! let key_package_bytes = hex_to_bytes(
//!         "0100010020687A9693D4FADC951B999E6EDD80B80F11747DE30620C75ED0A5F41E32\
//!          CB064C00010008000000000000000208070020AEF756C7D75DE1BEACA7D2DD17FA7A\
//!          C36F56B9BA1F7DF019BCB49A4138CEBCCB000000360002000000100000000061A0B6\
//!          2D000000006B086B9D00010000001A0201C8020001060001000200030C0001000200\
//!          030004000500080040961F9EC3D3F1BFCE673FEF39AB8BE6A8FF4D0BA40B3AA8A0DC\
//!          50CDE22482DC30A594EDDEC398F0966C3AFD67135007A6875F9873F4B521DF28827F\
//!          6A4EFF1704");
//! let key_package = KeyPackage::try_from(key_package_bytes.as_slice());
//! ```
//!
//! See [`KeyPackage`] for more details on how to use key packages.

use crate::{
    ciphersuite::{
        hash_ref::{make_key_package_ref, KeyPackageRef},
        signable::*,
        *,
    },
    credentials::*,
    error::LibraryError,
    extensions::{errors::ExtensionError, Extension, ExtensionType, LifetimeExtension},
    treesync::LeafNode,
    versions::ProtocolVersion,
};
use log::error;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, HpkeKeyPair, SignatureScheme},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, TlsSize, VLBytes,
};

// Private
mod codec;
use errors::*;

// Public
pub mod errors;

// Tests
#[cfg(test)]
mod test_key_packages;

// Public types

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
#[derive(Debug, Clone, PartialEq, TlsSize, Serialize, Deserialize)]
struct KeyPackageTBS {
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    init_key: HpkePublicKey,
    leaf_node: LeafNode,
    credential: Credential, // TODO[FK]: remove
    extensions: Vec<Extension>,
}

impl tls_codec::Serialize for KeyPackageTBS {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.protocol_version.tls_serialize(writer)?;
        written += self.ciphersuite.tls_serialize(writer)?;
        written += self.init_key.tls_serialize(writer)?;
        written += self.leaf_node.tls_serialize(writer)?;
        written += self.credential.tls_serialize(writer)?;
        self.extensions.tls_serialize(writer).map(|l| l + written)
    }
}

impl Signable for KeyPackageTBS {
    type SignedOutput = KeyPackage;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        SIGNATURE_KEY_PACKAGE_LABEL
    }
}

impl From<KeyPackage> for KeyPackageTBS {
    fn from(kp: KeyPackage) -> Self {
        kp.payload
    }
}

impl KeyPackageTBS {
    /// Remove an extension from the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn remove_extension(&mut self, extension_type: ExtensionType) {
        self.extensions
            .retain(|e| e.extension_type() != extension_type);
    }

    /// Add (or replace) an extension to the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    fn add_extension(&mut self, extension: Extension) {
        self.remove_extension(extension.extension_type());
        self.extensions.push(extension);
    }

    /// Replace the credential in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_credential(&mut self, credential: Credential) {
        self.credential = credential
    }

    /// Replace the public key in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_public_key(&mut self, public_key: HpkePublicKey) {
        self.init_key = public_key
    }
    /// Replace the version in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_version(&mut self, version: ProtocolVersion) {
        self.protocol_version = version
    }
    /// Replace the ciphersuite in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_ciphersuite(&mut self, ciphersuite: Ciphersuite) {
        self.ciphersuite = ciphersuite
    }
}

/// The key package struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackage {
    payload: KeyPackageTBS,
    signature: Signature,
}

impl TryFrom<&[u8]> for KeyPackage {
    type Error = tls_codec::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::tls_deserialize(&mut &*bytes)
    }
}

impl PartialEq for KeyPackage {
    fn eq(&self, other: &Self) -> bool {
        // We ignore the signature in the comparison. The same key package
        // may have different, valid signatures.
        self.payload == other.payload
    }
}

impl SignedStruct<KeyPackageTBS> for KeyPackage {
    fn from_payload(payload: KeyPackageTBS, signature: Signature) -> Self {
        Self { payload, signature }
    }
}

const SIGNATURE_KEY_PACKAGE_LABEL: &str = "KeyPackageTBS";

impl Verifiable for KeyPackage {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.payload.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        SIGNATURE_KEY_PACKAGE_LABEL
    }
}

// Public `KeyPackage` functions.
impl KeyPackage {
    /// Verify that this key package is valid:
    /// * verify that the signature on this key package is valid
    /// * verify that all extensions are supported by the leaf node
    /// * make sure that the lifetime is valid
    /// Returns `Ok(())` if all checks succeed and `KeyPackageError` otherwise
    pub fn verify(
        &self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<(), KeyPackageVerifyError> {
        // Extension included in the extensions or leaf_node.extensions fields
        // MUST be included in the leaf_node.capabilities field.
        for extension in self.payload.extensions.iter() {
            if !self
                .payload
                .leaf_node
                .supports_extension(&extension.extension_type())
            {
                return Err(KeyPackageVerifyError::UnsupportedExtension);
            }
        }

        // Ensure validity of the life time extension in the leaf node.
        if let Some(life_time) = self.payload.leaf_node.life_time() {
            if !life_time.is_valid() {
                return Err(KeyPackageVerifyError::InvalidLifetime);
            }
        } else {
            // This assumes that we only verify key packages with leaf nodes
            // that were created for the key package.
            return Err(KeyPackageVerifyError::MissingLifetime);
        }

        // Verify the signature on this key package.
        <Self as Verifiable>::verify_no_out(self, backend, &self.payload.credential).map_err(|_| {
            log::error!("Key package signature is invalid.");
            KeyPackageVerifyError::InvalidSignature
        })
    }

    /// Get the application ID of this key package as byte slice.
    /// See [`ApplicationIdExtension`](`crate::extensions::ApplicationIdExtension`)
    /// for more details on the application ID extension.
    ///
    ///
    /// Returns a [`ExtensionError`] if no application ID extension is present.
    pub fn application_id(&self) -> Result<&[u8], ExtensionError> {
        if let Some(key_id_ext) = self.extension_with_type(ExtensionType::ApplicationId) {
            return Ok(key_id_ext.as_application_id_extension()?.as_slice());
        } else {
            Err(ExtensionError::InvalidExtensionType(
                "Tried to get a key ID extension".into(),
            ))
        }
    }

    /// Get a reference to the extensions of this key package.
    pub fn extensions(&self) -> &[Extension] {
        self.payload.extensions.as_slice()
    }

    /// Check whether the this key package supports all the required extensions
    /// in the provided list.
    pub fn check_extension_support(
        &self,
        required_extensions: &[ExtensionType],
    ) -> Result<(), KeyPackageExtensionSupportError> {
        let my_extension_types = self.extensions().iter().map(|ext| ext.extension_type());
        for required in required_extensions.iter() {
            if !my_extension_types.clone().any(|e| &e == required) {
                return Err(KeyPackageExtensionSupportError::UnsupportedExtension);
            }
        }
        Ok(())
    }

    /// Get a reference to the [`Credential`].
    pub fn credential(&self) -> &Credential {
        &self.payload.credential
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
}

/// Private `KeyPackage` functions.
impl KeyPackage {
    /// Create a new key package but only with the given `extensions` for the
    /// given `ciphersuite` and `identity`, and the initial HPKE key pair
    /// `init_key`.
    fn new(
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        hpke_init_key: HpkePublicKey,
        credential_bundle: &CredentialBundle,
        // TODO: #819: Handle key package extensions (and refactor API).
        mut leaf_node_extensions: Vec<Extension>,
    ) -> Result<Self, KeyPackageNewError> {
        if SignatureScheme::from(ciphersuite) != credential_bundle.credential().signature_scheme() {
            return Err(KeyPackageNewError::CiphersuiteSignatureSchemeMismatch);
        }
        let life_time = leaf_node_extensions
            .iter()
            .position(|e| e.extension_type() == ExtensionType::Lifetime);
        let lifetime: LifetimeExtension = if let Some(index) = life_time {
            let extension = leaf_node_extensions.remove(index);
            extension
                .as_lifetime_extension()
                .map_err(|_| LibraryError::custom(""))?
                .clone()
        } else {
            LifetimeExtension::default()
        };
        let leaf_node = LeafNode::from_init_key(
            hpke_init_key.clone(),
            credential_bundle,
            lifetime,
            leaf_node_extensions,
            backend,
        )?;
        let key_package = KeyPackageTBS {
            // TODO: #34 Take from global config.
            protocol_version: ProtocolVersion::default(),
            ciphersuite,
            init_key: hpke_init_key,
            leaf_node,
            credential: credential_bundle.credential().clone(),
            extensions: vec![],
        };
        Ok(key_package.sign(backend, credential_bundle)?)
    }
}

/// Crate visible `KeyPackage` functions.
impl KeyPackage {
    /// Get a reference to the extension of `extension_type`.
    /// Returns `Some(extension)` if present and `None` if the extension is not
    /// present.
    pub(crate) fn extension_with_type(&self, extension_type: ExtensionType) -> Option<&Extension> {
        self.payload
            .extensions
            .as_slice()
            .iter()
            .find(|&e| e.extension_type() == extension_type)
    }

    /// Get a reference to the HPKE init key.
    pub(crate) fn hpke_init_key(&self) -> &HpkePublicKey {
        &self.payload.init_key
    }

    /// Get the `ProtocolVersion`.
    pub(crate) fn protocol_version(&self) -> ProtocolVersion {
        self.payload.protocol_version
    }

    /// Get the [`LeafNode`] reference.
    pub(crate) fn leaf_node(&self) -> &LeafNode {
        &self.payload.leaf_node
    }

    /// Get the [`LeafNode`].
    pub(crate) fn take_leaf_node(self) -> LeafNode {
        self.payload.leaf_node
    }
}

/// Payload of the [`KeyPackageBundle`].
#[cfg(any(feature = "test-utils", test))]
pub struct KeyPackageBundlePayload {
    key_package_tbs: KeyPackageTBS,
    private_key: HpkePrivateKey,
}

#[cfg(not(any(feature = "test-utils", test)))]
pub(crate) struct KeyPackageBundlePayload {
    key_package_tbs: KeyPackageTBS,
    private_key: HpkePrivateKey,
}

impl KeyPackageBundlePayload {
    /// Add (or replace) an extension to the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn add_extension(&mut self, extension: Extension) {
        self.key_package_tbs.add_extension(extension)
    }
    /// Replace the credential in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_credential(&mut self, credential: Credential) {
        self.key_package_tbs.set_credential(credential)
    }
    /// Replace the public key in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_public_key(&mut self, public_key: HpkePublicKey) {
        self.key_package_tbs.set_public_key(public_key)
    }
    /// Replace the version in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_version(&mut self, version: ProtocolVersion) {
        self.key_package_tbs.set_version(version)
    }
    /// Replace the ciphersuite in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_ciphersuite(&mut self, ciphersuite: Ciphersuite) {
        self.key_package_tbs.set_ciphersuite(ciphersuite)
    }
    /// Get the [`LeafNode`].
    #[cfg(any(feature = "test-utils", test))]
    pub fn leaf_node(&self) -> &LeafNode {
        &self.key_package_tbs.leaf_node
    }
    /// Set the [`LeafNode`].
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_leaf_node(&mut self, leaf_node: LeafNode) {
        self.key_package_tbs.leaf_node = leaf_node;
    }
}

impl Signable for KeyPackageBundlePayload {
    type SignedOutput = KeyPackageBundle;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.key_package_tbs.unsigned_payload()
    }

    fn label(&self) -> &str {
        SIGNATURE_KEY_PACKAGE_LABEL
    }
}

impl SignedStruct<KeyPackageBundlePayload> for KeyPackageBundle {
    fn from_payload(payload: KeyPackageBundlePayload, signature: Signature) -> Self {
        let key_package = KeyPackage::from_payload(payload.key_package_tbs, signature);
        Self {
            key_package,
            private_key: payload.private_key,
        }
    }
}

/// A [`KeyPackageBundle`] contains a [`KeyPackage`], the corresponding private
/// key, and a leaf secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct KeyPackageBundle {
    pub(crate) key_package: KeyPackage,
    pub(crate) private_key: HpkePrivateKey,
}

impl From<KeyPackageBundle> for KeyPackageBundlePayload {
    fn from(kpb: KeyPackageBundle) -> Self {
        Self {
            key_package_tbs: kpb.key_package.into(),
            private_key: kpb.private_key,
        }
    }
}

// Public `KeyPackageBundle` functions.
impl KeyPackageBundle {
    /// Create a new [`KeyPackageBundle`] with a fresh key pair.
    /// This key package will have the default MLS version.
    /// Use [`KeyPackageBundle::new_with_version`]
    /// to get a key package bundle for a specific MLS version.
    ///
    /// Note that the capabilities extension gets added automatically, based on
    /// the configuration.
    ///
    /// Returns a new [`KeyPackageBundle`] or a [`KeyPackageBundleNewError`].
    pub fn new(
        ciphersuites: &[Ciphersuite],
        credential_bundle: &CredentialBundle,
        backend: &impl OpenMlsCryptoProvider,
        extensions: Vec<Extension>,
    ) -> Result<Self, KeyPackageBundleNewError> {
        Self::new_with_version(
            ProtocolVersion::default(),
            ciphersuites,
            backend,
            credential_bundle,
            extensions,
        )
    }

    /// Create a new [`KeyPackageBundle`] with
    /// * a fresh key pair
    /// * the provided MLS version
    /// * the first ciphersuite in the `ciphersuites` slice
    /// * the provided `extensions`
    ///
    /// Note that the capabilities extension gets added automatically, based on
    /// the configuration.
    ///
    /// Returns a new [`KeyPackageBundle`] or a [`KeyPackageBundleNewError`].
    pub fn new_with_version(
        version: ProtocolVersion,
        ciphersuites: &[Ciphersuite],
        backend: &impl OpenMlsCryptoProvider,
        credential_bundle: &CredentialBundle,
        extensions: Vec<Extension>,
    ) -> Result<Self, KeyPackageBundleNewError> {
        if ciphersuites.is_empty() {
            let error = KeyPackageBundleNewError::NoCiphersuitesSupplied;
            error!(
                "Error creating new KeyPackageBundle: No Ciphersuites specified {:?}",
                error
            );
            return Err(error);
        }

        let ciphersuite = ciphersuites.iter().find(|&&c| {
            SignatureScheme::from(c) == credential_bundle.credential().signature_scheme()
        });
        let ciphersuite =
            ciphersuite.ok_or(KeyPackageBundleNewError::CiphersuiteSignatureSchemeMismatch)?;

        let leaf_secret = Secret::random(*ciphersuite, backend, version)
            .map_err(LibraryError::unexpected_crypto_error)?;
        Self::new_from_leaf_secret(
            ciphersuites,
            backend,
            credential_bundle,
            extensions,
            leaf_secret,
        )
    }

    /// Create a new [`KeyPackageBundle`] for the given `ciphersuite`, `identity`,
    /// and `extensions`, using the given [`HpkeKeyPair`].
    ///
    /// Note that the capabilities extension gets added automatically, based on
    /// the configuration. The ciphersuite for this key package bundle is the
    /// first one in the `ciphersuites` list. If a capabilities extension is
    /// included in the extensions, its supported ciphersuites have to match the
    /// `ciphersuites` list.
    ///
    /// Returns an [`KeyPackageBundleNewError::DuplicateExtension`] error if `extensions`
    /// contains multiple extensions of the same type.
    ///
    /// Returns a new [`KeyPackageBundle`].
    pub(crate) fn new_with_keypair(
        ciphersuites: &[Ciphersuite],
        backend: &impl OpenMlsCryptoProvider,
        credential_bundle: &CredentialBundle,
        mut extensions: Vec<Extension>,
        key_pair: HpkeKeyPair,
    ) -> Result<Self, KeyPackageBundleNewError> {
        if ciphersuites.is_empty() {
            let error = KeyPackageBundleNewError::NoCiphersuitesSupplied;
            error!(
                "Error creating new KeyPackageBundle: No Ciphersuites specified {:?}",
                error
            );
            return Err(error);
        }

        let ciphersuite = ciphersuites.iter().find(|&&c| {
            SignatureScheme::from(c) == credential_bundle.credential().signature_scheme()
        });
        let ciphersuite =
            *ciphersuite.ok_or(KeyPackageBundleNewError::CiphersuiteSignatureSchemeMismatch)?;

        // Detect duplicate extensions an return an error in case there is are any.
        let extensions_length = extensions.len();
        extensions.sort();
        extensions.dedup();
        if extensions_length != extensions.len() {
            let error = KeyPackageBundleNewError::DuplicateExtension;
            error!(
                "Error creating new KeyPackageBundle: Duplicate Extension {:?}",
                error
            );
            return Err(error);
        }

        // Check if there is a lifetime extension. If not, add one that is at
        // least valid.
        if !extensions
            .iter()
            .any(|e| e.extension_type() == ExtensionType::Lifetime)
        {
            extensions.push(Extension::Lifetime(LifetimeExtension::default()));
        }
        let key_package = KeyPackage::new(
            ciphersuite,
            backend,
            key_pair.public.into(),
            credential_bundle,
            extensions,
        )
        .map_err(|e| match e {
            KeyPackageNewError::LibraryError(e) => e.into(),
            KeyPackageNewError::CiphersuiteSignatureSchemeMismatch => {
                KeyPackageBundleNewError::CiphersuiteSignatureSchemeMismatch
            }
        })?;
        Ok(KeyPackageBundle {
            key_package,
            private_key: key_pair.private.into(),
        })
    }

    /// Get a reference to the public part of this bundle, i.e. the [`KeyPackage`].
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    /// Get a reference to the HPKE key pair.
    pub fn key_pair(&self) -> (&VLBytes, &HpkePublicKey) {
        (&self.private_key, self.key_package.hpke_init_key())
    }

    /// Get a reference to the HPKE key pair.
    pub fn hpke_key_pair(&self) -> HpkeKeyPair {
        HpkeKeyPair {
            private: self.private_key.clone().into(),
            public: self.key_package.hpke_init_key().as_slice().to_vec(),
        }
    }

    /// Separates the bundle into the [`KeyPackage`] and the HPKE private key
    /// as raw byte vectors.
    pub fn into_parts(self) -> (KeyPackage, Vec<u8>) {
        (self.key_package, self.private_key.as_slice().to_vec())
    }

    /// Get the unsigned payload version of this key package bundle for modificaiton.
    #[cfg(feature = "test-utils")]
    pub fn unsigned(self) -> KeyPackageBundlePayload {
        self.into()
    }
}

/// Crate visible `KeyPackageBundle` functions.
impl KeyPackageBundle {
    pub(crate) fn new_from_leaf_secret(
        ciphersuites: &[Ciphersuite],
        backend: &impl OpenMlsCryptoProvider,
        credential_bundle: &CredentialBundle,
        extensions: Vec<Extension>,
        leaf_secret: Secret,
    ) -> Result<Self, KeyPackageBundleNewError> {
        if ciphersuites.is_empty() {
            let error = KeyPackageBundleNewError::NoCiphersuitesSupplied;
            error!(
                "Error creating new KeyPackageBundle: No Ciphersuites specified {:?}",
                error
            );
            return Err(error);
        }

        let ciphersuite = ciphersuites[0];
        let keypair = backend
            .crypto()
            .derive_hpke_keypair(ciphersuite.hpke_config(), leaf_secret.as_slice());
        Self::new_with_keypair(
            ciphersuites,
            backend,
            credential_bundle,
            extensions,
            keypair,
        )
    }

    /// Update the private key in the bundle.
    pub(crate) fn _set_private_key(&mut self, private_key: HpkePrivateKey) {
        self.private_key = private_key;
    }

    /// Get a reference to the `HpkePrivateKey`.
    pub(crate) fn private_key(&self) -> &HpkePrivateKey {
        &self.private_key
    }
}

// Test-only functions
#[cfg(any(test, feature = "test-utils"))]
impl KeyPackageBundle {
    pub fn set_ciphersuite(&mut self, ciphersuite: Ciphersuite) {
        self.key_package.payload.set_ciphersuite(ciphersuite);
    }

    /// Replace the public key in the KeyPackage.
    pub fn set_public_key(&mut self, public_key: HpkePublicKey) {
        self.key_package.payload.init_key = public_key
    }
}
