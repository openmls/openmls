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
//!     KeyPackageBundle::new(&[ciphersuite], &credential_bundle, &backend, Extensions::empty())
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
    extensions::{CapabilitiesExtension, Extension, ExtensionType, Extensions, LifetimeExtension},
    treesync::LeafNode,
    versions::ProtocolVersion,
};
use log::error;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, CryptoError, HpkeKeyPair, SignatureScheme},
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
    extensions: Extensions,
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
        for extension in self.payload.extensions.inner().iter() {
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
        let my_extension_types = self
            .extensions()
            .inner()
            .iter()
            .map(|ext| ext.extension_type());
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
        // TODO: #819: properly handle extensions (what's going where?)
        extensions: Extensions,
    ) -> Result<Self, KeyPackageNewError> {
        if SignatureScheme::from(ciphersuite) != credential_bundle.credential().signature_scheme() {
            return Err(KeyPackageNewError::CiphersuiteSignatureSchemeMismatch);
        }

        let lifetime = extensions.lifetime().map(Clone::clone).unwrap_or_default();
        let leaf_node = LeafNode::from_init_key(
            hpke_init_key.clone(),
            credential_bundle,
            lifetime,
            extensions.clone(),
            backend,
        )?;
        let key_package = KeyPackageTBS {
            // TODO: #34 Take from global config.
            protocol_version: ProtocolVersion::default(),
            ciphersuite,
            init_key: hpke_init_key,
            leaf_node,
            credential: credential_bundle.credential().clone(),
            extensions,
        };
        Ok(key_package.sign(backend, credential_bundle)?)
    }
}

/// Crate visible `KeyPackage` functions.
impl KeyPackage {
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
    leaf_secret: Secret,
}

#[cfg(not(any(feature = "test-utils", test)))]
pub(crate) struct KeyPackageBundlePayload {
    key_package_tbs: KeyPackageTBS,
    private_key: HpkePrivateKey,
    leaf_secret: Secret,
}

impl KeyPackageBundlePayload {
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

    #[cfg(any(feature = "test-utils", test))]
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.key_package_tbs.extensions
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
            leaf_secret: payload.leaf_secret,
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
    pub(crate) leaf_secret: Secret,
}

impl From<KeyPackageBundle> for KeyPackageBundlePayload {
    fn from(kpb: KeyPackageBundle) -> Self {
        Self {
            key_package_tbs: kpb.key_package.into(),
            private_key: kpb.private_key,
            leaf_secret: kpb.leaf_secret,
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
        extensions: Extensions,
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
        extensions: Extensions,
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
        mut extensions: Extensions,
        key_pair: HpkeKeyPair,
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

        let ciphersuite = ciphersuites.iter().find(|&&c| {
            SignatureScheme::from(c) == credential_bundle.credential().signature_scheme()
        });
        let ciphersuite =
            *ciphersuite.ok_or(KeyPackageBundleNewError::CiphersuiteSignatureSchemeMismatch)?;

        // First, check if one of the input extensions is a capabilities
        // extension. If there is, check if one of the extensions is a
        // capabilities extensions and if the contained ciphersuites are the
        // same as the ciphersuites passed as input. If that is not the case,
        // return an error. If none of the extensions is a capabilities
        // extension, create one that supports the given ciphersuites and that
        // is otherwise default.

        match extensions.capabilities() {
            Some(capabilities) => {
                if capabilities.ciphersuites() != ciphersuites {
                    let error = KeyPackageBundleNewError::CiphersuiteMismatch;
                    error!(
                        "Error creating new KeyPackageBundle: Invalid Capabilities Extensions {:?}",
                        error
                    );
                    return Err(error);
                }
            }
            None => {
                extensions.add_or_replace(Extension::Capabilities(CapabilitiesExtension::new(
                    None,
                    Some(ciphersuites),
                    None,
                    None,
                )));
            }
        };

        // Check if there is a lifetime extension. If not, add one that is at
        // least valid.
        if !extensions.contains(ExtensionType::Lifetime) {
            extensions.add_or_replace(Extension::Lifetime(LifetimeExtension::default()));
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
            leaf_secret,
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

    /// Separates the bundle into the [`KeyPackage`] and the HPKE private key and
    /// leaf secret as raw byte vectors.
    pub fn into_parts(self) -> (KeyPackage, (Vec<u8>, Vec<u8>)) {
        (
            self.key_package,
            (
                self.private_key.as_slice().to_vec(),
                self.leaf_secret.as_slice().to_vec(),
            ),
        )
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
        extensions: Extensions,
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
        let leaf_node_secret = derive_leaf_node_secret(&leaf_secret, backend)
            .map_err(LibraryError::unexpected_crypto_error)?;
        let keypair = backend
            .crypto()
            .derive_hpke_keypair(ciphersuite.hpke_config(), leaf_node_secret.as_slice());
        Self::new_with_keypair(
            ciphersuites,
            backend,
            credential_bundle,
            extensions,
            keypair,
            leaf_secret,
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

    /// Get a reference to the leaf secret associated with this bundle.
    pub(crate) fn leaf_secret(&self) -> &Secret {
        &self.leaf_secret
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

/// This function derives the leaf_node_secret from the leaf_secret as
/// described in 5.4 Ratchet Tree Evolution
pub(crate) fn derive_leaf_node_secret(
    leaf_secret: &Secret,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<Secret, CryptoError> {
    leaf_secret.derive_secret(backend, "node")
}

/// A builder for [`KeyPackageBundle`].
pub struct KeyPackageBundleBuilder {
    version: Option<ProtocolVersion>,
    ciphersuites: Option<Vec<Ciphersuite>>,
    extensions: Option<Extensions>,
    keypair: Option<HpkeKeyPair>,
    leaf_secret: Option<Secret>,
}

impl KeyPackageBundleBuilder {
    /// Create a new [`KeyPackageBundleBuilder`].
    pub fn new() -> Self {
        Self {
            version: None,
            ciphersuites: None,
            extensions: None,
            keypair: None,
            leaf_secret: None,
        }
    }

    /// Set the version that should be used in the [`KeyPackage`].
    /// Note: A subsequent call will replace the previous value.
    pub fn version(self, version: ProtocolVersion) -> Self {
        Self {
            version: Some(version),
            ..self
        }
    }

    /// Set the ciphersuites that should be used in the [`KeyPackage`].
    /// Note: A subsequent call will replace the previous value.
    pub fn ciphersuites(self, ciphersuites: Vec<Ciphersuite>) -> Self {
        Self {
            ciphersuites: Some(ciphersuites),
            ..self
        }
    }

    /// Set the extensions that should be used in the [`KeyPackage`].
    /// Note: A subsequent call will replace the previous value.
    pub fn extensions(self, extensions: Extensions) -> Self {
        Self {
            extensions: Some(extensions),
            ..self
        }
    }

    /// Set the keypair that should be used in the [`KeyPackage`].
    /// Note: A subsequent call will replace the previous value.
    pub fn keypair(self, keypair: HpkeKeyPair) -> Self {
        Self {
            keypair: Some(keypair),
            ..self
        }
    }

    pub(crate) fn leaf_secret(self, leaf_secret: Secret) -> Self {
        Self {
            leaf_secret: Some(leaf_secret),
            ..self
        }
    }

    /// Build a [`KeyPackageBundle`].
    /// This method will validate the provided values and
    /// return an error when the configuration is invalid.
    pub fn build(
        self,
        backend: &impl OpenMlsCryptoProvider,
        credential_bundle: CredentialBundle,
    ) -> Result<KeyPackageBundle, KeyPackageBundleNewError> {
        // Destructure into components (moving the values).
        let Self {
            version,
            ciphersuites,
            extensions,
            keypair,
            leaf_secret,
        } = self;

        let version = version.unwrap_or_default();

        let ciphersuites = match ciphersuites {
            Some(ciphersuites) => ciphersuites,
            None => {
                // TODO:
                //      * Do we want a default at all?
                //      * Do we want these values as default?
                let ciphersuites = ciphersuites.unwrap_or_else(|| {
                    vec![
                        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                    ]
                });

                if ciphersuites.is_empty() {
                    let error = KeyPackageBundleNewError::NoCiphersuitesSupplied;
                    error!(
                        "Error creating new KeyPackageBundle: No Ciphersuites specified {:?}",
                        error
                    );
                    return Err(error);
                }

                ciphersuites
            }
        };

        let ciphersuite = {
            let ciphersuite = ciphersuites.iter().find(|&&c| {
                SignatureScheme::from(c) == credential_bundle.credential().signature_scheme()
            });

            ciphersuite.ok_or(KeyPackageBundleNewError::CiphersuiteSignatureSchemeMismatch)?
        };

        let extensions = match extensions {
            Some(extensions) => extensions,
            None => {
                let mut extensions = extensions.unwrap_or_default();

                // First, check if one of the input extensions is a capabilities
                // extension. If there is, check if one of the extensions is a
                // capabilities extensions and if the contained ciphersuites are the
                // same as the ciphersuites passed as input. If that is not the case,
                // return an error. If none of the extensions is a capabilities
                // extension, create one that supports the given ciphersuites and that
                // is otherwise default.

                match extensions.capabilities() {
                    Some(capabilities) => {
                        if capabilities.ciphersuites() != ciphersuites {
                            let error = KeyPackageBundleNewError::CiphersuiteMismatch;
                            error!(
                        "Error creating new KeyPackageBundle: Invalid Capabilities Extensions {:?}",
                        error
                    );
                            return Err(error);
                        }
                    }
                    None => {
                        extensions.add_or_replace(Extension::Capabilities(
                            CapabilitiesExtension::new(None, Some(&ciphersuites), None, None),
                        ));
                    }
                };

                // Check if there is a lifetime extension. If not, add one that is at
                // least valid.
                if !extensions.contains(ExtensionType::Lifetime) {
                    extensions.add_or_replace(Extension::Lifetime(LifetimeExtension::default()));
                }

                extensions
            }
        };

        let keypair = match keypair {
            Some(keypair) => keypair,
            None => {
                // # Safety
                //
                // We have checked before that `ciphersuites` is not empty.
                // Thus, it is guaranteed to have a first element.
                let ciphersuite = ciphersuites.first().unwrap();

                let leaf_secret = Secret::random(*ciphersuite, backend, version)
                    .map_err(LibraryError::unexpected_crypto_error)?;

                let leaf_node_secret = derive_leaf_node_secret(&leaf_secret, backend)
                    .map_err(LibraryError::unexpected_crypto_error)?;

                backend
                    .crypto()
                    .derive_hpke_keypair(ciphersuite.hpke_config(), leaf_node_secret.as_slice())
            }
        };

        let key_package = KeyPackage::new(
            *ciphersuite,
            backend,
            keypair.public.into(),
            &credential_bundle,
            extensions,
        )
        .map_err(|e| match e {
            KeyPackageNewError::LibraryError(e) => e.into(),
            KeyPackageNewError::CiphersuiteSignatureSchemeMismatch => {
                KeyPackageBundleNewError::CiphersuiteSignatureSchemeMismatch
            }
        })?;

        let leaf_secret = match leaf_secret {
            Some(leaf_secret) => leaf_secret,
            None => Secret::random(*ciphersuite, backend, version)
                .map_err(LibraryError::unexpected_crypto_error)?,
        };

        Ok(KeyPackageBundle {
            key_package,
            private_key: keypair.private.into(),
            leaf_secret,
        })
    }
}
