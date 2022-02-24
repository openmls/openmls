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
//! cipher suites.
//!
//! The value for HPKE init key MUST be a public key for the asymmetric
//! encryption scheme defined by cipher suite, and it MUST be unique among the
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
    ciphersuite::{hash_ref::KeyPackageRef, signable::*, *},
    credentials::*,
    error::LibraryError,
    extensions::{
        errors::ExtensionError, CapabilitiesExtension, Extension, ExtensionType, LifetimeExtension,
        ParentHashExtension, RequiredCapabilitiesExtension,
    },
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
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, TlsSize, TlsVecU32,
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
#[derive(Debug, Clone, PartialEq, TlsSize, Serialize, Deserialize)]
struct KeyPackagePayload {
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    hpke_init_key: HpkePublicKey,
    credential: Credential,
    extensions: TlsVecU32<Extension>,
}

impl tls_codec::Serialize for KeyPackagePayload {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.protocol_version.tls_serialize(writer)?;
        written += self.ciphersuite.tls_serialize(writer)?;
        written += self.hpke_init_key.tls_serialize(writer)?;
        written += self.credential.tls_serialize(writer)?;
        self.extensions.tls_serialize(writer).map(|l| l + written)
    }
}

impl Signable for KeyPackagePayload {
    type SignedOutput = KeyPackage;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }
}

impl From<KeyPackage> for KeyPackagePayload {
    fn from(kp: KeyPackage) -> Self {
        kp.payload
    }
}

impl KeyPackagePayload {
    fn from_key_package(kp: &KeyPackage, hpke_init_key: HpkePublicKey) -> Self {
        Self {
            protocol_version: kp.payload.protocol_version,
            ciphersuite: kp.payload.ciphersuite,
            hpke_init_key,
            credential: kp.payload.credential.clone(),
            extensions: kp.payload.extensions.clone(),
        }
    }

    /// Remove an extension from the KeyPackage.
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
        self.hpke_init_key = public_key
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
    payload: KeyPackagePayload,
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

impl SignedStruct<KeyPackagePayload> for KeyPackage {
    fn from_payload(payload: KeyPackagePayload, signature: Signature) -> Self {
        Self { payload, signature }
    }
}

impl Verifiable for KeyPackage {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.payload.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// Mandatory extensions for key packages.
const MANDATORY_EXTENSIONS: [ExtensionType; 2] =
    [ExtensionType::Capabilities, ExtensionType::Lifetime];

// Public `KeyPackage` functions.
impl KeyPackage {
    /// Verify that this key package is valid:
    /// * verify that the signature on this key package is valid
    /// * verify that all mandatory extensions are present
    /// * make sure that the lifetime is valid
    /// Returns `Ok(())` if all checks succeed and `KeyPackageError` otherwise
    pub fn verify(
        &self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<(), KeyPackageVerifyError> {
        //  First make sure that all mandatory extensions are present.
        let mut mandatory_extensions_found = MANDATORY_EXTENSIONS.to_vec();
        for extension in self.payload.extensions.iter() {
            if let Some(p) = mandatory_extensions_found
                .iter()
                .position(|&e| e == extension.extension_type())
            {
                let _ = mandatory_extensions_found.remove(p);
            }
            // Make sure the lifetime is valid.
            if extension.extension_type() == ExtensionType::Lifetime {
                match extension.as_lifetime_extension() {
                    Ok(e) => {
                        if !e.is_valid() {
                            log::error!("Invalid lifetime extension in key package.");
                            return Err(KeyPackageVerifyError::InvalidLifetimeExtension);
                        }
                    }
                    Err(_) => {
                        log::error!("as_lifetime_extension failed while verifying a key package.");
                        return Err(LibraryError::custom("Expected a lifetime extension").into());
                    }
                }
            }
        }

        // Make sure we found all mandatory extensions.
        if !mandatory_extensions_found.is_empty() {
            log::error!("This key package is missing mandatory extensions.");
            return Err(KeyPackageVerifyError::MandatoryExtensionsMissing);
        }

        // Verify the signature on this key package.
        <Self as Verifiable>::verify_no_out(self, backend, &self.payload.credential).map_err(|_| {
            log::error!("Key package signature is invalid.");
            KeyPackageVerifyError::InvalidSignature
        })
    }

    /// Get the external ID of this key package as byte slice.
    /// See [`ExternalKeyIdExtension`](`crate::extensions::ExternalKeyIdExtension`)
    /// for more details on the external key ID extension.
    ///
    ///
    /// Returns a [`ExtensionError`] if no external key ID extension is present.
    pub fn external_key_id(&self) -> Result<&[u8], ExtensionError> {
        if let Some(key_id_ext) = self.extension_with_type(ExtensionType::ExternalKeyId) {
            return Ok(key_id_ext.as_external_key_id_extension()?.as_slice());
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

    /// Check that all extensions that are required, are supported by this key
    /// package.
    pub(crate) fn validate_required_capabilities<'a>(
        &self,
        required_capabilities: impl Into<Option<&'a RequiredCapabilitiesExtension>>,
    ) -> Result<(), KeyPackageExtensionSupportError> {
        if let Some(required_capabilities) = required_capabilities.into() {
            let my_extension_types = self.extensions().iter().map(|e| e.extension_type());
            for required_extension in required_capabilities.extensions() {
                if !my_extension_types.clone().any(|e| &e == required_extension) {
                    return Err(KeyPackageExtensionSupportError::UnsupportedExtension);
                }
            }
        }
        Ok(())
    }

    /// Compute the [`KeyPackageRef`] of this [`KeyPackage`].
    /// The [`KeyPackageRef`] is used to identify a member in a group (leaf in
    /// the tree) within MLS.
    pub fn hash_ref(&self, backend: &impl OpenMlsCrypto) -> Result<KeyPackageRef, LibraryError> {
        KeyPackageRef::new(
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
        extensions: Vec<Extension>,
    ) -> Result<Self, KeyPackageNewError> {
        if SignatureScheme::from(ciphersuite) != credential_bundle.credential().signature_scheme() {
            return Err(KeyPackageNewError::CiphersuiteSignatureSchemeMismatch);
        }
        let key_package = KeyPackagePayload {
            // TODO: #85 Take from global config.
            protocol_version: ProtocolVersion::default(),
            ciphersuite,
            hpke_init_key,
            credential: credential_bundle.credential().clone(),
            extensions: extensions.into(),
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
        for e in self.payload.extensions.as_slice() {
            if e.extension_type() == extension_type {
                return Some(e);
            }
        }
        None
    }

    /// Get a reference to the HPKE init key.
    pub(crate) fn hpke_init_key(&self) -> &HpkePublicKey {
        &self.payload.hpke_init_key
    }

    /// Get the `ProtocolVersion`.
    pub(crate) fn protocol_version(&self) -> ProtocolVersion {
        self.payload.protocol_version
    }
}

/// Payload of the [`KeyPackageBundle`].
#[cfg(any(feature = "test-utils", test))]
pub struct KeyPackageBundlePayload {
    key_package_payload: KeyPackagePayload,
    private_key: HpkePrivateKey,
    leaf_secret: Secret,
}

#[cfg(not(any(feature = "test-utils", test)))]
pub(crate) struct KeyPackageBundlePayload {
    key_package_payload: KeyPackagePayload,
    private_key: HpkePrivateKey,
    leaf_secret: Secret,
}

impl KeyPackageBundlePayload {
    /// Replace the init key in the `KeyPackage` with a random one and return a
    /// `KeyPackageBundlePayload` with the corresponding secret values.
    /// To get a key package bundle sign the `KeyPackageBundlePayload`.
    pub(crate) fn from_rekeyed_key_package(
        key_package: &KeyPackage,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, CryptoError> {
        let leaf_secret = Secret::random(
            key_package.ciphersuite(),
            backend,
            key_package.protocol_version(),
        )?;
        Self::from_key_package_and_leaf_secret(leaf_secret, key_package, backend)
    }

    /// Creates a new `KeyPackageBundlePayload` from a given `KeyPackage` and a leaf
    /// secret.
    /// To get a key package bundle sign the `KeyPackageBundlePayload`.
    pub(crate) fn from_key_package_and_leaf_secret(
        leaf_secret: Secret,
        key_package: &KeyPackage,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, CryptoError> {
        let leaf_node_secret = derive_leaf_node_secret(&leaf_secret, backend);
        let key_pair = backend.crypto().derive_hpke_keypair(
            key_package.ciphersuite().hpke_config(),
            leaf_node_secret?.as_slice(),
        );
        let key_package_payload =
            KeyPackagePayload::from_key_package(key_package, key_pair.public.into());
        Ok(Self {
            key_package_payload,
            private_key: key_pair.private.into(),
            leaf_secret,
        })
    }

    /// Update the parent hash extension of this key package.
    pub(crate) fn update_parent_hash(&mut self, parent_hash: &[u8]) {
        self.key_package_payload
            .remove_extension(ExtensionType::ParentHash);
        let extension = Extension::ParentHash(ParentHashExtension::new(parent_hash));
        self.key_package_payload.extensions.push(extension);
    }

    /// Add (or replace) an extension to the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn add_extension(&mut self, extension: Extension) {
        self.key_package_payload.add_extension(extension)
    }

    /// Get a reference to the `leaf_secret`.
    pub(crate) fn leaf_secret(&self) -> &Secret {
        &self.leaf_secret
    }

    /// Replace the credential in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_credential(&mut self, credential: Credential) {
        self.key_package_payload.set_credential(credential)
    }
    /// Replace the public key in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_public_key(&mut self, public_key: HpkePublicKey) {
        self.key_package_payload.set_public_key(public_key)
    }
    /// Replace the version in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_version(&mut self, version: ProtocolVersion) {
        self.key_package_payload.set_version(version)
    }
    /// Replace the ciphersuite in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_ciphersuite(&mut self, ciphersuite: Ciphersuite) {
        self.key_package_payload.set_ciphersuite(ciphersuite)
    }
}

impl Signable for KeyPackageBundlePayload {
    type SignedOutput = KeyPackageBundle;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.key_package_payload.unsigned_payload()
    }
}

impl SignedStruct<KeyPackageBundlePayload> for KeyPackageBundle {
    fn from_payload(payload: KeyPackageBundlePayload, signature: Signature) -> Self {
        let key_package = KeyPackage::from_payload(payload.key_package_payload, signature);
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
            key_package_payload: kpb.key_package.into(),
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
    /// * the first cipher suite in the `ciphersuites` slice
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

        if SignatureScheme::from(ciphersuites[0])
            != credential_bundle.credential().signature_scheme()
        {
            return Err(KeyPackageBundleNewError::CiphersuiteSignatureSchemeMismatch);
        }

        let ciphersuite = ciphersuites[0];
        let leaf_secret = Secret::random(ciphersuite, backend, version)
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

        // First, check if one of the input extensions is a capabilities
        // extension. If there is, check if one of the extensions is a
        // capabilities extensions and if the contained ciphersuites are the
        // same as the ciphersuites passed as input. If that is not the case,
        // return an error. If none of the extensions is a capabilities
        // extension, create one that supports the given ciphersuites and that
        // is otherwise default.

        match extensions
            .iter()
            .find(|e| e.extension_type() == ExtensionType::Capabilities)
        {
            Some(extension) => {
                let capabilities_extension = extension.as_capabilities_extension()?;
                if capabilities_extension.ciphersuites() != ciphersuites {
                    let error = KeyPackageBundleNewError::CiphersuiteMismatch;
                    error!(
                        "Error creating new KeyPackageBundle: Invalid Capabilities Extensions {:?}",
                        error
                    );
                    return Err(error);
                }
            }

            None => extensions.push(Extension::Capabilities(CapabilitiesExtension::new(
                None,
                Some(ciphersuites),
                None,
                None,
            ))),
        };

        // Check if there is a lifetime extension. If not, add one that is at
        // least valid.
        if !extensions
            .iter()
            .any(|e| e.extension_type() == ExtensionType::Lifetime)
        {
            extensions.push(Extension::LifeTime(LifetimeExtension::default()));
        }
        let key_package = KeyPackage::new(
            ciphersuites[0],
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

/// This function derives the leaf_node_secret from the leaf_secret as
/// described in 5.4 Ratchet Tree Evolution
pub(crate) fn derive_leaf_node_secret(
    leaf_secret: &Secret,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<Secret, CryptoError> {
    leaf_secret.derive_secret(backend, "node")
}
