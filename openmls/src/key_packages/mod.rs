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
//!     KeyPackageBundle::builder().ciphersuite(ciphersuite).build(&backend, credential_bundle)
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

use std::{
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    ciphersuite::{
        hash_ref::{make_key_package_ref, KeyPackageRef},
        signable::*,
        *,
    },
    credentials::*,
    error::LibraryError,
    extensions::Extension,
    treesync::LeafNode,
    versions::ProtocolVersion,
};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, HpkeKeyPair, SignatureScheme},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, TlsSerialize, TlsSize,
    VLBytes,
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
        lifetime: Lifetime,
        // TODO: #819: properly handle extensions (what's going where?)
        extensions: Vec<Extension>,
    ) -> Result<Self, KeyPackageNewError> {
        if SignatureScheme::from(ciphersuite) != credential_bundle.credential().signature_scheme() {
            return Err(KeyPackageNewError::CiphersuiteSignatureSchemeMismatch);
        }
        let leaf_node = LeafNode::from_init_key(
            hpke_init_key.clone(),
            credential_bundle,
            lifetime,
            extensions,
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
    /// Create a [`KeyPackageBundleBuilder`].
    pub fn builder() -> KeyPackageBundleBuilder {
        KeyPackageBundleBuilder::new()
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
    #[cfg(test)]
    pub(crate) fn new_from_leaf_secret(
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        credential_bundle: &CredentialBundle,
        lifetime: Lifetime,
        leaf_secret: Secret,
    ) -> Result<Self, KeyPackageBundleNewError> {
        let keypair = backend
            .crypto()
            .derive_hpke_keypair(ciphersuite.hpke_config(), leaf_secret.as_slice());

        Self::builder()
            .ciphersuite(ciphersuite)
            .lifetime(lifetime)
            .keypair(keypair)
            .build(backend, credential_bundle.clone())
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

/// This value is used as the default lifetime if no default  lifetime is configured.
/// The value is in seconds and amounts to 3 * 28 Days, i.e. about 3 months.
const DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS: u64 = 60 * 60 * 24 * 28 * 3;

/// This value is used as the default amount of time (in seconds) the lifetime
/// of a `KeyPackage` is extended into the past to allow for skewed clocks. The
/// value is in seconds and amounts to 1h.
const DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN_SECONDS: u64 = 60 * 60;

/// The lifetime extension represents the times between which clients will
/// consider a KeyPackage valid. This time is represented as an absolute time,
/// measured in seconds since the Unix epoch (1970-01-01T00:00:00Z).
/// A client MUST NOT use the data in a KeyPackage for any processing before
/// the not_before date, or after the not_after date.
///
/// Applications MUST define a maximum total lifetime that is acceptable for a
/// KeyPackage, and reject any KeyPackage where the total lifetime is longer
/// than this duration.This extension MUST always be present in a KeyPackage.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     uint64 not_before;
///     uint64 not_after;
/// } Lifetime;
/// ```
#[derive(PartialEq, Eq, Copy, Clone, Debug, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct Lifetime {
    not_before: u64,
    not_after: u64,
}

impl Lifetime {
    /// Create a new lifetime with lifetime `t` (in seconds).
    /// Note that the lifetime is extended 1h into the past to adapt to skewed
    /// clocks, i.e. `not_before` is set to now - 1h.
    pub fn new(t: u64) -> Self {
        let lifetime_margin: u64 = DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN_SECONDS;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH!")
            .as_secs();
        let not_before = now - lifetime_margin;
        let not_after = now + t;
        Self {
            not_before,
            not_after,
        }
    }

    /// Returns true if this lifetime is valid.
    pub(crate) fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH!")
            .as_secs();
        self.not_before < now && now < self.not_after
    }
}

impl Default for Lifetime {
    fn default() -> Self {
        Lifetime::new(DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS)
    }
}

// Deserialize manually in order to do additional validity checks.
impl tls_codec::Deserialize for Lifetime {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let not_before = u64::tls_deserialize(bytes)?;
        let not_after = u64::tls_deserialize(bytes)?;
        let out = Self {
            not_before,
            not_after,
        };
        if !out.is_valid() {
            log::trace!(
                "Lifetime expired!\n\tnot before: {:?} - not_after: {:?}",
                not_before,
                not_after
            );
            return Err(tls_codec::Error::DecodingError(
                "Invalid lifetime".to_string(),
            ));
        }
        Ok(out)
    }
}

/// A builder for [`KeyPackageBundle`].
pub struct KeyPackageBundleBuilder {
    version: Option<ProtocolVersion>,
    ciphersuite: Option<Ciphersuite>,
    lifetime: Option<Lifetime>,
    keypair: Option<HpkeKeyPair>,
}

impl KeyPackageBundleBuilder {
    /// Create a new [`KeyPackageBundleBuilder`].
    pub fn new() -> Self {
        Self {
            version: None,
            ciphersuite: None,
            lifetime: None,
            keypair: None,
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

    /// Set the ciphersuite that should be used in the [`KeyPackage`].
    /// Note: A subsequent call will replace the previous value.
    pub fn ciphersuite(self, ciphersuite: Ciphersuite) -> Self {
        Self {
            ciphersuite: Some(ciphersuite),
            ..self
        }
    }

    /// Set the lifetime that should be used in the [`KeyPackage`].
    /// Note: A subsequent call will replace the previous value.
    pub fn lifetime(self, lifetime: Lifetime) -> Self {
        Self {
            lifetime: Some(lifetime),
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
            ciphersuite,
            lifetime,
            keypair,
        } = self;

        let version = version.unwrap_or_default();
        // TODO: Do we want a default? Do we want this default?
        let ciphersuite =
            ciphersuite.unwrap_or(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);
        let lifetime = lifetime.unwrap_or_default();
        let keypair = match keypair {
            Some(keypair) => keypair,
            None => {
                let leaf_secret = Secret::random(ciphersuite, backend, version)
                    .map_err(LibraryError::unexpected_crypto_error)?;

                backend
                    .crypto()
                    .derive_hpke_keypair(ciphersuite.hpke_config(), leaf_secret.as_slice())
            }
        };

        // draft-ietf-mls-protocol-16 does not define any key package extension.
        let extensions = vec![];

        let key_package = KeyPackage::new(
            ciphersuite,
            backend,
            keypair.public.into(),
            &credential_bundle,
            lifetime,
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
            private_key: keypair.private.into(),
        })
    }
}
