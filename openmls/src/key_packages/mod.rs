use log::error;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::CryptoError;
use openmls_traits::types::HpkeKeyPair;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Serialize as TlsSerializeTrait, TlsSize, TlsVecU32};

use crate::ciphersuite::signable::Signable;
use crate::ciphersuite::signable::SignedStruct;
use crate::ciphersuite::signable::Verifiable;
use crate::ciphersuite::*;
use crate::config::{Config, ProtocolVersion};
use crate::credentials::*;
use crate::extensions::RequiredCapabilitiesExtension;
use crate::extensions::{
    CapabilitiesExtension, Extension, ExtensionError, ExtensionType, LifetimeExtension,
    ParentHashExtension,
};

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};

mod codec;
pub mod errors;
pub use errors::*;

#[cfg(test)]
mod test_key_packages;

/// The unsigned payload of a key package.
/// Any modification must happen on this unsigned struct. Use `sign` to get a
/// signed key package.
#[derive(Debug, Clone, PartialEq, TlsSize)]
pub struct KeyPackagePayload {
    protocol_version: ProtocolVersion,
    ciphersuite: &'static Ciphersuite,
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

implement_persistence!(
    KeyPackagePayload,
    protocol_version,
    hpke_init_key,
    credential,
    extensions
);

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
    pub fn add_extension(&mut self, extension: Extension) {
        self.remove_extension(extension.extension_type());
        self.extensions.push(extension);
    }

    /// Get extensions of the KeyPackage.
    pub fn extensions(&self) -> &[Extension] {
        self.extensions.as_slice()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackage {
    payload: KeyPackagePayload,
    signature: Signature,
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

/// Public `KeyPackage` functions.
impl KeyPackage {
    /// Verify that this key package is valid:
    /// * verify that the signature on this key package is valid
    /// * verify that all mandatory extensions are present
    /// * make sure that the lifetime is valid
    /// Returns `Ok(())` if all checks succeed and `KeyPackageError` otherwise
    pub fn verify(&self, backend: &impl OpenMlsCryptoProvider) -> Result<(), KeyPackageError> {
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
                            return Err(KeyPackageError::InvalidLifetimeExtension);
                        }
                    }
                    Err(e) => {
                        log::error!("as_lifetime_extension failed while verifying a key package.");
                        error!("Library error: {:?}", e);
                        return Err(KeyPackageError::LibraryError);
                    }
                }
            }
        }

        // Make sure we found all mandatory extensions.
        if !mandatory_extensions_found.is_empty() {
            log::error!("This key package is missing mandatory extensions.");
            return Err(KeyPackageError::MandatoryExtensionsMissing);
        }

        // Verify the signature on this key package.
        <Self as Verifiable>::verify_no_out(self, backend, &self.payload.credential).map_err(|_| {
            log::error!("Key package signature is invalid.");
            KeyPackageError::InvalidSignature
        })
    }

    /// Compute the hash of the encoding of this key package.
    pub fn hash(&self, backend: &impl OpenMlsCryptoProvider) -> Result<Vec<u8>, KeyPackageError> {
        let bytes = self.tls_serialize_detached()?;
        Ok(self.payload.ciphersuite.hash(backend, &bytes)?)
    }

    /// Get the ID of this key package as byte slice.
    /// Returns an error if no Key ID extension is present.
    pub fn key_id(&self) -> Result<&[u8], KeyPackageError> {
        if let Some(key_id_ext) = self.extension_with_type(ExtensionType::KeyId) {
            return Ok(key_id_ext.as_key_id_extension()?.as_slice());
        }
        Err(KeyPackageError::ExtensionError(
            ExtensionError::InvalidExtensionType("Tried to get a key ID extension".into()),
        ))
    }

    /// Get a reference to the extensions of this key package.
    pub fn extensions(&self) -> &[Extension] {
        self.payload.extensions.as_slice()
    }

    /// Get a reference to the credential.
    pub fn credential(&self) -> &Credential {
        &self.payload.credential
    }

    /// Check that all extensions that are required, are supported by this key
    /// package.
    pub(crate) fn validate_required_capabilities<'a>(
        &self,
        required_capabilities: impl Into<Option<&'a RequiredCapabilitiesExtension>>,
    ) -> Result<(), KeyPackageError> {
        if let Some(required_capabilities) = required_capabilities.into() {
            let my_capabilities = self
                .extension_with_type(ExtensionType::Capabilities)
                .ok_or(KeyPackageError::MandatoryExtensionsMissing)?
                .as_capabilities_extension()?;
            // Check required extension support.
            for required_extension in required_capabilities.extensions() {
                if !my_capabilities
                    .extensions()
                    .iter()
                    .any(|e| e == required_extension)
                {
                    return Err(KeyPackageError::UnsupportedExtension);
                }
            }
            // Check required proposal support.
            for required_proposal in required_capabilities.proposals() {
                if !my_capabilities
                    .proposals()
                    .iter()
                    .any(|p| p == required_proposal)
                {
                    return Err(KeyPackageError::UnsupportedProposal);
                }
            }
        }
        Ok(())
    }
}

/// Private `KeyPackage` functions.
impl KeyPackage {
    /// Create a new key package but only with the given `extensions` for the
    /// given `ciphersuite` and `identity`, and the initial HPKE key pair
    /// `init_key`.
    fn new(
        ciphersuite_name: CiphersuiteName,
        backend: &impl OpenMlsCryptoProvider,
        hpke_init_key: HpkePublicKey,
        credential_bundle: &CredentialBundle,
        extensions: Vec<Extension>,
    ) -> Result<Self, KeyPackageError> {
        if SignatureScheme::from(ciphersuite_name)
            != credential_bundle.credential().signature_scheme()
        {
            return Err(KeyPackageError::CiphersuiteSignatureSchemeMismatch);
        }
        let key_package = KeyPackagePayload {
            // TODO: #85 Take from global config.
            protocol_version: ProtocolVersion::default(),
            ciphersuite: Config::ciphersuite(ciphersuite_name)?,
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

    /// Get the `Ciphersuite`.
    pub(crate) fn ciphersuite(&self) -> &'static Ciphersuite {
        self.payload.ciphersuite
    }

    /// Get the `ProtocolVersion`.
    pub(crate) fn protocol_version(&self) -> ProtocolVersion {
        self.payload.protocol_version
    }

    /// Get the `CiphersuiteName`.
    pub fn ciphersuite_name(&self) -> CiphersuiteName {
        self.payload.ciphersuite.name()
    }
}

pub struct KeyPackageBundlePayload {
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
    pub fn from_key_package_and_leaf_secret(
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
    pub fn add_extension(&mut self, extension: Extension) {
        self.key_package_payload.add_extension(extension)
    }

    /// Get a reference to the `leaf_secret`.
    pub(crate) fn leaf_secret(&self) -> &Secret {
        &self.leaf_secret
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

/// Public `KeyPackageBundle` functions.
impl KeyPackageBundle {
    /// Create a new `KeyPackageBundle` with a fresh `HpkeKeyPair`.
    /// See `new_with_keypair` and `new_with_version` for details.
    /// This key package will have the default MLS version. Use `new_with_version`
    /// to get a key package bundle for a specific MLS version.
    ///
    /// Returns a new `KeyPackageBundle` or a `KeyPackageError`.
    pub fn new(
        ciphersuites: &[CiphersuiteName],
        credential_bundle: &CredentialBundle,
        backend: &impl OpenMlsCryptoProvider,
        extensions: Vec<Extension>,
    ) -> Result<Self, KeyPackageError> {
        Self::new_with_version(
            ProtocolVersion::default(),
            ciphersuites,
            backend,
            credential_bundle,
            extensions,
        )
    }

    /// Create a new `KeyPackageBundle` with
    /// * a fresh `HpkeKeyPair`
    /// * the provided MLS version
    /// * the first cipher suite in the `ciphersuites` slice
    /// * the provided `extensions`
    /// See `new_with_keypair` for details.
    ///
    /// Returns a new `KeyPackageBundle` or a `KeyPackageError`.
    pub fn new_with_version(
        version: ProtocolVersion,
        ciphersuites: &[CiphersuiteName],
        backend: &impl OpenMlsCryptoProvider,
        credential_bundle: &CredentialBundle,
        extensions: Vec<Extension>,
    ) -> Result<Self, KeyPackageError> {
        if SignatureScheme::from(ciphersuites[0])
            != credential_bundle.credential().signature_scheme()
        {
            return Err(KeyPackageError::CiphersuiteSignatureSchemeMismatch);
        }
        debug_assert!(!ciphersuites.is_empty());
        let ciphersuite = Config::ciphersuite(ciphersuites[0])?;
        let leaf_secret = Secret::random(ciphersuite, backend, version)?;
        Self::new_from_leaf_secret(
            ciphersuites,
            backend,
            credential_bundle,
            extensions,
            leaf_secret,
        )
    }

    /// Create a new `KeyPackageBundle` for the given `ciphersuite`, `identity`,
    /// and `extensions`, using the given HPKE `key_pair`.
    ///
    /// Note that the capabilities extension gets added automatically, based on
    /// the configuration. The ciphersuite for this key package bundle is the
    /// first one in the `ciphersuites` list. If a capabilities extension is
    /// included in the extensions, its supported ciphersuites have to match the
    /// `ciphersuites` list.
    ///
    /// Returns an `DuplicateExtension` error if `extensions` contains multiple
    /// extensions of the same type.
    ///
    /// Returns a new `KeyPackageBundle`.
    pub fn new_with_keypair(
        ciphersuites: &[CiphersuiteName],
        backend: &impl OpenMlsCryptoProvider,
        credential_bundle: &CredentialBundle,
        mut extensions: Vec<Extension>,
        key_pair: HpkeKeyPair,
        leaf_secret: Secret,
    ) -> Result<Self, KeyPackageError> {
        if ciphersuites.is_empty() {
            let error = KeyPackageError::NoCiphersuitesSupplied;
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
            let error = KeyPackageError::DuplicateExtension;
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
                    let error = KeyPackageError::CiphersuiteMismatch;
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
        )?;
        Ok(KeyPackageBundle {
            key_package,
            private_key: key_pair.private.into(),
            leaf_secret,
        })
    }

    /// Get a reference to the `KeyPackage`.
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    /// Get the unsigned payload version of this key package bundle for modificaiton.
    pub fn unsigned(self) -> KeyPackageBundlePayload {
        self.into()
    }
}

/// Private `KeyPackageBundle` functions.
impl KeyPackageBundle {
    fn new_from_leaf_secret(
        ciphersuites: &[CiphersuiteName],
        backend: &impl OpenMlsCryptoProvider,
        credential_bundle: &CredentialBundle,
        extensions: Vec<Extension>,
        leaf_secret: Secret,
    ) -> Result<Self, KeyPackageError> {
        if ciphersuites.is_empty() {
            let error = KeyPackageError::NoCiphersuitesSupplied;
            error!(
                "Error creating new KeyPackageBundle: No Ciphersuites specified {:?}",
                error
            );
            return Err(error);
        }

        let ciphersuite = Config::ciphersuite(ciphersuites[0])?;
        let leaf_node_secret = derive_leaf_node_secret(&leaf_secret, backend);
        let keypair = backend
            .crypto()
            .derive_hpke_keypair(ciphersuite.hpke_config(), leaf_node_secret?.as_slice());
        Self::new_with_keypair(
            ciphersuites,
            backend,
            credential_bundle,
            extensions,
            keypair,
            leaf_secret,
        )
    }
}

/// Crate visible `KeyPackageBundle` functions.
impl KeyPackageBundle {
    /// Update the private key in the bundle.
    pub(crate) fn _set_private_key(&mut self, private_key: HpkePrivateKey) {
        self.private_key = private_key;
    }

    /// Get a reference to the `HpkePrivateKey`.
    pub(crate) fn private_key(&self) -> &HpkePrivateKey {
        &self.private_key
    }

    /// Get a reference to the `leaf_secret`.
    pub fn leaf_secret(&self) -> &Secret {
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
