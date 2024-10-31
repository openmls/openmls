//! Incoming KeyPackages. This modules contains deserialization and validation
//! of KeyPackages.

use crate::{
    ciphersuite::{signable::*, *},
    credentials::*,
    extensions::Extensions,
    treesync::node::leaf_node::{LeafNodeIn, VerifiableLeafNode},
    versions::ProtocolVersion,
};
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use serde::{Deserialize, Serialize};
use tls_codec::{
    Serialize as TlsSerializeTrait, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
};

use super::{
    errors::KeyPackageVerifyError, InitKey, KeyPackage, KeyPackageTbs, SIGNATURE_KEY_PACKAGE_LABEL,
};

#[cfg(any(feature = "test-utils", test))]
use super::KeyPackageBundle;

/// Intermediary struct for deserialization of a [`KeyPackageIn`].
struct VerifiableKeyPackage {
    payload: KeyPackageTbs,
    signature: Signature,
}

impl VerifiableKeyPackage {
    fn new(payload: KeyPackageTbs, signature: Signature) -> Self {
        Self { payload, signature }
    }
}

impl Verifiable for VerifiableKeyPackage {
    type VerifiedStruct = KeyPackage;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.payload.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        SIGNATURE_KEY_PACKAGE_LABEL
    }

    fn verify(
        self,
        crypto: &impl OpenMlsCrypto,
        pk: &OpenMlsSignaturePublicKey,
    ) -> Result<Self::VerifiedStruct, SignatureError> {
        self.verify_no_out(crypto, pk)?;

        Ok(KeyPackage {
            payload: self.payload,
            signature: self.signature,
        })
    }
}

impl VerifiedStruct for KeyPackage {}

/// The unsigned payload of a key package.
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
#[derive(
    Debug,
    Clone,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    Serialize,
    Deserialize,
)]
struct KeyPackageTbsIn {
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    init_key: InitKey,
    leaf_node: LeafNodeIn,
    extensions: Extensions,
}

/// The key package struct.
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct KeyPackageIn {
    payload: KeyPackageTbsIn,
    signature: Signature,
}

impl KeyPackageIn {
    /// Returns a [`CredentialWithKey`] from the unverified payload
    pub fn unverified_credential(&self) -> CredentialWithKey {
        let credential = self.payload.leaf_node.credential().clone();
        let signature_key = self.payload.leaf_node.signature_key().clone();
        CredentialWithKey {
            credential,
            signature_key,
        }
    }

    /// Verify that this key package is valid:
    /// * verify that the signature on this key package is valid
    /// * verify that the signature on the leaf node is valid
    /// * verify that all extensions are supported by the leaf node
    /// * make sure that the lifetime is valid
    /// * make sure that the init key and the encryption key are different
    /// * make sure that the protocol version is valid
    ///
    /// Returns a [`KeyPackage`] after having verified the signature or a
    /// [`KeyPackageVerifyError`] otherwise.
    pub fn validate(
        self,
        crypto: &impl OpenMlsCrypto,
        protocol_version: ProtocolVersion,
    ) -> Result<KeyPackage, KeyPackageVerifyError> {
        // We first need to verify the LeafNode inside the KeyPackage
        let leaf_node = self.payload.leaf_node.clone().into_verifiable_leaf_node();

        let signature_key = &OpenMlsSignaturePublicKey::from_signature_key(
            self.payload.leaf_node.signature_key().clone(),
            self.payload.ciphersuite.signature_algorithm(),
        );

        // https://validation.openmls.tech/#valn0108
        let leaf_node = match leaf_node {
            VerifiableLeafNode::KeyPackage(leaf_node) => leaf_node
                .verify(crypto, signature_key)
                .map_err(|_| KeyPackageVerifyError::InvalidLeafNodeSignature)?,
            _ => return Err(KeyPackageVerifyError::InvalidLeafNodeSourceType),
        };

        // Verify that the protocol version is valid
        // https://validation.openmls.tech/#valn0201
        if !self.version_is_supported(protocol_version) {
            return Err(KeyPackageVerifyError::InvalidProtocolVersion);
        }

        // Verify that the encryption key and the init key are different
        // https://validation.openmls.tech/#valn0204
        if leaf_node.encryption_key().key() == self.payload.init_key.key() {
            return Err(KeyPackageVerifyError::InitKeyEqualsEncryptionKey);
        }

        let key_package_tbs = KeyPackageTbs {
            protocol_version: self.payload.protocol_version,
            ciphersuite: self.payload.ciphersuite,
            init_key: self.payload.init_key,
            leaf_node,
            extensions: self.payload.extensions,
        };

        // Verify the KeyPackage signature
        // https://validation.openmls.tech/#valn0203
        let key_package = VerifiableKeyPackage::new(key_package_tbs, self.signature)
            .verify(crypto, signature_key)
            .map_err(|_| KeyPackageVerifyError::InvalidSignature)?;

        // Extension included in the extensions or leaf_node.extensions fields
        // MUST be included in the leaf_node.capabilities field.
        for extension in key_package.payload.extensions.iter() {
            if !key_package
                .payload
                .leaf_node
                .supports_extension(&extension.extension_type())
            {
                return Err(KeyPackageVerifyError::UnsupportedExtension);
            }
        }

        // Ensure validity of the life time extension in the leaf node.
        if let Some(life_time) = key_package.payload.leaf_node.life_time() {
            if !life_time.is_valid() {
                return Err(KeyPackageVerifyError::InvalidLifetime);
            }
        } else {
            // This assumes that we only verify key packages with leaf nodes
            // that were created for the key package.
            return Err(KeyPackageVerifyError::MissingLifetime);
        }

        Ok(key_package)
    }

    /// Returns true if the protocol version is supported by this key package and
    /// false otherwise.
    pub(crate) fn version_is_supported(&self, protocol_version: ProtocolVersion) -> bool {
        self.payload.protocol_version == protocol_version
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<KeyPackageTbsIn> for KeyPackageTbs {
    fn from(value: KeyPackageTbsIn) -> Self {
        KeyPackageTbs {
            protocol_version: value.protocol_version,
            ciphersuite: value.ciphersuite,
            init_key: value.init_key,
            leaf_node: value.leaf_node.into(),
            extensions: value.extensions,
        }
    }
}

impl From<KeyPackageTbs> for KeyPackageTbsIn {
    fn from(value: KeyPackageTbs) -> Self {
        Self {
            protocol_version: value.protocol_version,
            ciphersuite: value.ciphersuite,
            init_key: value.init_key,
            leaf_node: value.leaf_node.into(),
            extensions: value.extensions,
        }
    }
}

impl From<KeyPackage> for KeyPackageIn {
    fn from(value: KeyPackage) -> Self {
        Self {
            payload: value.payload.into(),
            signature: value.signature,
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<KeyPackageBundle> for KeyPackageIn {
    fn from(value: KeyPackageBundle) -> Self {
        Self {
            payload: value.key_package.payload.into(),
            signature: value.key_package.signature,
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<KeyPackageIn> for KeyPackage {
    fn from(value: KeyPackageIn) -> Self {
        Self {
            payload: value.payload.into(),
            signature: value.signature,
        }
    }
}
