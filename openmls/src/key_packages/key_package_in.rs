//! Incoming KeyPackages. This modules contains deserialization and validation
//! of KeyPackages.

use crate::{
    ciphersuite::{signable::*, *},
    credentials::*,
    extensions::Extensions,
    treesync::LeafNode,
    versions::ProtocolVersion,
};
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use serde::{Deserialize, Serialize};
use tls_codec::{Serialize as TlsSerializeTrait, TlsDeserialize, TlsSerialize, TlsSize};

use super::{
    errors::KeyPackageVerifyError, KeyPackage, KeyPackageTBS, SIGNATURE_KEY_PACKAGE_LABEL,
};

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
    Debug, Clone, PartialEq, TlsSize, TlsSerialize, TlsDeserialize, Serialize, Deserialize,
)]
struct KeyPackageTbsIn {
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    init_key: HpkePublicKey,
    leaf_node: LeafNode,
    extensions: Extensions,
}

/// The key package struct.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
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
    /// * verify that all extensions are supported by the leaf node
    /// * make sure that the lifetime is valid Returns a [`KeyPackage`] after
    /// having verified the signature or a [`KeyPackageVerifyError`] otherwise.
    pub fn into_validated(
        self,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<KeyPackage, KeyPackageVerifyError> {
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

        let signature_key = OpenMlsSignaturePublicKey::from_signature_key(
            self.payload.leaf_node.signature_key().clone(),
            self.payload.ciphersuite.signature_algorithm(),
        );
        let key_package: KeyPackage = self
            .verify(crypto, &signature_key)
            .map_err(|_| KeyPackageVerifyError::InvalidSignature)?;
        Ok(key_package)
    }
}

mod private_mod {
    #[derive(Default)]
    pub struct Seal;
}

impl VerifiedStruct<KeyPackageIn> for KeyPackage {
    type SealingType = private_mod::Seal;

    fn from_verifiable(verifiable: KeyPackageIn, _seal: Self::SealingType) -> Self {
        Self {
            payload: verifiable.payload.into(),
            signature: verifiable.signature,
        }
    }
}

impl Verifiable for KeyPackageIn {
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

impl From<KeyPackageTbsIn> for KeyPackageTBS {
    fn from(value: KeyPackageTbsIn) -> Self {
        KeyPackageTBS {
            protocol_version: value.protocol_version,
            ciphersuite: value.ciphersuite,
            init_key: value.init_key,
            leaf_node: value.leaf_node,
            extensions: value.extensions,
        }
    }
}

impl From<KeyPackageTBS> for KeyPackageTbsIn {
    fn from(value: KeyPackageTBS) -> Self {
        Self {
            protocol_version: value.protocol_version,
            ciphersuite: value.ciphersuite,
            init_key: value.init_key,
            leaf_node: value.leaf_node,
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
impl From<KeyPackageIn> for KeyPackage {
    fn from(value: KeyPackageIn) -> Self {
        Self {
            payload: value.payload.into(),
            signature: value.signature,
        }
    }
}
