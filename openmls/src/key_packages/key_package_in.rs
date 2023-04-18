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
    leaf_node: LeafNodeIn,
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
    /// * verify that the signature on the leaf node is valid
    /// * verify that all extensions are supported by the leaf node
    /// * make sure that the lifetime is valid Returns a [`KeyPackage`] after
    /// having verified the signature or a [`KeyPackageVerifyError`] otherwise.
    pub fn into_validated(
        self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<KeyPackage, KeyPackageVerifyError> {
        // Verify the signature of the KeyPackage
        let signature_key = OpenMlsSignaturePublicKey::from_signature_key(
            self.payload.leaf_node.signature_key().clone(),
            self.payload.ciphersuite.signature_algorithm(),
        );
        self.verify_no_out(crypto, &signature_key)
            .map_err(|_| KeyPackageVerifyError::InvalidSignature)?;

        // We need to verify the LeafNode inside the KeyPackage
        let leaf_node = self.payload.leaf_node.into_verifiable_leaf_node();

        let leaf_node = match leaf_node {
            VerifiableLeafNode::KeyPackage(leaf_node) => {
                let pk = &leaf_node
                    .signature_key()
                    .clone()
                    .into_signature_public_key_enriched(ciphersuite.signature_algorithm());

                leaf_node
                    .verify(crypto, pk)
                    .map_err(|_| KeyPackageVerifyError::InvalidLeafNodeSignature)?
            }
            _ => return Err(KeyPackageVerifyError::InvalidLeafNodeSourceType),
        };

        let key_package = KeyPackage {
            payload: KeyPackageTBS {
                protocol_version: self.payload.protocol_version,
                ciphersuite: self.payload.ciphersuite,
                init_key: self.payload.init_key,
                leaf_node,
                extensions: self.payload.extensions,
            },
            signature: self.signature,
        };

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
}

mod private_mod {
    #[derive(Default)]
    pub struct Seal;
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

#[cfg(any(feature = "test-utils", test))]
impl From<KeyPackageTbsIn> for KeyPackageTBS {
    fn from(value: KeyPackageTbsIn) -> Self {
        KeyPackageTBS {
            protocol_version: value.protocol_version,
            ciphersuite: value.ciphersuite,
            init_key: value.init_key,
            leaf_node: value.leaf_node.into(),
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
impl From<KeyPackageIn> for KeyPackage {
    fn from(value: KeyPackageIn) -> Self {
        Self {
            payload: value.payload.into(),
            signature: value.signature,
        }
    }
}
