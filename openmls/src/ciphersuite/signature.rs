//! Signatures.
//!
//! This module contains structs for creating signature keys, issuing signatures and verifying them.

use super::{LABEL_PREFIX, *};

/// Signature.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct Signature {
    value: VLBytes,
}

impl From<Vec<u8>> for Signature {
    fn from(value: Vec<u8>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

/// Labeled signature content.
///
/// ```text
/// struct {
///     opaque label<V> = "MLS 1.0 " + Label;
///     opaque content<V> = Content;
/// } SignContent;
/// ```
#[derive(Debug, Clone, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub struct SignContent {
    label: VLBytes,
    content: VLBytes,
}

impl SignContent {
    /// Create a new [`SignContent`] from a string label and the content bytes.
    pub fn new(label: &str, content: VLBytes) -> Self {
        let label_string = LABEL_PREFIX.to_owned() + label;
        let label = label_string.as_bytes().into();
        Self { label, content }
    }
}

/// A public signature key.
#[derive(
    Eq,
    PartialEq,
    Hash,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct SignaturePublicKey {
    pub(in crate::ciphersuite) value: VLBytes,
}

impl From<Vec<u8>> for SignaturePublicKey {
    fn from(value: Vec<u8>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl From<&[u8]> for SignaturePublicKey {
    fn from(value: &[u8]) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl SignaturePublicKey {
    /// Convert the "raw" signature into an enriched form, [OpenMlsSignaturePublicKey], that
    /// already contains the signature scheme.
    pub fn into_signature_public_key_enriched(
        self,
        signature_scheme: SignatureScheme,
    ) -> OpenMlsSignaturePublicKey {
        OpenMlsSignaturePublicKey {
            signature_scheme,
            value: self.value,
        }
    }

    /// Returns the bytes of the signature public key.
    pub fn as_slice(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl From<OpenMlsSignaturePublicKey> for SignaturePublicKey {
    fn from(signature_public_key_enriched: OpenMlsSignaturePublicKey) -> Self {
        SignaturePublicKey {
            value: signature_public_key_enriched.value,
        }
    }
}

/// A public signature key.
#[derive(Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize)]
pub struct OpenMlsSignaturePublicKey {
    signature_scheme: SignatureScheme,
    pub(in crate::ciphersuite) value: VLBytes,
}

#[cfg(any(test, feature = "test-utils"))]
impl Signature {
    #[cfg(test)]
    pub(crate) fn modify(&mut self, value: &[u8]) {
        self.value = value.to_vec().into();
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl Signature {
    /// Get this signature as slice.
    pub(super) fn value(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl<T> SignedStruct<T> for Signature {
    fn from_payload(_payload: T, signature: Signature) -> Self {
        signature
    }
}

impl OpenMlsSignaturePublicKey {
    /// Create a new signature public key from raw key bytes.
    pub fn new(value: VLBytes, signature_scheme: SignatureScheme) -> Result<Self, CryptoError> {
        Ok(Self {
            value,
            signature_scheme,
        })
    }

    /// Create a new signature public key from raw key.
    pub fn from_signature_key(key: SignaturePublicKey, signature_scheme: SignatureScheme) -> Self {
        Self {
            value: key.value,
            signature_scheme,
        }
    }

    /// Get the signature scheme of the public key.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    /// Returns the bytes of the signature public key.
    pub fn as_slice(&self) -> &[u8] {
        self.value.as_ref()
    }
}
