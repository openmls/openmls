//! Signatures.
//!
//! This module contains structs for creating signature keys, issuing signatures and verifying them.

use tls_codec::Serialize;

use super::*;

/// Signature.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
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
#[derive(Debug, Clone, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct SignContent {
    label: VLBytes,
    content: VLBytes,
}

const SIGN_LABEL_PREFIX: &str = "MLS 1.0";

impl SignContent {
    /// Create a new [`SignContent`] from a string label and the content bytes.
    pub fn new(label: &str, content: VLBytes) -> Self {
        let label_string = SIGN_LABEL_PREFIX.to_owned() + label;
        let label = label_string.as_bytes().into();
        Self { label, content }
    }
}

impl From<(&str, &[u8])> for SignContent {
    fn from((label, content): (&str, &[u8])) -> Self {
        let label_string = SIGN_LABEL_PREFIX.to_owned() + label;
        let label = label_string.as_bytes().into();
        Self {
            label,
            content: content.into(),
        }
    }
}

/// A private signature key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Eq))]
pub struct SignaturePrivateKey {
    signature_scheme: SignatureScheme,
    value: Vec<u8>,
}

/// A public signature key.
#[derive(
    Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
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

/// A signature keypair.
#[derive(Debug, Clone)]
pub struct SignatureKeypair {
    private_key: SignaturePrivateKey,
    public_key: OpenMlsSignaturePublicKey,
}

#[cfg(test)]
impl Signature {
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

impl SignatureKeypair {
    #[cfg(feature = "crypto-subtle")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto-subtle")))]
    /// Construct a new [`SignatureKeypair`] from bytes of a private and a public key.
    ///
    /// **NO CHECKS ARE PERFORMED ON THE KEYS. USE AT YOUR OWN RISK.**
    pub fn from_bytes(
        signature_scheme: SignatureScheme,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            private_key: SignaturePrivateKey {
                signature_scheme,
                value: private_key,
            },
            public_key: OpenMlsSignaturePublicKey {
                signature_scheme,
                value: public_key,
            },
        }
    }

    /// Get the private and public key objects
    pub fn into_tuple(self) -> (SignaturePrivateKey, OpenMlsSignaturePublicKey) {
        (self.private_key, self.public_key)
    }

    /// Returns a reference to the signature private key.
    pub fn private_key(&self) -> &SignaturePrivateKey {
        &self.private_key
    }

    /// Returns a reference to the signature public key.
    pub fn public_key(&self) -> &OpenMlsSignaturePublicKey {
        &self.public_key
    }
}

#[cfg(test)]
impl SignatureKeypair {
    /// Sign the [`SignContent`] with this signature key.
    /// Returns a `Result` with a [`Signature`] or a [`CryptoError`].
    pub fn sign_with_label(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        sign_content: &SignContent,
    ) -> Result<Signature, CryptoError> {
        self.private_key.sign_with_label(backend, sign_content)
    }

    /// Verify a [`Signature`] on the [`SignContent`] with the key pair's
    /// public key.
    pub fn verify_with_label(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        signature: &Signature,
        sign_content: &SignContent,
    ) -> Result<(), CryptoError> {
        self.public_key
            .verify_with_label(backend, signature, sign_content)
    }
}

impl SignatureKeypair {
    /// Generates a fresh signature keypair using a specific [`SignatureScheme`].
    pub fn new(
        signature_scheme: SignatureScheme,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<SignatureKeypair, CryptoError> {
        let (sk, pk) = backend
            .crypto()
            .signature_key_gen(signature_scheme)
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        Ok(SignatureKeypair {
            private_key: SignaturePrivateKey {
                value: sk,
                signature_scheme,
            },
            public_key: OpenMlsSignaturePublicKey {
                value: pk.into(),
                signature_scheme,
            },
        })
    }

    /// Create a [`SignatureKeypair`] from a public and a private key.
    #[cfg(any(feature = "test-utils", test))]
    pub fn from_parts(
        public_key: OpenMlsSignaturePublicKey,
        private_key: SignaturePrivateKey,
    ) -> Self {
        Self {
            private_key,
            public_key,
        }
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

    /// Verify a [`Signature`] on the [`SignContent`] with this public key
    /// public key.
    pub fn verify_with_label(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        signature: &Signature,
        sign_content: &SignContent,
    ) -> Result<(), CryptoError> {
        let payload = match sign_content.tls_serialize_detached() {
            Ok(p) => p,
            Err(e) => {
                log::error!("Serializing SignContent failed, {:?}", e);
                return Err(CryptoError::TlsSerializationError);
            }
        };
        backend
            .crypto()
            .verify_signature(
                self.signature_scheme,
                &payload,
                self.value.as_ref(),
                signature.value.as_slice(),
            )
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Verify a `Signature` on the `payload` byte slice with the keypair's
    /// public key.
    pub fn verify(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        signature: &Signature,
        payload: &[u8],
    ) -> Result<(), CryptoError> {
        backend
            .crypto()
            .verify_signature(
                self.signature_scheme,
                payload,
                self.value.as_ref(),
                signature.value.as_slice(),
            )
            .map_err(|_| CryptoError::InvalidSignature)
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

impl SignaturePrivateKey {
    /// Sign the serialization of [`SignContent`] with this signature key.
    /// Returns a `Result` with a [`Signature`] or an Error.
    pub fn sign_with_label(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        sign_content: &SignContent,
    ) -> Result<Signature, CryptoError> {
        let payload = match sign_content.tls_serialize_detached() {
            Ok(p) => p,
            Err(e) => {
                log::error!("Serializing SignContent failed, {:?}", e);
                return Err(CryptoError::TlsSerializationError);
            }
        };
        match backend
            .crypto()
            .sign(self.signature_scheme, &payload, &self.value)
        {
            Ok(s) => Ok(Signature { value: s.into() }),
            Err(_) => Err(CryptoError::CryptoLibraryError),
        }
    }

    /// Get the signature scheme of the private key
    #[cfg(test)]
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    /// Returns the raw private key bytes as slice.
    #[cfg(feature = "crypto-subtle")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto-subtle")))]
    pub fn as_slice(&self) -> &[u8] {
        &self.value
    }
}
