//! Signatures.
//!
//! This module contains structs for creating signature keys, issuing signatures and verifying them.

use super::*;

/// Signature.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct Signature {
    value: TlsByteVecU16,
}

/// A private signature key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Eq))]
pub struct SignaturePrivateKey {
    signature_scheme: SignatureScheme,
    value: Vec<u8>,
}

/// A public signature key.
#[derive(Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePublicKey {
    signature_scheme: SignatureScheme,
    pub(in crate::ciphersuite) value: Vec<u8>,
}

/// A signature keypair.
#[derive(Debug, Clone)]
pub struct SignatureKeypair {
    private_key: SignaturePrivateKey,
    public_key: SignaturePublicKey,
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
            public_key: SignaturePublicKey {
                signature_scheme,
                value: public_key,
            },
        }
    }

    /// Get the private and public key objects
    pub fn into_tuple(self) -> (SignaturePrivateKey, SignaturePublicKey) {
        (self.private_key, self.public_key)
    }
}

#[cfg(test)]
impl SignatureKeypair {
    /// Sign the `payload` byte slice with this signature key.
    /// Returns a `Result` with a `Signature` or a `CryptoError`.
    pub fn sign(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        payload: &[u8],
    ) -> Result<Signature, CryptoError> {
        self.private_key.sign(backend, payload)
    }

    /// Verify a `Signature` on the `payload` byte slice with the key pair's
    /// public key.
    pub fn verify(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        signature: &Signature,
        payload: &[u8],
    ) -> Result<(), CryptoError> {
        self.public_key.verify(backend, signature, payload)
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
            public_key: SignaturePublicKey {
                value: pk,
                signature_scheme,
            },
        })
    }

    /// Create a [`SignatureKeypair`] from a public and a private key.
    #[cfg(any(feature = "test-utils", test))]
    pub fn from_parts(public_key: SignaturePublicKey, private_key: SignaturePrivateKey) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}

impl SignaturePublicKey {
    /// Create a new signature public key from raw key bytes.
    pub fn new(bytes: Vec<u8>, signature_scheme: SignatureScheme) -> Result<Self, CryptoError> {
        Ok(Self {
            value: bytes,
            signature_scheme,
        })
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
                &self.value,
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
        &self.value
    }
}

impl SignaturePrivateKey {
    /// Sign the `payload` byte slice with this signature key.
    /// Returns a `Result` with a `Signature` or a `SignatureError`.
    pub fn sign(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        payload: &[u8],
    ) -> Result<Signature, CryptoError> {
        match backend
            .crypto()
            .sign(self.signature_scheme, payload, &self.value)
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
