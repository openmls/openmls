use super::*;

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct Signature {
    value: TlsByteVecU16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SignaturePrivateKey {
    signature_scheme: SignatureScheme,
    value: Vec<u8>,
}

#[derive(Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePublicKey {
    signature_scheme: SignatureScheme,
    pub(in crate::ciphersuite) value: Vec<u8>,
}

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
    /// Construct new [SignatureKeypair] from a private and a public key
    pub fn from_keys(private_key: SignaturePrivateKey, public_key: SignaturePublicKey) -> Self {
        Self {
            private_key,
            public_key,
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
    pub(crate) fn new(
        signature_scheme: SignatureScheme,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<SignatureKeypair, CryptoError> {
        let (sk, pk) = backend
            .crypto()
            .signature_key_gen(signature_scheme)
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        Ok(SignatureKeypair {
            private_key: SignaturePrivateKey {
                value: sk.to_vec(),
                signature_scheme,
            },
            public_key: SignaturePublicKey {
                value: pk.to_vec(),
                signature_scheme,
            },
        })
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

    /// Verify a `Signature` on the `payload` byte slice with the key pair's
    /// public key.
    pub fn verify(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        signature: &Signature,
        payload: &[u8],
    ) -> Result<(), CryptoError> {
        backend
            .crypto()
            .supports(self.signature_scheme)
            .map_err(|_| CryptoError::UnsupportedSignatureScheme)?;
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
}
