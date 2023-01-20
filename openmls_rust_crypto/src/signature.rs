use openmls_memory_keystore::{MemoryKeyStore, MemoryKeyStoreError};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    key_store::{FromKeyStoreValue, OpenMlsKeyStore, ToKeyStoreValue},
    signatures::{ByteSigner, ByteVerifier, Signer, Verifier},
    types::{self, CryptoError, SignatureScheme},
};

use p256::{
    ecdsa::{signature::Verifier as P256Verifier, Signature, SigningKey, VerifyingKey},
    EncodedPoint,
};

// See https://github.com/rust-analyzer/rust-analyzer/issues/7243
// for the rust-analyzer issue with the following line.
use ed25519_dalek::Signer as DalekSigner;
use tls_codec::{Deserialize, Serialize, TlsDeserialize, TlsSerialize, TlsSize};

use crate::RustCrypto;

impl Signer<Vec<u8>> for Signatures {
    type Error = CryptoError;

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match self.signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = SigningKey::from_bytes(&self.private)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature = k.sign(payload);
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::Keypair::from_bytes(&self.private)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature = k.sign(payload);
                Ok(signature.to_bytes().into())
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }
}
impl ByteSigner for Signatures {}

impl Verifier<[u8]> for Signatures {
    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), types::Error> {
        match self.signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = VerifyingKey::from_encoded_point(
                    &EncodedPoint::from_bytes(&self.public)
                        .map_err(|_| types::Error::InvalidSignature)?,
                )
                .map_err(|_| types::Error::InvalidSignature)?;
                k.verify(
                    payload,
                    &Signature::from_der(signature).map_err(|_| types::Error::InvalidSignature)?,
                )
                .map_err(|_| types::Error::InvalidSignature)
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::PublicKey::from_bytes(&self.public)
                    .map_err(|_| types::Error::InvalidSignature)?;
                if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
                    return Err(types::Error::InvalidSignature);
                }
                let mut sig = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
                sig.clone_from_slice(signature);
                k.verify_strict(payload, &ed25519_dalek::Signature::from(sig))
                    .map_err(|_| types::Error::InvalidSignature)
            }
            _ => Err(types::Error::CryptoError(
                CryptoError::UnsupportedSignatureScheme,
            )),
        }
    }
}
impl ByteVerifier for Signatures {}

#[derive(TlsSerialize, TlsSize, TlsDeserialize)]
pub struct Signatures {
    private: Vec<u8>,
    public: Vec<u8>,
    signature_scheme: SignatureScheme,
}

/// Compute the ID for a [`Signature`] in the key store.
fn id(public_key: &[u8], signature_scheme: SignatureScheme) -> Vec<u8> {
    const LABEL: &[u8; 22] = b"RustCryptoSignatureKey";
    let mut id = public_key.to_vec();
    id.extend_from_slice(LABEL);
    let signature_scheme = (signature_scheme as u16).to_be_bytes();
    id.extend_from_slice(&signature_scheme);
    id
}

impl ToKeyStoreValue for Signatures {
    type Error = tls_codec::Error;

    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        self.tls_serialize_detached()
    }
}

impl FromKeyStoreValue for Signatures {
    type Error = tls_codec::Error;

    fn from_key_store_value(mut ksv: &[u8]) -> Result<Self, Self::Error> {
        Self::tls_deserialize(&mut ksv)
    }
}

impl Signatures {
    /// Generates a fresh signature keypair using the [`SignatureScheme`].
    pub fn new(
        signature_scheme: SignatureScheme,
        backend: &RustCrypto,
    ) -> Result<Self, CryptoError> {
        let (private, public) = backend
            .signature_key_gen(signature_scheme)
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        Ok(Self {
            private,
            public,
            signature_scheme,
        })
    }

    fn id(&self) -> Vec<u8> {
        id(&self.public, self.signature_scheme)
    }

    /// Store this signature key pair in the key store.
    pub fn store(&self, key_store: &MemoryKeyStore) -> Result<(), MemoryKeyStoreError> {
        key_store.store(&self.id(), self)
    }

    /// Read a signature key pair from the key store.
    pub fn read(
        key_store: &MemoryKeyStore,
        public_key: &[u8],
        signature_scheme: SignatureScheme,
    ) -> Option<Self> {
        key_store.read(&id(public_key, signature_scheme))
    }

    /// Get the public key as byte slice.
    pub fn public(&self) -> &[u8] {
        self.public.as_ref()
    }

    /// Get the [`SignatureScheme`] of this signature key.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}
