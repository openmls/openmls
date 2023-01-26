//! # Basic Credential
//!
//! An implementation of the basic credential from the MLS spec.
//!
//! For now this credential uses only RustCrypto.

use std::fmt::Debug;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    key_store::{FromKeyStoreValue, OpenMlsKeyStore, ToKeyStoreValue},
    signatures::Signer,
    types::{CryptoError, Error, SignatureScheme},
};

use p256::ecdsa::SigningKey;

// See https://github.com/rust-analyzer/rust-analyzer/issues/7243
// for the rust-analyzer issue with the following line.
use ed25519_dalek::Signer as DalekSigner;
use tls_codec::{Deserialize, Serialize, TlsDeserialize, TlsSerialize, TlsSize};

/// A signature key pair for the basic credential.
///
/// This can be used as keys to implement the MLS basic credential. It is a simple
/// private and public key pair with corresponding signature scheme.
#[derive(TlsSerialize, TlsSize, TlsDeserialize)]
#[cfg_attr(feature = "clonable", derive(Clone))]
pub struct SignatureKeyPair {
    private: Vec<u8>,
    public: Vec<u8>,
    signature_scheme: SignatureScheme,
}

impl Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("private", &format!("***"))
            .field("public", &self.public)
            .field("signature_scheme", &self.signature_scheme)
            .finish()
    }
}

impl Signer for SignatureKeyPair {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        match self.signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = SigningKey::from_bytes(&self.private).map_err(|_| Error::SigningError)?;
                let signature = k.sign(payload);
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::Keypair::from_bytes(&self.private)
                    .map_err(|_| Error::SigningError)?;
                let signature = k.sign(payload);
                Ok(signature.to_bytes().into())
            }
            _ => Err(Error::SigningError),
        }
    }
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

impl ToKeyStoreValue for SignatureKeyPair {
    type Error = tls_codec::Error;

    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        self.tls_serialize_detached()
    }
}

impl FromKeyStoreValue for SignatureKeyPair {
    type Error = tls_codec::Error;

    fn from_key_store_value(mut ksv: &[u8]) -> Result<Self, Self::Error> {
        Self::tls_deserialize(&mut ksv)
    }
}

/// Note that functions in here use a key store or a crypto provider.
/// They are not used within OpenMLS.
/// The only relevant functions for MLS are in the [`Signer`] trait implementaiton.
impl SignatureKeyPair {
    /// Generates a fresh signature keypair using the [`SignatureScheme`].
    pub fn new(
        signature_scheme: SignatureScheme,
        backend: &impl OpenMlsCrypto,
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
    pub fn store<T>(&self, key_store: &T) -> Result<(), <T as OpenMlsKeyStore>::Error>
    where
        T: OpenMlsKeyStore,
    {
        key_store.store(&self.id(), self)
    }

    /// Read a signature key pair from the key store.
    pub fn read(
        key_store: &impl OpenMlsKeyStore,
        public_key: &[u8],
        signature_scheme: SignatureScheme,
    ) -> Option<Self> {
        key_store.read(&id(public_key, signature_scheme))
    }

    /// Get the public key as byte slice.
    pub fn public(&self) -> &[u8] {
        self.public.as_ref()
    }

    /// Get the public key as byte vector.
    pub fn to_public_vec(&self) -> Vec<u8> {
        self.public.clone()
    }

    /// Get the [`SignatureScheme`] of this signature key.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}
