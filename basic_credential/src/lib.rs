//! # Basic Credential
//!
//! An implementation of the basic credential from the MLS spec.
//!
//! For now this credential uses only RustCrypto.

use std::fmt::Debug;

use openmls_traits::{
    key_store::{MlsEntity, MlsEntityId, OpenMlsKeyStore},
    signatures::Signer,
    types::{CryptoError, Error, SignatureScheme},
};

use p256::ecdsa::SigningKey;

// See https://github.com/rust-analyzer/rust-analyzer/issues/7243
// for the rust-analyzer issue with the following line.
use ed25519_dalek::Signer as DalekSigner;
use rand::rngs::OsRng;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// A signature key pair for the basic credential.
///
/// This can be used as keys to implement the MLS basic credential. It is a simple
/// private and public key pair with corresponding signature scheme.
#[derive(TlsSerialize, TlsSize, TlsDeserialize, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "clonable", derive(Clone))]
pub struct SignatureKeyPair {
    private: Vec<u8>,
    public: Vec<u8>,
    signature_scheme: SignatureScheme,
}

impl Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("private", &"***".to_string())
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

    fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
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

impl MlsEntity for SignatureKeyPair {
    const ID: MlsEntityId = MlsEntityId::SignatureKeyPair;
}

impl SignatureKeyPair {
    /// Generates a fresh signature keypair using the [`SignatureScheme`].
    pub fn new(signature_scheme: SignatureScheme) -> Result<Self, CryptoError> {
        let (private, public) = match signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = SigningKey::random(&mut OsRng);
                let pk = k.verifying_key().to_encoded_point(false).as_bytes().into();
                (k.to_bytes().as_slice().into(), pk)
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::Keypair::generate(&mut rand_07::rngs::OsRng).to_bytes();
                let pk = k[ed25519_dalek::SECRET_KEY_LENGTH..].to_vec();
                // full key here because we need it to sign...
                let sk_pk = k.into();
                (sk_pk, pk)
            }
            _ => return Err(CryptoError::UnsupportedSignatureScheme),
        };

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
