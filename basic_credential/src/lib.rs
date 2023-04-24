//! # Basic Credential
//!
//! An implementation of the basic credential from the MLS spec.
//!
//! For now this credential uses only RustCrypto.

use std::fmt::Debug;

use openmls_traits::{
    credential::OpenMlsCredential,
    key_store::{MlsEntity, MlsEntityId, OpenMlsKeyStore},
    signatures::Signer,
    types::{
        credential::{BasicCredential, Credential, MlsCredentialType},
        CryptoError, Error, SignatureScheme,
    },
};

use p256::ecdsa::SigningKey;

// See https://github.com/rust-analyzer/rust-analyzer/issues/7243
// for the rust-analyzer issue with the following line.
use ed25519_dalek::Signer as DalekSigner;
use rand::rngs::OsRng;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// A credential for verification.
#[derive(TlsSerialize, TlsSize, TlsDeserialize, serde::Serialize, serde::Deserialize, Debug)]
#[cfg_attr(feature = "cloneable", derive(Clone))]
pub struct VerificationCredential {
    public_key: Vec<u8>,
    signature_scheme: SignatureScheme,
    identity: Vec<u8>,
}

impl VerificationCredential {
    /// Generate a new credential for verification.
    pub fn new(public_key: Vec<u8>, signature_scheme: SignatureScheme, identity: Vec<u8>) -> Self {
        Self {
            public_key,
            signature_scheme,
            identity,
        }
    }
}

/// A signature key pair for the basic credential.
///
/// This can be used as keys to implement the MLS basic credential. It is a simple
/// private and public key pair with corresponding signature scheme.
#[derive(TlsSerialize, TlsSize, TlsDeserialize, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "cloneable", derive(Clone))]
pub struct SignatureKeyPair {
    private: Vec<u8>,
    public_credential: VerificationCredential,
}

impl Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("private", &"***".to_string())
            .field("public_credential", &self.public_credential)
            .finish()
    }
}

impl Signer for SignatureKeyPair {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        match self.public_credential.signature_scheme {
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
        self.public_credential.signature_scheme
    }
}

impl OpenMlsCredential for SignatureKeyPair {
    fn identity(&self) -> &[u8] {
        &self.public_credential.identity
    }

    fn public_key(&self) -> &[u8] {
        &self.public_credential.public_key
    }

    fn credential(&self) -> Credential {
        let credential = MlsCredentialType::Basic(BasicCredential::new(
            self.public_credential.identity.clone().into(),
        ));
        Credential::new(credential)
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
    pub fn new(signature_scheme: SignatureScheme, identity: Vec<u8>) -> Result<Self, CryptoError> {
        let (private, public_key) = match signature_scheme {
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
            public_credential: VerificationCredential {
                public_key,
                signature_scheme,
                identity,
            },
        })
    }

    /// Create a new signature key pair from the raw keys.
    pub fn from_raw(
        signature_scheme: SignatureScheme,
        private: Vec<u8>,
        public_key: Vec<u8>,
        identity: Vec<u8>,
    ) -> Self {
        Self {
            private,
            public_credential: VerificationCredential {
                public_key,
                signature_scheme,
                identity,
            },
        }
    }

    fn id(&self) -> Vec<u8> {
        id(
            &self.public_credential.public_key,
            self.public_credential.signature_scheme,
        )
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
        self.public_credential.public_key.as_ref()
    }

    /// Get the public key as byte vector.
    pub fn to_public_vec(&self) -> Vec<u8> {
        self.public_credential.public_key.clone()
    }

    /// Get the [`SignatureScheme`] of this signature key.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.public_credential.signature_scheme
    }

    /// Verification credential that implements [`OpenMlsCredential`].
    pub fn public_credential(&self) -> &VerificationCredential {
        &self.public_credential
    }
}

impl OpenMlsCredential for VerificationCredential {
    fn identity(&self) -> &[u8] {
        &self.identity
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn credential(&self) -> Credential {
        let credential =
            MlsCredentialType::Basic(BasicCredential::new(self.identity.clone().into()));
        Credential::new(credential)
    }
}

#[cfg(feature = "test-utils")]
impl SignatureKeyPair {
    /// Get the private key as byte slice.
    pub fn private(&self) -> &[u8] {
        &self.private
    }

    /// Replace the public key with `public_key`.
    pub fn set_public_key(&mut self, public_key: Vec<u8>) {
        self.public_credential.public_key = public_key
    }

    /// Get the same keys with a new identity
    pub fn new_with_new_identity(&self, id: &str) -> Self {
        Self {
            private: self.private.clone(),
            public_credential: VerificationCredential {
                public_key: self.public_credential.public_key.clone(),
                signature_scheme: self.public_credential.signature_scheme,
                identity: id.as_bytes().to_vec(),
            },
        }
    }
}
