//! # Basic Credential
//!
//! An implementation of the basic credential from the MLS spec.
//!
//! For now this credential uses only RustCrypto.

use std::fmt::Debug;

use openmls_traits::{
    signatures::{Signer, SignerError},
    storage::{self, StorageProvider, CURRENT_VERSION},
    types::{CryptoError, SignatureScheme},
};

use p256::ecdsa::{signature::Signer as P256Signer, Signature, SigningKey};

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tls_codec::{SecretVLBytes, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};
use zeroize::Zeroize;

/// A signature key pair for the basic credential.
///
/// This can be used as keys to implement the MLS basic credential. It is a simple
/// private and public key pair with corresponding signature scheme.
#[derive(
    TlsSerialize, TlsSize, TlsDeserialize, TlsDeserializeBytes, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(feature = "clonable", derive(Clone))]
pub struct SignatureKeyPair {
    #[serde(with = "secret_bytes_as_vec")]
    private: SecretVLBytes,
    public: Vec<u8>,
    signature_scheme: SignatureScheme,
}

/// Serde helper that serializes [`SecretVLBytes`] as a bare `Vec<u8>`.
///
/// `SecretVLBytes` wraps `VLBytes { vec: Vec<u8> }`, which serde serializes as
/// `{"vec": [...]}` rather than `[...]`. This module preserves the original
/// `Vec<u8>` wire format for backward compatibility with stored key pairs.
mod secret_bytes_as_vec {
    use super::*;

    pub fn serialize<S: serde::Serializer>(value: &SecretVLBytes, s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(value.as_slice(), s)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<SecretVLBytes, D::Error> {
        let mut bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        let secret: SecretVLBytes = bytes.as_slice().into();
        bytes.zeroize();
        Ok(secret)
    }
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
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        match self.signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = SigningKey::from_bytes(self.private.as_slice().into())
                    .map_err(|_| SignerError::SigningError)?;
                let signature: Signature = k.sign(payload);
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::SigningKey::try_from(self.private.as_slice())
                    .map_err(|_| SignerError::SigningError)?;
                let signature = k.sign(payload);
                Ok(signature.to_bytes().into())
            }
            _ => Err(SignerError::SigningError),
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

impl SignatureKeyPair {
    /// Generates a fresh signature keypair using the [`SignatureScheme`].
    pub fn new(signature_scheme: SignatureScheme) -> Result<Self, CryptoError> {
        let (private, public) = match signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = SigningKey::random(&mut OsRng);
                let pk = k.verifying_key().to_encoded_point(false).as_bytes().into();
                #[allow(deprecated)]
                let mut key_bytes = k.to_bytes();
                let private: SecretVLBytes = key_bytes.as_slice().into();
                key_bytes.zeroize();
                (private, pk)
            }
            SignatureScheme::ED25519 => {
                let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
                let pk = sk.verifying_key().to_bytes().into();
                // Use as_bytes() to avoid an unzeroed stack copy from to_bytes().
                // sk itself implements ZeroizeOnDrop.
                (sk.as_bytes().as_slice().into(), pk)
            }
            _ => return Err(CryptoError::UnsupportedSignatureScheme),
        };

        Ok(Self {
            private,
            public,
            signature_scheme,
        })
    }

    /// Create a new signature key pair from the raw keys.
    pub fn from_raw(signature_scheme: SignatureScheme, private: Vec<u8>, public: Vec<u8>) -> Self {
        Self {
            private: private.into(),
            public,
            signature_scheme,
        }
    }

    pub fn id(&self) -> StorageId {
        StorageId {
            value: id(&self.public, self.signature_scheme),
        }
    }

    /// Store this signature key pair in the key store.
    pub fn store<T>(&self, store: &T) -> Result<(), T::Error>
    where
        T: StorageProvider<CURRENT_VERSION>,
    {
        store.write_signature_key_pair(&self.id(), self)
    }

    /// Read a signature key pair from the key store.
    pub fn read(
        store: &impl StorageProvider<CURRENT_VERSION>,
        public_key: &[u8],
        signature_scheme: SignatureScheme,
    ) -> Option<Self> {
        store
            .signature_key_pair(&StorageId {
                value: id(public_key, signature_scheme),
            })
            .ok()
            .flatten()
    }

    /// Delete a signature key pair from the key store.
    pub fn delete<T: StorageProvider<CURRENT_VERSION>>(
        store: &T,
        public_key: &[u8],
        signature_scheme: SignatureScheme,
    ) -> Result<(), T::Error> {
        let id = StorageId {
            value: id(public_key, signature_scheme),
        };
        store.delete_signature_key_pair(&id)
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

    #[cfg(feature = "test-utils")]
    pub fn private(&self) -> &[u8] {
        self.private.as_slice()
    }
}

// Storage

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageId {
    value: Vec<u8>,
}

impl From<Vec<u8>> for StorageId {
    fn from(vec: Vec<u8>) -> Self {
        StorageId { value: vec }
    }
}

// Implement key traits for the storage id
impl storage::Key<CURRENT_VERSION> for StorageId {}
impl storage::traits::SignaturePublicKey<CURRENT_VERSION> for StorageId {}

// Implement entity trait for the signature key pair
impl storage::Entity<CURRENT_VERSION> for SignatureKeyPair {}
impl storage::traits::SignatureKeyPair<CURRENT_VERSION> for SignatureKeyPair {}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_codec::{DeserializeBytes as TlsDeserializeBytesTrait, Serialize as TlsSerializeTrait};

    #[test]
    fn test_serde_roundtrip() {
        let kp = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let json = serde_json::to_string(&kp).unwrap();

        let kp2: SignatureKeyPair = serde_json::from_str(&json).unwrap();
        assert_eq!(kp.private.as_slice(), kp2.private.as_slice());
        assert_eq!(kp.public(), kp2.public());
        assert_eq!(kp.signature_scheme(), kp2.signature_scheme());
    }

    #[test]
    fn test_serde_format_backwards_compat() {
        // Old Vec<u8>-based serialization format must still deserialize
        let old_json = r#"{"private":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],"public":[1,2,3],"signature_scheme":"ED25519"}"#;
        let kp = serde_json::from_str::<SignatureKeyPair>(old_json)
            .expect("must deserialize old format");
        assert_eq!(
            kp.private.as_slice(),
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32
            ]
        );
        assert_eq!(kp.public(), &[1, 2, 3]);
        assert_eq!(kp.signature_scheme(), SignatureScheme::ED25519);

        // New format must serialize as bare array (not {"vec": [...]})
        let json = serde_json::to_string(&kp).unwrap();
        assert!(
            !json.contains(r#""vec""#),
            "private field must serialize as bare array, got: {json}"
        );
    }

    #[test]
    fn test_tls_roundtrip() {
        let kp = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let tls_bytes = kp.tls_serialize_detached().unwrap();

        let (kp2, rest) = SignatureKeyPair::tls_deserialize_bytes(&tls_bytes).unwrap();
        assert!(rest.is_empty());
        assert_eq!(kp.private.as_slice(), kp2.private.as_slice());
        assert_eq!(kp.public(), kp2.public());
        assert_eq!(kp.signature_scheme(), kp2.signature_scheme());
    }

    /// Copy of the pre-zeroize SignatureKeyPair for backward compatibility testing.
    #[derive(TlsSerialize, TlsSize, serde::Serialize)]
    struct OldSignatureKeyPair {
        private: Vec<u8>,
        public: Vec<u8>,
        signature_scheme: SignatureScheme,
    }

    #[test]
    fn test_serde_backwards_compat() {
        let private_bytes: Vec<u8> = (1..=32).collect();
        let public_bytes = vec![100, 101, 102];
        let old = OldSignatureKeyPair {
            private: private_bytes.clone(),
            public: public_bytes.clone(),
            signature_scheme: SignatureScheme::ED25519,
        };
        let json = serde_json::to_string(&old).unwrap();

        let kp: SignatureKeyPair = serde_json::from_str(&json).unwrap();
        assert_eq!(kp.private.as_slice(), private_bytes.as_slice());
        assert_eq!(kp.public(), public_bytes.as_slice());
        assert_eq!(kp.signature_scheme(), SignatureScheme::ED25519);
    }

    #[test]
    fn test_tls_backwards_compat() {
        let private_bytes = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let public_bytes = vec![100, 101, 102];
        let old = OldSignatureKeyPair {
            private: private_bytes.clone(),
            public: public_bytes.clone(),
            signature_scheme: SignatureScheme::ED25519,
        };
        let tls_bytes = old.tls_serialize_detached().unwrap();

        let (kp, rest) = SignatureKeyPair::tls_deserialize_bytes(&tls_bytes).unwrap();
        assert!(rest.is_empty());
        assert_eq!(kp.private.as_slice(), private_bytes.as_slice());
        assert_eq!(kp.public(), public_bytes.as_slice());
        assert_eq!(kp.signature_scheme(), SignatureScheme::ED25519);
    }
}
