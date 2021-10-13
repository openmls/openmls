use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::RwLock,
};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Aes256Gcm, NewAead,
};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::Signer as DalekSigner;
use hkdf::Hkdf;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    key_store::{FromKeyStoreValue, OpenMlsKeyStore, ToKeyStoreValue},
    random::OpenMlsRand,
    types::{AeadType, CryptoError, HashType, SignatureScheme},
    OpenMlsSecurity,
};
use p256::{
    ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey},
    EncodedPoint,
};
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug)]
pub struct RustCrypto {
    rng: RwLock<rand_chacha::ChaCha20Rng>,
    values: RwLock<HashMap<u64, Vec<u8>>>,
}

impl OpenMlsSecurity for RustCrypto {}

impl Default for RustCrypto {
    fn default() -> Self {
        Self {
            rng: RwLock::new(rand_chacha::ChaCha20Rng::from_entropy()),
            values: RwLock::new(HashMap::default()),
        }
    }
}

impl OpenMlsCrypto for RustCrypto {
    fn supports(
        &self,
        signature_scheme: openmls_traits::types::SignatureScheme,
    ) -> Result<(), openmls_traits::types::CryptoError> {
        match signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(()),
            SignatureScheme::ED25519 => Ok(()),
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn hkdf_extract(
        &self,
        hash_type: openmls_traits::types::HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(Hkdf::<Sha256>::extract(Some(salt), ikm).0.as_slice().into()),
            HashType::Sha2_512 => Ok(Hkdf::<Sha512>::extract(Some(salt), ikm).0.as_slice().into()),
        }
    }

    fn hkdf_expand(
        &self,
        hash_type: openmls_traits::types::HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => {
                let hkdf = Hkdf::<Sha256>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                Ok(okm)
            }
            HashType::Sha2_512 => {
                let hkdf = Hkdf::<Sha512>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                Ok(okm)
            }
        }
    }

    fn hash(
        &self,
        hash_type: openmls_traits::types::HashType,
        data: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(Sha256::digest(data).as_slice().into()),
            HashType::Sha2_512 => Ok(Sha512::digest(data).as_slice().into()),
        }
    }

    fn aead_encrypt(
        &self,
        alg: openmls_traits::types::AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match alg {
            AeadType::Aes128Gcm => {
                let aes =
                    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
            AeadType::Aes256Gcm => {
                let aes =
                    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
            AeadType::ChaCha20Poly1305 => {
                let aes = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
        }
    }

    fn aead_decrypt(
        &self,
        alg: openmls_traits::types::AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match alg {
            AeadType::Aes128Gcm => {
                let aes =
                    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            AeadType::Aes256Gcm => {
                let aes =
                    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.encrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            AeadType::ChaCha20Poly1305 => {
                let aes = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.encrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
        }
    }

    fn signature_key_gen(
        &self,
        alg: openmls_traits::types::SignatureScheme,
    ) -> Result<(Vec<u8>, Vec<u8>), openmls_traits::types::CryptoError> {
        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let k = SigningKey::random(&mut *rng);
                let pk = k.verifying_key().to_encoded_point(false).as_bytes().into();
                Ok((k.to_bytes().as_slice().into(), pk))
            }
            SignatureScheme::ED25519 => {
                // XXX: We can't use our RNG here
                let k = ed25519_dalek::Keypair::generate(&mut rand_07::rngs::OsRng).to_bytes();
                let pk = k[ed25519_dalek::SECRET_KEY_LENGTH..].to_vec();
                // full key here because we need it to sign...
                let sk_pk = k.into();
                Ok((sk_pk, pk))
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn verify_signature(
        &self,
        alg: openmls_traits::types::SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), openmls_traits::types::CryptoError> {
        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = VerifyingKey::from_encoded_point(
                    &EncodedPoint::from_bytes(pk).map_err(|_| CryptoError::CryptoLibraryError)?,
                )
                .map_err(|_| CryptoError::CryptoLibraryError)?;
                k.verify(
                    data,
                    &Signature::from_der(signature).map_err(|_| CryptoError::InvalidSignature)?,
                )
                .map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::PublicKey::from_bytes(pk)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
                    return Err(CryptoError::CryptoLibraryError);
                }
                let mut sig = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
                sig.clone_from_slice(signature);
                k.verify_strict(data, &ed25519_dalek::Signature::new(sig))
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn sign(
        &self,
        alg: openmls_traits::types::SignatureScheme,
        data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = SigningKey::from_bytes(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature = k.sign(data);
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::Keypair::from_bytes(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature = k.sign(data);
                Ok(signature.to_bytes().into())
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }
}

impl OpenMlsRand for RustCrypto {
    fn random_array<const N: usize>(&self) -> [u8; N] {
        let mut rng = self.rng.write().unwrap();
        let mut out = [0u8; N];
        rng.fill_bytes(&mut out);
        out
    }

    fn random_vec(&self, len: usize) -> Vec<u8> {
        let mut rng = self.rng.write().unwrap();
        let mut out = vec![0u8; len];
        rng.fill_bytes(&mut out);
        out
    }
}

/// Errors thrown by the key store.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Error {
    UnsupportedValueTypeBytes,
    UnsupportedMethod,
    SerializationError,
}

impl Into<String> for Error {
    fn into(self) -> String {
        match self {
            Error::UnsupportedValueTypeBytes => {
                "The key store does not allow storing serialized values.".to_string()
            }
            Error::UnsupportedMethod => "Updating is not supported by this key store.".to_string(),
            Error::SerializationError => "Error serializing value.".to_string(),
        }
    }
}

impl OpenMlsKeyStore for RustCrypto {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error = Error;

    /// Store a value `v` that implements the [`KeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<K: Hash, V: ToKeyStoreValue>(&self, k: &K, v: &V) -> Result<(), Self::Error> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut hasher);
        let k = hasher.finish();
        let value = v
            .to_key_store_value()
            .map_err(|_| Error::SerializationError)?;
        // We unwrap here, because this is the only function claiming a write
        // lock on `credential_bundles`. It only holds the lock very briefly and
        // should not panic during that period.
        let mut values = self.values.write().unwrap();
        values.insert(k, value);
        Ok(())
    }

    /// Read and return a value stored for ID `k` that implements the
    /// [`KeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<K: Hash, V: FromKeyStoreValue>(&self, k: &K) -> Option<V> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut hasher);
        let k = hasher.finish();

        // We unwrap here, because the two functions claiming a write lock on
        // `init_key_package_bundles` (this one and `generate_key_package_bundle`) only
        // hold the lock very briefly and should not panic during that period.
        let values = self.values.read().unwrap();
        if let Some(value) = values.get(&k) {
            V::from_key_store_value(value).ok()
        } else {
            None
        }
    }

    /// Not supported.
    fn update<K: Hash, V: FromKeyStoreValue>(&self, _k: &K, _v: &V) -> Result<(), Self::Error> {
        Err(Error::UnsupportedMethod)
    }

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete<K: Hash>(&self, k: &K) -> Result<(), Self::Error> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut hasher);
        let k = hasher.finish();

        // We just delete both ...
        let mut values = self.values.write().unwrap();
        values.remove(&k);
        Ok(())
    }
}
