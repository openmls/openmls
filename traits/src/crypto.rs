//! # The OpenMLS Crypto Trait
//!
//! This trait defines all cryptographic functions used by OpenMLS.

use crate::{
    random::OpenMlsRand,
    types::{AeadType, CryptoError, HashType, SignatureScheme},
};

pub trait OpenMlsCrypto {
    /// Check whether the [`SignatureScheme`] is supported or not.
    ///
    /// Returns an error if the signature scheme is not supported.
    /// FIXME: Drop.
    fn supports(&self, signature_scheme: SignatureScheme) -> Result<(), CryptoError>;

    /// HKDF extract.
    ///
    /// Returns an error if the [`HashType`] is not supported.
    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// HKDF expand.
    ///
    /// Returns an error if the [`HashType`] is not supported or the output length
    /// is too long.
    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Hash the `data`.
    ///
    /// Returns an error if the [`HashType`] is not supported.
    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// AEAD encrypt with the given parameters.
    ///
    /// Returns an error if the [`AeadType`] is not supported or an encryption
    /// error occurs.
    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// AEAD decrypt with the given parameters.
    ///
    /// Returns an error if the [`AeadType`] is not supported or a decryption
    /// error occurs.
    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Generate a signature key.
    ///
    /// Returns an error if the [`SignatureScheme`] is not supported or the key
    /// generation fails.
    fn signature_key_gen(
        &self,
        alg: SignatureScheme,
        rng: &mut impl OpenMlsRand,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

    /// Verify the signature
    ///
    /// Returns an error if the [`SignatureScheme`] is not supported or the
    /// signature verification fails.
    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;

    /// Sign with the given parameters.
    ///
    /// Returns an error if the [`SignatureScheme`] is not supported or an error
    /// occurs during signature generation.
    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
