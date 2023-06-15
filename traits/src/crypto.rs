//! # The OpenMLS Crypto Trait
//!
//! This trait defines all cryptographic functions used by OpenMLS.

use tls_codec::SecretVLBytes;

use crate::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
    HpkeKeyPair, KemOutput, SignatureScheme,
};

pub trait OpenMlsCrypto: Send + Sync {
    /// Check whether the [`Ciphersuite`] is supported by the backend or not.
    ///
    /// Returns a [`CryptoError::UnsupportedCiphersuite`] if the ciphersuite is not supported.
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError>;

    /// Returns the list of supported [`Ciphersuite`]s.
    fn supported_ciphersuites(&self) -> Vec<Ciphersuite>;

    /// HKDF extract.
    ///
    /// Returns an error if the [`HashType`] is not supported.
    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError>;

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
    ) -> Result<SecretVLBytes, CryptoError>;

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
    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

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

    // === HPKE === //

    /// HPKE single-shot encryption of `ptxt` to `pk_r`, using `info` and `aad`.
    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> HpkeCiphertext;

    /// HPKE single-shot decryption of `input` with `sk_r`, using `info` and
    /// `aad`.
    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// HPKE single-shot setup of a sender and immediate export a secret.
    ///
    /// The encapsulated secret is returned together with the exported secret.
    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError>;

    /// HPKE single-shot setup of a receiver and immediate export a secret.
    ///
    /// Returns the exported secret.
    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError>;

    /// Derive a new HPKE keypair from a given input key material.
    fn derive_hpke_keypair(&self, config: HpkeConfig, ikm: &[u8]) -> HpkeKeyPair;
}
