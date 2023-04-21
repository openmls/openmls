//! # Evercrypt Crypto Provider
//!
//! Use evercrypt for all crypto operations.

use std::{
    io::{Read, Write},
    sync::RwLock,
};

use evercrypt::prelude::*;
use hpke::Hpke;
use hpke_rs_crypto::types as hpke_types;
use hpke_rs_evercrypt::HpkeEvercrypt;
use log::error;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
        HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
    },
};
use rand::{RngCore, SeedableRng};

/// The Evercrypt crypto provider.
#[derive(Debug)]
pub struct EvercryptProvider {
    rng: RwLock<rand_chacha::ChaCha20Rng>,
}

impl Default for EvercryptProvider {
    fn default() -> Self {
        Self {
            rng: RwLock::new(rand_chacha::ChaCha20Rng::from_entropy()),
        }
    }
}

#[inline(always)]
fn signature_mode(signature_scheme: SignatureScheme) -> Result<SignatureMode, &'static str> {
    match signature_scheme {
        SignatureScheme::ED25519 => Ok(SignatureMode::Ed25519),
        SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(SignatureMode::P256),
        SignatureScheme::ED448 => Err("SignatureScheme ed448 is not supported."),
        SignatureScheme::ECDSA_SECP521R1_SHA512 => {
            Err("SignatureScheme ecdsa_secp521r1 is not supported.")
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            Err("SignatureScheme ecdsa_secp384r1 is not supported.")
        }
    }
}

#[inline(always)]
fn hash_from_signature(signature_scheme: SignatureScheme) -> Result<DigestMode, &'static str> {
    match signature_scheme {
        // The digest mode for ed25519 is not really used
        SignatureScheme::ED25519 => Ok(DigestMode::Sha256),
        SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(DigestMode::Sha256),
        SignatureScheme::ED448 => Err("SignatureScheme ed448 is not supported."),
        SignatureScheme::ECDSA_SECP521R1_SHA512 => {
            Err("SignatureScheme ecdsa_secp521r1 is not supported.")
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            Err("SignatureScheme ecdsa_secp384r1 is not supported.")
        }
    }
}

#[inline(always)]
fn hash_from_algorithm(hash_type: HashType) -> DigestMode {
    match hash_type {
        HashType::Sha2_256 => DigestMode::Sha256,
        HashType::Sha2_384 => DigestMode::Sha384,
        HashType::Sha2_512 => DigestMode::Sha512,
    }
}

#[inline(always)]
fn aead_from_algorithm(alg: AeadType) -> AeadMode {
    match alg {
        AeadType::Aes128Gcm => AeadMode::Aes128Gcm,
        AeadType::Aes256Gcm => AeadMode::Aes256Gcm,
        AeadType::ChaCha20Poly1305 => AeadMode::Chacha20Poly1305,
    }
}

#[inline(always)]
fn hmac_from_hash(hash_type: HashType) -> HmacMode {
    match hash_type {
        HashType::Sha2_256 => HmacMode::Sha256,
        HashType::Sha2_384 => HmacMode::Sha384,
        HashType::Sha2_512 => HmacMode::Sha512,
    }
}

impl OpenMlsCrypto for EvercryptProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        ]
    }

    /// Returns `HKDF::extract` with the given parameters or an error if the HKDF
    /// algorithm isn't supported.
    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let hmac = hmac_from_hash(hash_type);
        Ok(hkdf::extract(hmac, salt, ikm))
    }

    /// Returns `HKDF::expand` with the given parameters or an error if the HKDF
    /// algorithms isn't supported or the requested output length is invalid.
    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let hmac = hmac_from_hash(hash_type);
        Ok(hkdf::expand(hmac, prk, info, okm_len))
    }

    /// Returns the hash of `data` or an error if the hash algorithm isn't supported.
    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let alg = hash_from_algorithm(hash_type);
        Ok(evercrypt::digest::hash(alg, data))
    }

    /// Returns the cipher text, tag (concatenated) or an error if the AEAD scheme
    /// is not supported or the encryption fails.
    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let alg = aead_from_algorithm(alg);
        aead::encrypt_combined(alg, key, data, nonce, aad)
            .map_err(|_| CryptoError::CryptoLibraryError)
    }

    /// Returns the decryption of the provided cipher text or an error if the AEAD
    /// scheme is not supported or the decryption fails.
    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let alg = aead_from_algorithm(alg);
        aead_decrypt_combined(alg, key, ct_tag, nonce, aad)
            .map_err(|_| CryptoError::CryptoLibraryError)
    }

    /// Returns an error if the signature verification fails or the requested scheme
    /// is not supported.
    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let signature_mode = match signature_mode(alg) {
            Ok(signature_mode) => signature_mode,
            Err(_) => return Err(CryptoError::UnsupportedSignatureScheme),
        };
        let digest_mode = match hash_from_signature(alg) {
            Ok(dm) => dm,
            Err(_) => return Err(CryptoError::UnsupportedSignatureScheme),
        };
        let valid = if signature_mode == SignatureMode::P256 {
            verify(
                signature_mode,
                digest_mode,
                pk,
                &der_decode(signature)?,
                data,
            )
        } else {
            verify(signature_mode, digest_mode, pk, signature, data)
        }
        .map_err(|_| CryptoError::InvalidSignature)?;

        if valid {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> openmls_traits::types::HpkeCiphertext {
        let (kem_output, ciphertext) = hpke_from_config(config)
            .seal(&pk_r.into(), info, aad, ptxt, None, None, None)
            .unwrap();
        HpkeCiphertext {
            kem_output: kem_output.into(),
            ciphertext: ciphertext.into(),
        }
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &openmls_traits::types::HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        hpke_from_config(config)
            .open(
                input.kem_output.as_slice(),
                &sk_r.into(),
                info,
                aad,
                input.ciphertext.as_slice(),
                None,
                None,
                None,
            )
            .map_err(|_| CryptoError::HpkeDecryptionError)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        let (kem_output, context) = hpke_from_config(config)
            .setup_sender(&pk_r.into(), info, None, None, None)
            .map_err(|_| CryptoError::SenderSetupError)?;
        let exported_secret = context
            .export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)?;
        Ok((kem_output, exported_secret))
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        let context = hpke_from_config(config)
            .setup_receiver(enc, &sk_r.into(), info, None, None, None)
            .map_err(|_| CryptoError::ReceiverSetupError)?;
        let exported_secret = context
            .export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)?;
        Ok(exported_secret)
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> openmls_traits::types::HpkeKeyPair {
        let kp = hpke_from_config(config)
            .derive_key_pair(ikm)
            .unwrap()
            .into_keys();
        HpkeKeyPair {
            private: kp.0.as_slice().into(),
            public: kp.1.as_slice().into(),
        }
    }
}

fn hpke_from_config(config: HpkeConfig) -> Hpke<HpkeEvercrypt> {
    Hpke::<HpkeEvercrypt>::new(
        hpke::Mode::Base,
        kem_mode(config.0),
        kdf_mode(config.1),
        aead_mode(config.2),
    )
}

#[inline(always)]
fn kem_mode(kem: HpkeKemType) -> hpke_types::KemAlgorithm {
    match kem {
        HpkeKemType::DhKemP256 => hpke_types::KemAlgorithm::DhKemP256,
        HpkeKemType::DhKemP384 => hpke_types::KemAlgorithm::DhKemP384,
        HpkeKemType::DhKemP521 => hpke_types::KemAlgorithm::DhKemP521,
        HpkeKemType::DhKem25519 => hpke_types::KemAlgorithm::DhKem25519,
        HpkeKemType::DhKem448 => hpke_types::KemAlgorithm::DhKem448,
    }
}

#[inline(always)]
fn kdf_mode(kdf: HpkeKdfType) -> hpke_types::KdfAlgorithm {
    match kdf {
        HpkeKdfType::HkdfSha256 => hpke_types::KdfAlgorithm::HkdfSha256,
        HpkeKdfType::HkdfSha384 => hpke_types::KdfAlgorithm::HkdfSha384,
        HpkeKdfType::HkdfSha512 => hpke_types::KdfAlgorithm::HkdfSha512,
    }
}

#[inline(always)]
fn aead_mode(aead: HpkeAeadType) -> hpke_types::AeadAlgorithm {
    match aead {
        HpkeAeadType::AesGcm128 => hpke_types::AeadAlgorithm::Aes128Gcm,
        HpkeAeadType::AesGcm256 => hpke_types::AeadAlgorithm::Aes256Gcm,
        HpkeAeadType::ChaCha20Poly1305 => hpke_types::AeadAlgorithm::ChaCha20Poly1305,
        HpkeAeadType::Export => hpke_types::AeadAlgorithm::HpkeExport,
    }
}

// The length of the individual scalars. Since we only support ECDSA with P256,
// this is 32. It would be great if evercrypt were able to return the scalar
// size of a given curve.
const P256_SCALAR_LENGTH: usize = 32;

// DER encoding INTEGER tag.
const INTEGER_TAG: u8 = 0x02;

// DER encoding SEQUENCE tag.
const SEQUENCE_TAG: u8 = 0x30;

// The following two traits (ReadU8, Writeu8)are inlined from the byteorder
// crate to avoid a full dependency.
impl<R: Read + ?Sized> ReadU8 for R {}

pub trait ReadU8: Read {
    /// A small helper function to read a u8 from a Reader.
    #[inline]
    fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

impl<W: Write + ?Sized> WriteU8 for W {}

pub trait WriteU8: Write {
    /// A small helper function to write a u8 to a Writer.
    #[inline]
    fn write_u8(&mut self, n: u8) -> std::io::Result<()> {
        self.write_all(&[n])
    }
}

/// This function takes a DER encoded ECDSA signature and decodes it to the
/// bytes representing the concatenated scalars. If the decoding fails, it
/// will throw a `CryptoError`.
fn der_decode(mut signature_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // A small function to DER decode a single scalar.
    fn decode_scalar<R: Read>(mut buffer: R) -> Result<Vec<u8>, CryptoError> {
        // Check header bytes of encoded scalar.

        // 1 byte INTEGER tag should be 0x02
        let integer_tag = buffer
            .read_u8()
            .map_err(|_| CryptoError::SignatureDecodingError)?;
        if integer_tag != INTEGER_TAG {
            log::error!("Error while decoding scalar: Couldn't find INTEGER tag.");
            return Err(CryptoError::SignatureDecodingError);
        };

        // 1 byte length tag should be at most 0x21, i.e. 32 plus at most 1
        // byte indicating that the integer is unsigned.
        let mut scalar_length = buffer
            .read_u8()
            .map_err(|_| CryptoError::SignatureDecodingError)?
            as usize;
        if scalar_length > P256_SCALAR_LENGTH + 1 {
            log::error!("Error while decoding scalar: Scalar too long.");
            return Err(CryptoError::SignatureDecodingError);
        };

        // If the scalar is 0x21 long, the first byte has to be 0x00,
        // indicating that the following integer is unsigned. We can discard
        // this byte safely. If it's not 0x00, the scalar is too large not
        // thus not a valid point on the curve.
        if scalar_length == P256_SCALAR_LENGTH + 1 {
            if buffer
                .read_u8()
                .map_err(|_| CryptoError::SignatureDecodingError)?
                != 0x00
            {
                log::error!("Error while decoding scalar: Scalar too large or invalid encoding.");
                return Err(CryptoError::SignatureDecodingError);
            };
            // Since we just read that byte, we decrease the length by 1.
            scalar_length -= 1;
        };

        let mut scalar = vec![0; scalar_length];
        buffer
            .read_exact(&mut scalar)
            .map_err(|_| CryptoError::SignatureDecodingError)?;

        // The verification algorithm expects the scalars to be 32 bytes
        // long, buffered with zeroes.
        let mut padded_scalar = vec![0u8; P256_SCALAR_LENGTH - scalar_length];
        padded_scalar.append(&mut scalar);

        Ok(padded_scalar)
    }

    // Check header bytes:
    // 1 byte SEQUENCE tag should be 0x30
    let sequence_tag = signature_bytes
        .read_u8()
        .map_err(|_| CryptoError::SignatureDecodingError)?;
    if sequence_tag != SEQUENCE_TAG {
        log::error!("Error while decoding DER encoded signature: Couldn't find SEQUENCE tag.");
        return Err(CryptoError::SignatureDecodingError);
    };

    // At most 1 byte encoding the length of the scalars (short form DER
    // length encoding). Length has to be encoded in the short form, as we
    // expect the length not to exceed the maximum length of 70: Two times
    // at most 32 (scalar value) + 1 byte integer tag + 1 byte length tag +
    // at most 1 byte to indicating that the integer is unsigned.
    let length = signature_bytes
        .read_u8()
        .map_err(|_| CryptoError::SignatureDecodingError)? as usize;
    if length > 2 * (P256_SCALAR_LENGTH + 3) {
        log::error!("Error while decoding DER encoded signature: Signature too long.");
        return Err(CryptoError::SignatureDecodingError);
    }

    // The remaining bytes should be equal to the encoded length.
    if signature_bytes.len() != length {
        log::error!("Error while decoding DER encoded signature: Encoded length inaccurate.");
        return Err(CryptoError::SignatureDecodingError);
    }

    let mut r = decode_scalar(&mut signature_bytes)?;
    let mut s = decode_scalar(&mut signature_bytes)?;

    // If there are bytes remaining, the encoded length was larger than the
    // length of the individual scalars..
    if !signature_bytes.is_empty() {
        log::error!("Error while decoding DER encoded signature: Encoded overall length does not match the sum of scalar lengths.");
        return Err(CryptoError::SignatureDecodingError);
    }

    let mut out = Vec::with_capacity(2 * P256_SCALAR_LENGTH);
    out.append(&mut r);
    out.append(&mut s);
    Ok(out)
}

impl OpenMlsRand for EvercryptProvider {
    type Error = RandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut rng = self.rng.write().map_err(|_| Self::Error::LockPoisoned)?;
        let mut out = [0u8; N];
        rng.try_fill_bytes(&mut out)
            .map_err(|_| Self::Error::NotEnoughRandomness)?;
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut rng = self.rng.write().map_err(|_| Self::Error::LockPoisoned)?;
        let mut out = vec![0u8; len];
        rng.try_fill_bytes(&mut out)
            .map_err(|_| Self::Error::NotEnoughRandomness)?;
        Ok(out)
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RandError {
    #[error("Rng lock is poisoned.")]
    LockPoisoned,
    #[error("Unable to collect enough randomness.")]
    NotEnoughRandomness,
}
