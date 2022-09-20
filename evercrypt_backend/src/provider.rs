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

    /// Returns `(sk, pk)` or an error if the signature scheme is not supported or
    /// the key generation fails.
    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let signature_mode = match signature_mode(alg) {
            Ok(signature_mode) => signature_mode,
            Err(_) => return Err(CryptoError::UnsupportedSignatureScheme),
        };
        match signature::key_gen(signature_mode) {
            Ok((sk, pk)) => Ok((sk, pk)),
            Err(e) => {
                error!("Key generation really shouldn't fail. {:?}", e);
                Err(CryptoError::CryptoLibraryError)
            }
        }
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

    /// Returns the signature or an error if the signature scheme is not supported
    /// or signing fails.
    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature_mode = match signature_mode(alg) {
            Ok(signature_mode) => signature_mode,
            Err(_) => return Err(CryptoError::UnsupportedSignatureScheme),
        };
        let (hash, nonce) = match signature_mode {
            SignatureMode::Ed25519 => (None, None),
            SignatureMode::P256 => {
                let digest =
                    hash_from_signature(alg).map_err(|_| CryptoError::UnsupportedHashAlgorithm)?;
                let nonce =
                    p256_ecdsa_random_nonce().map_err(|_| CryptoError::CryptoLibraryError)?;
                (Some(digest), Some(nonce))
            }
        };
        let signature = evercrypt::signature::sign(signature_mode, hash, key, data, nonce.as_ref())
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        if signature_mode == SignatureMode::P256 {
            der_encode(&signature)
        } else {
            Ok(signature)
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

/// This function DER encodes a given ECDSA signature consisting of bytes
/// representing the concatenated scalars. If the encoding fails, it will
/// throw a `CryptoError`.
fn der_encode(raw_signature: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // A small helper function to determine the length of a given raw
    // scalar.
    fn scalar_length(mut scalar: &[u8]) -> Result<usize, CryptoError> {
        // Remove prepending zeros of the given, unencoded scalar.
        let mut msb = scalar
            .read_u8()
            .map_err(|_| CryptoError::SignatureEncodingError)?;
        while msb == 0x00 {
            msb = scalar
                .read_u8()
                .map_err(|_| CryptoError::SignatureEncodingError)?;
        }

        // The length of the scalar is what's left after removing the
        // prepending zeroes, plus 1 for the msb which we've already read.
        let mut scalar_length = scalar.len() + 1;

        // If the most significant bit is 1, we have to prepend 0x00 to indicate
        // that the integer is unsigned.
        if msb > 0x7F {
            // This increases the scalar length by 1.
            scalar_length += 1;
        };

        Ok(scalar_length)
    }

    // A small function to DER encode single scalar.
    fn encode_scalar<W: Write>(mut scalar: &[u8], mut buffer: W) -> Result<(), CryptoError> {
        // Check that the given scalar has the right length.
        if scalar.len() != P256_SCALAR_LENGTH {
            log::error!("Error while encoding scalar: Scalar too large.");
            return Err(CryptoError::SignatureEncodingError);
        }

        // The encoded scalar needs to start with integer tag.
        buffer
            .write_u8(INTEGER_TAG)
            .map_err(|_| CryptoError::SignatureEncodingError)?;

        // Determine the length of the scalar.
        let scalar_length = scalar_length(scalar)?;

        buffer
            // It is safpe to convert to u8, because we know that the length
            // of the scalar is at most 33.
            .write_u8(scalar_length as u8)
            .map_err(|_| CryptoError::SignatureEncodingError)?;

        // Remove prepending zeros of the given, unencoded scalar.
        let mut msb = scalar
            .read_u8()
            .map_err(|_| CryptoError::SignatureEncodingError)?;
        while msb == 0x00 {
            msb = scalar
                .read_u8()
                .map_err(|_| CryptoError::SignatureEncodingError)?;
        }

        // If the most significant bit is 1, we have to prepend 0x00 to indicate
        // that the integer is unsigned.
        if msb > 0x7F {
            buffer
                .write_u8(0x00)
                .map_err(|_| CryptoError::SignatureEncodingError)?;
        };

        // Write the msb to the encoded scalar.
        buffer
            .write_u8(msb)
            .map_err(|_| CryptoError::SignatureEncodingError)?;

        // Write the rest of the scalar.
        buffer
            .write_all(scalar)
            .map_err(|_| CryptoError::SignatureEncodingError)?;

        Ok(())
    }

    // Check overall length
    if raw_signature.len() != 2 * P256_SCALAR_LENGTH {
        return Err(CryptoError::SignatureEncodingError);
    }

    // We DER encode the ECDSA signature as per spec, assuming that
    // `sign` returns two concatenated values (r||s).
    let r = raw_signature
        .get(..P256_SCALAR_LENGTH)
        .ok_or(CryptoError::SignatureEncodingError)?;
    let s = raw_signature
        .get(P256_SCALAR_LENGTH..2 * P256_SCALAR_LENGTH)
        .ok_or(CryptoError::SignatureEncodingError)?;

    let length_r = scalar_length(r)?;
    let length_s = scalar_length(s)?;

    // The overall length is
    // 1 for the sequence tag
    // 1 for the overall length encoding
    // 2 for the integer tags of both scalars
    // 2 for the length encoding of both scalars
    // plus the length of both scalars
    let mut encoded_signature: Vec<u8> = Vec::with_capacity(6 + length_r + length_s);

    // Write the DER Sequence tag
    encoded_signature
        .write_u8(SEQUENCE_TAG)
        .map_err(|_| CryptoError::SignatureEncodingError)?;

    // Write a placeholder byte for length. This will be overwritten once we
    // have encoded the scalars and know the final length.
    encoded_signature
        //The conversion to u8 is safe, because we know that each of the
        // scalars is at most 33 bytes long plus the tags and length
        // encodings as described above.
        .write_u8((4 + length_r + length_s) as u8)
        .map_err(|_| CryptoError::SignatureEncodingError)?;

    encode_scalar(r, &mut encoded_signature)?;
    encode_scalar(s, &mut encoded_signature)?;

    Ok(encoded_signature)
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

#[test]
fn test_der_codec() {
    let evercrypt = EvercryptProvider::default();
    let payload = vec![0u8];
    let signature_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    let (sk, pk) = signature_key_gen(signature_mode(signature_scheme).unwrap())
        .expect("error generating sig keypair");
    let signature = evercrypt
        .sign(signature_scheme, &payload, &sk)
        .expect("error creating signature");

    // Make sure that signatures are DER encoded and can be decoded to valid signatures
    let decoded_signature = der_decode(&signature).expect("Error decoding valid signature.");

    verify(
        SignatureMode::P256,
        Some(hash_from_signature(signature_scheme).expect("Couldn't get digest mode of P256")),
        &pk,
        &decoded_signature,
        &payload,
    )
    .expect("error while verifying der decoded signature");

    // Encoding a de-coded signature should yield the same string.
    let re_encoded_signature =
        der_encode(&decoded_signature).expect("error encoding valid signature");

    assert_eq!(re_encoded_signature, signature);

    // Make sure that the signature still verifies.
    evercrypt
        .verify_signature(signature_scheme, &payload, &pk, &signature)
        .expect("error verifying signature");
}

#[test]
fn test_der_decoding() {
    let evercrypt = EvercryptProvider::default();
    let payload = vec![0u8];
    let signature_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    let (sk, _) = signature_key_gen(signature_mode(signature_scheme).unwrap())
        .expect("error generating sig keypair");
    let signature = evercrypt
        .sign(signature_scheme, &payload, &sk)
        .expect("error creating signature");

    // Now we tamper with the original signature to make the decoding fail in
    // various ways.
    let original_bytes = signature;

    // Wrong sequence tag
    let mut wrong_sequence_tag = original_bytes.clone();
    wrong_sequence_tag[0] ^= 0xFF;

    assert_eq!(
        der_decode(&wrong_sequence_tag).expect_err("invalid signature successfully decoded"),
        CryptoError::SignatureDecodingError
    );

    // Too long to be valid (bytes will be left over after reading the
    // signature.)
    let mut too_long = original_bytes.clone();
    too_long.extend_from_slice(&original_bytes);

    assert_eq!(
        der_decode(&too_long).expect_err("invalid signature successfully decoded"),
        CryptoError::SignatureDecodingError
    );

    // Inaccurate length
    let mut inaccurate_length = original_bytes.clone();
    inaccurate_length[1] = 0x9F;

    assert_eq!(
        der_decode(&inaccurate_length).expect_err("invalid signature successfully decoded"),
        CryptoError::SignatureDecodingError
    );

    // Wrong integer tag
    let mut wrong_integer_tag = original_bytes.clone();
    wrong_integer_tag[2] ^= 0xFF;

    assert_eq!(
        der_decode(&wrong_sequence_tag).expect_err("invalid signature successfully decoded"),
        CryptoError::SignatureDecodingError
    );

    // Scalar too long overall
    let mut scalar_too_long = original_bytes.clone();
    scalar_too_long[3] = 0x9F;

    assert_eq!(
        der_decode(&scalar_too_long).expect_err("invalid signature successfully decoded"),
        CryptoError::SignatureDecodingError
    );

    // Scalar length encoding invalid
    let mut scalar_length_encoding = original_bytes.clone();
    scalar_length_encoding[3] = 0x21;
    scalar_length_encoding[4] = 0xFF;

    assert_eq!(
        der_decode(&scalar_length_encoding).expect_err("invalid signature successfully decoded"),
        CryptoError::SignatureDecodingError
    );

    // Empty signature
    let empty_signature = Vec::new();

    assert_eq!(
        der_decode(&empty_signature).expect_err("invalid signature successfully decoded"),
        CryptoError::SignatureDecodingError
    );

    // 1byte signature
    let one_byte_sig = vec![0x30];

    assert_eq!(
        der_decode(&one_byte_sig).expect_err("invalid signature successfully decoded"),
        CryptoError::SignatureDecodingError
    );

    // Another signature too long variation
    let mut signature_too_long_2 = original_bytes.clone();
    signature_too_long_2[1] += 0x01;
    signature_too_long_2.extend_from_slice(&[0]);

    assert_eq!(
        der_decode(&signature_too_long_2).expect_err("invalid signature successfully decoded"),
        CryptoError::SignatureDecodingError
    );
}

#[test]
fn test_der_encoding() {
    let evercrypt = EvercryptProvider::default();
    let payload = vec![0u8];
    let signature_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    let (sk, _) = signature_key_gen(signature_mode(signature_scheme).unwrap())
        .expect("error generating sig keypair");
    let signature = evercrypt
        .sign(signature_scheme, &payload, &sk)
        .expect("error creating signature");

    let raw_signature = der_decode(&signature).expect("error decoding a valid siganture");

    // Now let's try to der encode various incomplete parts of it.

    // Empty signature
    let empty_signature = Vec::new();

    assert_eq!(
        der_encode(&empty_signature).expect_err("successfully encoded invalid raw signature"),
        CryptoError::SignatureEncodingError
    );

    // Signature too long
    let mut signature_too_long = raw_signature.clone();
    signature_too_long.extend_from_slice(&raw_signature);

    assert_eq!(
        der_encode(&signature_too_long).expect_err("successfully encoded invalid raw signature"),
        CryptoError::SignatureEncodingError
    );

    // Scalar consisting only of 0x00
    let zero_scalar = vec![0x00; 2 * P256_SCALAR_LENGTH];

    assert_eq!(
        der_encode(&zero_scalar).expect_err("successfully encoded invalid raw signature"),
        CryptoError::SignatureEncodingError
    );
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
