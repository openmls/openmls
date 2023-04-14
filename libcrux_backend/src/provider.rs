//! # libcrux Crypto Provider
//!
//! Use libcrux for all crypto operations.

use std::{
    io::{Read, Write},
    sync::RwLock,
};

use libcrux::{
    aead, digest,
    drbg::{Drbg, RngCore},
    hkdf,
    hpke::{self, HPKECiphertext},
    signature::{self, EcDsaP256Signature, Ed25519Signature},
};

#[cfg(test)]
use libcrux::hmac;

use log::error;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
        HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
    },
};

/// The libcrux crypto provider.
pub struct LibcruxProvider {
    rng: RwLock<Drbg>,
}

impl Default for LibcruxProvider {
    /// **PANICS** if there's not enough system entropy.
    fn default() -> Self {
        Self {
            rng: RwLock::new(Drbg::new(digest::Algorithm::Sha256).unwrap()),
        }
    }
}

#[inline(always)]
fn signature_mode(signature_scheme: SignatureScheme) -> Result<signature::Algorithm, &'static str> {
    match signature_scheme {
        SignatureScheme::ED25519 => Ok(signature::Algorithm::Ed25519),
        SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(signature::Algorithm::EcDsaP256(
            signature::DigestAlgorithm::Sha256,
        )),
        SignatureScheme::ED448 => Err("SignatureScheme ed448 is not supported."),
        SignatureScheme::ECDSA_SECP521R1_SHA512 => {
            Err("SignatureScheme ecdsa_secp521r1 is not supported.")
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            Err("SignatureScheme ecdsa_secp384r1 is not supported.")
        }
    }
}

#[cfg(test)]
#[inline(always)]
fn hash_from_signature(
    signature_scheme: SignatureScheme,
) -> Result<digest::Algorithm, &'static str> {
    match signature_scheme {
        // The digest mode for ed25519 is not really used
        SignatureScheme::ED25519 => Ok(digest::Algorithm::Sha256),
        SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(digest::Algorithm::Sha256),
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
fn hash_from_algorithm(hash_type: HashType) -> digest::Algorithm {
    match hash_type {
        HashType::Sha2_256 => digest::Algorithm::Sha256,
        HashType::Sha2_384 => digest::Algorithm::Sha384,
        HashType::Sha2_512 => digest::Algorithm::Sha512,
    }
}

#[inline(always)]
fn aead_from_algorithm(alg: AeadType) -> aead::Algorithm {
    match alg {
        AeadType::Aes128Gcm => aead::Algorithm::Aes128Gcm,
        AeadType::Aes256Gcm => aead::Algorithm::Aes256Gcm,
        AeadType::ChaCha20Poly1305 => aead::Algorithm::Chacha20Poly1305,
    }
}

#[cfg(test)]
#[inline(always)]
fn hmac_from_hash(hash_type: HashType) -> hmac::Algorithm {
    match hash_type {
        HashType::Sha2_256 => hmac::Algorithm::Sha256,
        HashType::Sha2_384 => hmac::Algorithm::Sha384,
        HashType::Sha2_512 => hmac::Algorithm::Sha512,
    }
}

#[inline(always)]
fn hkdf_from_hash(hash_type: HashType) -> hkdf::Algorithm {
    match hash_type {
        HashType::Sha2_256 => hkdf::Algorithm::Sha256,
        HashType::Sha2_384 => hkdf::Algorithm::Sha384,
        HashType::Sha2_512 => hkdf::Algorithm::Sha512,
    }
}

const MAX_DATA_LEN: usize = 0x10000000;

impl OpenMlsCrypto for LibcruxProvider {
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
        let hkdf = hkdf_from_hash(hash_type);
        Ok(hkdf::extract(hkdf, salt, ikm))
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
        let hkdf = hkdf_from_hash(hash_type);
        hkdf::expand(hkdf, prk, info, okm_len).map_err(|_| CryptoError::HkdfOutputLengthInvalid)
    }

    /// Returns the hash of `data` or an error if the hash algorithm isn't supported.
    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let alg = hash_from_algorithm(hash_type);
        Ok(digest::hash(alg, data))
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
        if data.len() > MAX_DATA_LEN {
            return Err(CryptoError::TooMuchData);
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidLength);
        }
        let alg = aead_from_algorithm(alg);
        let key =
            aead::Key::from_bytes(alg, key.to_vec()).map_err(|_| CryptoError::InvalidAeadKey)?;
        let mut data = data.to_vec();
        let mut iv = [0u8; 12];
        iv.copy_from_slice(nonce);
        aead::encrypt(&key, &mut data, aead::Iv(iv), aad)
            .map_err(|_| CryptoError::CryptoLibraryError)
            .map(|r| r.as_ref().to_vec())
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
        if ct_tag.len() > MAX_DATA_LEN {
            return Err(CryptoError::TooMuchData);
        }
        if nonce.len() != 12 || ct_tag.len() < 16 {
            return Err(CryptoError::InvalidLength);
        }
        let alg = aead_from_algorithm(alg);
        let key =
            aead::Key::from_bytes(alg, key.to_vec()).map_err(|_| CryptoError::InvalidAeadKey)?;
        let mut data = ct_tag[..ct_tag.len() - 16].to_vec();
        let iv = aead::Iv::new(nonce).map_err(|_| CryptoError::CryptoLibraryError)?;
        let tag = aead::Tag::from_slice(&ct_tag[ct_tag.len() - 16..])
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        aead::decrypt(&key, &mut data, iv, aad, &tag)
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        Ok(data.to_vec())
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
        // let digest_mode = match hash_from_signature(alg) {
        //     Ok(dm) => dm,
        //     Err(_) => return Err(CryptoError::UnsupportedSignatureScheme),
        // };
        let signature = if matches!(
            signature_mode,
            signature::Algorithm::EcDsaP256(signature::DigestAlgorithm::Sha256)
        ) {
            let mut bytes = [0u8; 64];
            let decoded = der_decode(signature)?;
            if decoded.len() != 64 {
                return Err(CryptoError::InvalidSignature);
            }
            bytes.clone_from_slice(&decoded);
            signature::Signature::EcDsaP256(EcDsaP256Signature::from_bytes(
                bytes,
                signature::Algorithm::EcDsaP256(signature::DigestAlgorithm::Sha256),
            ))
        } else {
            if signature.len() != 32 {
                return Err(CryptoError::InvalidSignature);
            }
            let mut bytes = [0u8; 32];
            bytes.clone_from_slice(signature);
            signature::Signature::Ed25519(Ed25519Signature::from_bytes(bytes))
        };

        signature::verify(data, &signature, pk).map_err(|_| CryptoError::InvalidSignature)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> openmls_traits::types::HpkeCiphertext {
        let mut rng = self.rng.write().unwrap(); // XXX: return error
        let hpke_config = hpke_from_config(config);
        let mut randomness = vec![0u8; hpke::kem::Nsk(hpke_config.1)];
        rng.fill_bytes(&mut randomness);

        let enc_ctxt = hpke::HpkeSeal(
            hpke_config,
            pk_r,
            info,
            aad,
            ptxt,
            None,
            None,
            None,
            randomness,
        )
        .unwrap();

        HpkeCiphertext {
            kem_output: enc_ctxt.0.into(),
            ciphertext: enc_ctxt.1.into(),
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
        let kem_ctxt = HPKECiphertext(
            // XXX: unnecessary conversion
            input.kem_output.as_slice().to_vec(),
            input.ciphertext.as_slice().to_vec(),
        );
        hpke::HpkeOpen(
            hpke_from_config(config),
            &kem_ctxt,
            sk_r,
            info,
            aad,
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
        let mut rng = self.rng.write().unwrap(); // XXX: return error
        let hpke_config = hpke_from_config(config);
        let mut randomness = vec![0u8; hpke::kem::Nsk(hpke_config.1)];
        rng.fill_bytes(&mut randomness);

        let exported_secret = hpke::SendExport(
            hpke_config,
            pk_r,
            info,
            exporter_context.to_vec(),
            exporter_length,
            None,
            None,
            None,
            randomness,
        )
        .map_err(|_| CryptoError::ExporterError)?;
        Ok((exported_secret.0, exported_secret.1))
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
        let mut rng = self.rng.write().unwrap(); // XXX: return error
        let hpke_config = hpke_from_config(config);
        let mut randomness = vec![0u8; hpke::kem::Nsk(hpke_config.1)];
        rng.fill_bytes(&mut randomness);

        let exported_secret = hpke::ReceiveExport(
            hpke_config,
            enc,
            sk_r,
            info,
            exporter_context.to_vec(),
            exporter_length,
            None,
            None,
            None,
        )
        .map_err(|_| CryptoError::ExporterError)?;
        Ok(exported_secret)
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> openmls_traits::types::HpkeKeyPair {
        let kp = hpke::kem::DeriveKeyPair(hpke_from_config(config).1, ikm).unwrap(); //XXX: return error
        HpkeKeyPair {
            private: kp.0,
            public: kp.1,
        }
    }
}

fn hpke_from_config(config: HpkeConfig) -> hpke::HPKEConfig {
    hpke::HPKEConfig(
        hpke::Mode::mode_base,
        kem_mode(config.0),
        kdf_mode(config.1),
        aead_mode(config.2),
    )
}

#[inline(always)]
fn kem_mode(kem: HpkeKemType) -> hpke::kem::KEM {
    match kem {
        HpkeKemType::DhKemP256 => hpke::kem::KEM::DHKEM_P256_HKDF_SHA256,
        HpkeKemType::DhKemP384 => hpke::kem::KEM::DHKEM_P384_HKDF_SHA384,
        HpkeKemType::DhKemP521 => hpke::kem::KEM::DHKEM_P521_HKDF_SHA512,
        HpkeKemType::DhKem25519 => hpke::kem::KEM::DHKEM_X25519_HKDF_SHA256,
        HpkeKemType::DhKem448 => hpke::kem::KEM::DHKEM_X448_HKDF_SHA512,
    }
}

#[inline(always)]
fn kdf_mode(kdf: HpkeKdfType) -> hpke::kdf::KDF {
    match kdf {
        HpkeKdfType::HkdfSha256 => hpke::kdf::KDF::HKDF_SHA256,
        HpkeKdfType::HkdfSha384 => hpke::kdf::KDF::HKDF_SHA384,
        HpkeKdfType::HkdfSha512 => hpke::kdf::KDF::HKDF_SHA512,
    }
}

#[inline(always)]
fn aead_mode(aead: HpkeAeadType) -> hpke::aead::AEAD {
    match aead {
        HpkeAeadType::AesGcm128 => hpke::aead::AEAD::AES_128_GCM,
        HpkeAeadType::AesGcm256 => hpke::aead::AEAD::AES_256_GCM,
        HpkeAeadType::ChaCha20Poly1305 => hpke::aead::AEAD::ChaCha20Poly1305,
        HpkeAeadType::Export => hpke::aead::AEAD::Export_only,
    }
}

// The length of the individual scalars. Since we only support ECDSA with P256,
// this is 32. It would be great if libcrux were able to return the scalar
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

// FIXME: enable again
// #[test]
// fn test_der_codec() {
// let libcrux = LibcruxProvider::default();
// let payload = vec![0u8];
// let signature_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
// let (sk, pk) = signature_key_gen(signature_mode(signature_scheme).unwrap())
//     .expect("error generating sig keypair");
// let signature = libcrux
//     .sign(signature_scheme, &payload, &sk)
//     .expect("error creating signature");

// // Make sure that signatures are DER encoded and can be decoded to valid signatures
// let decoded_signature = der_decode(&signature).expect("Error decoding valid signature.");

// verify(
//     SignatureMode::P256,
//     Some(hash_from_signature(signature_scheme).expect("Couldn't get digest mode of P256")),
//     &pk,
//     &decoded_signature,
//     &payload,
// )
// .expect("error while verifying der decoded signature");

// // Encoding a de-coded signature should yield the same string.
// let re_encoded_signature =
//     der_encode(&decoded_signature).expect("error encoding valid signature");

// assert_eq!(re_encoded_signature, signature);

// // Make sure that the signature still verifies.
// libcrux
//     .verify_signature(signature_scheme, &payload, &pk, &signature)
//     .expect("error verifying signature");
// }

// #[test]
// fn test_der_decoding() {
//     let libcrux = LibcruxProvider::default();
//     let payload = vec![0u8];
//     let signature_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
//     let (sk, _) = signature_key_gen(signature_mode(signature_scheme).unwrap())
//         .expect("error generating sig keypair");
//     let signature = libcrux
//         .sign(signature_scheme, &payload, &sk)
//         .expect("error creating signature");

//     // Now we tamper with the original signature to make the decoding fail in
//     // various ways.
//     let original_bytes = signature;

//     // Wrong sequence tag
//     let mut wrong_sequence_tag = original_bytes.clone();
//     wrong_sequence_tag[0] ^= 0xFF;

//     assert_eq!(
//         der_decode(&wrong_sequence_tag).expect_err("invalid signature successfully decoded"),
//         CryptoError::SignatureDecodingError
//     );

//     // Too long to be valid (bytes will be left over after reading the
//     // signature.)
//     let mut too_long = original_bytes.clone();
//     too_long.extend_from_slice(&original_bytes);

//     assert_eq!(
//         der_decode(&too_long).expect_err("invalid signature successfully decoded"),
//         CryptoError::SignatureDecodingError
//     );

//     // Inaccurate length
//     let mut inaccurate_length = original_bytes.clone();
//     inaccurate_length[1] = 0x9F;

//     assert_eq!(
//         der_decode(&inaccurate_length).expect_err("invalid signature successfully decoded"),
//         CryptoError::SignatureDecodingError
//     );

//     // Wrong integer tag
//     let mut wrong_integer_tag = original_bytes.clone();
//     wrong_integer_tag[2] ^= 0xFF;

//     assert_eq!(
//         der_decode(&wrong_sequence_tag).expect_err("invalid signature successfully decoded"),
//         CryptoError::SignatureDecodingError
//     );

//     // Scalar too long overall
//     let mut scalar_too_long = original_bytes.clone();
//     scalar_too_long[3] = 0x9F;

//     assert_eq!(
//         der_decode(&scalar_too_long).expect_err("invalid signature successfully decoded"),
//         CryptoError::SignatureDecodingError
//     );

//     // Scalar length encoding invalid
//     let mut scalar_length_encoding = original_bytes.clone();
//     scalar_length_encoding[3] = 0x21;
//     scalar_length_encoding[4] = 0xFF;

//     assert_eq!(
//         der_decode(&scalar_length_encoding).expect_err("invalid signature successfully decoded"),
//         CryptoError::SignatureDecodingError
//     );

//     // Empty signature
//     let empty_signature = Vec::new();

//     assert_eq!(
//         der_decode(&empty_signature).expect_err("invalid signature successfully decoded"),
//         CryptoError::SignatureDecodingError
//     );

//     // 1byte signature
//     let one_byte_sig = vec![0x30];

//     assert_eq!(
//         der_decode(&one_byte_sig).expect_err("invalid signature successfully decoded"),
//         CryptoError::SignatureDecodingError
//     );

//     // Another signature too long variation
//     let mut signature_too_long_2 = original_bytes.clone();
//     signature_too_long_2[1] += 0x01;
//     signature_too_long_2.extend_from_slice(&[0]);

//     assert_eq!(
//         der_decode(&signature_too_long_2).expect_err("invalid signature successfully decoded"),
//         CryptoError::SignatureDecodingError
//     );
// }

// #[test]
// fn test_der_encoding() {
//     let libcrux = LibcruxProvider::default();
//     let payload = vec![0u8];
//     let signature_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
//     let (sk, _) = signature_key_gen(signature_mode(signature_scheme).unwrap())
//         .expect("error generating sig keypair");
//     let signature = libcrux
//         .sign(signature_scheme, &payload, &sk)
//         .expect("error creating signature");

//     let raw_signature = der_decode(&signature).expect("error decoding a valid siganture");

//     // Now let's try to der encode various incomplete parts of it.

//     // Empty signature
//     let empty_signature = Vec::new();

//     assert_eq!(
//         der_encode(&empty_signature).expect_err("successfully encoded invalid raw signature"),
//         CryptoError::SignatureEncodingError
//     );

//     // Signature too long
//     let mut signature_too_long = raw_signature.clone();
//     signature_too_long.extend_from_slice(&raw_signature);

//     assert_eq!(
//         der_encode(&signature_too_long).expect_err("successfully encoded invalid raw signature"),
//         CryptoError::SignatureEncodingError
//     );

//     // Scalar consisting only of 0x00
//     let zero_scalar = vec![0x00; 2 * P256_SCALAR_LENGTH];

//     assert_eq!(
//         der_encode(&zero_scalar).expect_err("successfully encoded invalid raw signature"),
//         CryptoError::SignatureEncodingError
//     );
// }

impl OpenMlsRand for LibcruxProvider {
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
