//! # Evercrypt Crypto Provider
//!
//! Use evercrypt for all crypto operations.

use std::convert::TryFrom;

use evercrypt::prelude::*;
use log::error;

use crate::ciphersuite::{errors::CryptoError, AeadType, HashType, SignatureScheme};

impl TryFrom<SignatureScheme> for SignatureMode {
    type Error = &'static str;
    #[inline(always)]
    fn try_from(signature_scheme: SignatureScheme) -> Result<Self, Self::Error> {
        match signature_scheme {
            SignatureScheme::ED25519 => Ok(SignatureMode::Ed25519),
            SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(SignatureMode::P256),
            SignatureScheme::ED448 => Err("SignatureScheme ed448 is not supported."),
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                Err("SignatureScheme ecdsa_secp521r1 is not supported.")
            }
        }
    }
}

impl TryFrom<SignatureScheme> for DigestMode {
    type Error = &'static str;
    #[inline(always)]
    fn try_from(signature_scheme: SignatureScheme) -> Result<Self, Self::Error> {
        match signature_scheme {
            // The digest mode for ed25519 is not really used
            SignatureScheme::ED25519 => Ok(DigestMode::Sha256),
            SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(DigestMode::Sha256),
            SignatureScheme::ED448 => Err("SignatureScheme ed448 is not supported."),
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                Err("SignatureScheme ecdsa_secp521r1 is not supported.")
            }
        }
    }
}
#[inline(always)]
fn hash_from_algorithm(hash_type: HashType) -> Result<DigestMode, CryptoError> {
    Ok(match hash_type {
        HashType::Sha1 => DigestMode::Sha1,
        HashType::Sha2_224 => DigestMode::Sha224,
        HashType::Sha2_256 => DigestMode::Sha256,
        HashType::Sha2_384 => DigestMode::Sha384,
        HashType::Sha2_512 => DigestMode::Sha512,
        HashType::Sha3_224 => DigestMode::Sha3_224,
        HashType::Sha3_256 => DigestMode::Sha3_256,
        HashType::Sha3_384 => DigestMode::Sha3_384,
        HashType::Sha3_512 => DigestMode::Sha3_512,
        _ => return Err(CryptoError::UnsupportedHashAlgorithm),
    })
}

#[inline(always)]
fn aead_from_algorithm(alg: AeadType) -> Result<AeadMode, CryptoError> {
    match alg {
        AeadType::Aes128Gcm => Ok(AeadMode::Aes128Gcm),
        AeadType::Aes256Gcm => Ok(AeadMode::Aes256Gcm),
        AeadType::ChaCha20Poly1305 => Ok(AeadMode::Chacha20Poly1305),
        AeadType::HpkeExport => Err(CryptoError::UnsupportedAeadAlgorithm),
    }
}

#[inline(always)]
fn hmac_from_hash(hash_type: HashType) -> Result<HmacMode, CryptoError> {
    Ok(match hash_type {
        HashType::Sha1 => HmacMode::Sha1,
        HashType::Sha2_256 => HmacMode::Sha256,
        HashType::Sha2_384 => HmacMode::Sha384,
        HashType::Sha2_512 => HmacMode::Sha512,
        _ => return Err(CryptoError::UnsupportedKdf),
    })
}

pub(crate) fn supports(signature_scheme: SignatureScheme) -> Result<(), CryptoError> {
    if SignatureMode::try_from(signature_scheme).is_err() {
        Err(CryptoError::UnsupportedSignatureScheme)
    } else if DigestMode::try_from(signature_scheme).is_err() {
        Err(CryptoError::UnsupportedSignatureScheme)
    } else {
        Ok(())
    }
}

pub(crate) fn hkdf_extract(
    hash_type: HashType,
    salt: &[u8],
    ikm: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let hmac = hmac_from_hash(hash_type)?;
    Ok(hkdf::extract(hmac, salt, ikm))
}

pub(crate) fn hkdf_expand(
    hash_type: HashType,
    prk: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hmac = hmac_from_hash(hash_type)?;
    Ok(hkdf::expand(hmac, prk, info, okm_len))
}

pub(crate) fn hash(hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let alg = hash_from_algorithm(hash_type)?;
    Ok(evercrypt::digest::hash(alg, data))
}

pub(crate) fn aead_encrypt(
    alg: AeadType,
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let alg = aead_from_algorithm(alg)?;
    aead::encrypt_combined(alg, key, data, nonce, aad).map_err(|_| CryptoError::CryptoLibraryError)
}

pub(crate) fn aead_decrypt(
    alg: AeadType,
    key: &[u8],
    ct_tag: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let alg = aead_from_algorithm(alg)?;
    aead_decrypt_combined(alg, key, ct_tag, nonce, aad).map_err(|_| CryptoError::CryptoLibraryError)
}

/// Returns `(sk, pk)`
pub(crate) fn signature_key_gen(alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let signature_mode = match SignatureMode::try_from(alg) {
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

pub(crate) fn verify_signature(
    alg: SignatureScheme,
    data: &[u8],
    pk: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let signature_mode = match SignatureMode::try_from(alg) {
        Ok(signature_mode) => signature_mode,
        Err(_) => return Err(CryptoError::UnsupportedSignatureScheme),
    };
    let digest_mode = match DigestMode::try_from(alg) {
        Ok(dm) => dm,
        Err(_) => return Err(CryptoError::UnsupportedSignatureScheme),
    };
    if verify(signature_mode, digest_mode, pk, signature, data)
        .map_err(|_| CryptoError::InvalidSignature)?
    {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

pub(crate) fn sign(alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature_mode = match SignatureMode::try_from(alg) {
        Ok(signature_mode) => signature_mode,
        Err(_) => return Err(CryptoError::UnsupportedSignatureScheme),
    };
    let (hash, nonce) = match signature_mode {
        SignatureMode::Ed25519 => (None, None),
        SignatureMode::P256 => (
            Some(DigestMode::try_from(alg).unwrap()),
            Some(p256_ecdsa_random_nonce().unwrap()),
        ),
    };
    evercrypt::signature::sign(signature_mode, hash, key, data, nonce.as_ref())
        .map_err(|_| CryptoError::CryptoLibraryError)
}
