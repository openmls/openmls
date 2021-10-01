//! # Native Rust Crypto Provider
//!
//! Use native Rust crypto for all operations.

// XXX: ed25519-dalek depends on an old version of rand.
//      https://github.com/dalek-cryptography/ed25519-dalek/issues/162
// extern crate ed25519_dalek;
extern crate rand_07;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Aes256Gcm, NewAead,
};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::Signer as DalekSigner;
use hkdf::Hkdf;
use p256::{
    ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey},
    EncodedPoint,
};
use rand_chacha::rand_core::OsRng;
use sha2::{Digest, Sha256, Sha512};

use crate::ciphersuite::{errors::CryptoError, AeadType, HashType, SignatureScheme};

pub(crate) fn supports(signature_scheme: SignatureScheme) -> Result<(), CryptoError> {
    match signature_scheme {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(()),
        SignatureScheme::ED25519 => Ok(()),
        _ => Err(CryptoError::UnsupportedSignatureScheme),
    }
}

pub(crate) fn hkdf_extract(
    hash_type: HashType,
    salt: &[u8],
    ikm: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match hash_type {
        HashType::Sha2_256 => Ok(Hkdf::<Sha256>::extract(Some(salt), ikm).0.as_slice().into()),
        HashType::Sha2_512 => Ok(Hkdf::<Sha512>::extract(Some(salt), ikm).0.as_slice().into()),
        _ => Err(CryptoError::UnsupportedKdf),
    }
}

pub(crate) fn hkdf_expand(
    hash_type: HashType,
    prk: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    match hash_type {
        HashType::Sha2_256 => {
            let hkdf =
                Hkdf::<Sha256>::from_prk(prk).map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
            let mut okm = vec![0u8; okm_len];
            hkdf.expand(info, &mut okm)
                .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
            Ok(okm)
        }
        HashType::Sha2_512 => {
            let hkdf =
                Hkdf::<Sha512>::from_prk(prk).map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
            let mut okm = vec![0u8; okm_len];
            hkdf.expand(info, &mut okm)
                .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
            Ok(okm)
        }
        _ => Err(CryptoError::UnsupportedKdf),
    }
}

pub(crate) fn hash(hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match hash_type {
        HashType::Sha2_256 => Ok(Sha256::digest(data).as_slice().into()),
        HashType::Sha2_512 => Ok(Sha512::digest(data).as_slice().into()),
        _ => Err(CryptoError::UnsupportedHashAlgorithm),
    }
}

pub(crate) fn aead_encrypt(
    alg: AeadType,
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
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
        _ => Err(CryptoError::UnsupportedAeadAlgorithm),
    }
}

pub(crate) fn aead_decrypt(
    alg: AeadType,
    key: &[u8],
    ct_tag: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
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
        _ => Err(CryptoError::UnsupportedAeadAlgorithm),
    }
}

/// Returns `(sk, pk)`
pub(crate) fn signature_key_gen(alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    match alg {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            let k = SigningKey::random(&mut OsRng);
            let pk = k.verifying_key().to_encoded_point(false).as_bytes().into();
            Ok((k.to_bytes().as_slice().into(), pk))
        }
        SignatureScheme::ED25519 => {
            let k = ed25519_dalek::Keypair::generate(&mut rand_07::rngs::OsRng).to_bytes();
            let pk = k[32..].to_vec();
            // full key here because we need it to sign...
            let sk_pk = k.into();
            Ok((sk_pk, pk))
        }
        _ => Err(CryptoError::UnsupportedSignatureScheme),
    }
}

pub(crate) fn verify_signature(
    alg: SignatureScheme,
    data: &[u8],
    pk: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
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
            if signature.len() != 64 {
                return Err(CryptoError::CryptoLibraryError);
            }
            let mut sig = [0u8; 64];
            sig.clone_from_slice(signature);
            k.verify_strict(data, &ed25519_dalek::Signature::new(sig))
                .map_err(|_| CryptoError::InvalidSignature)
        }
        _ => Err(CryptoError::UnsupportedSignatureScheme),
    }
}

pub(crate) fn sign(alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
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
