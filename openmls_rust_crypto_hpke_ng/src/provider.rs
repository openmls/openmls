use std::sync::RwLock;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Aes256Gcm, KeyInit,
};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::Signer;
use hkdf::Hkdf;
use hpke_ng::{
    Aes128Gcm as HpkeAes128Gcm, Aes256Gcm as HpkeAes256Gcm,
    ChaCha20Poly1305 as HpkeChaCha20Poly1305, DhKemP256HkdfSha256, DhKemP384HkdfSha384,
    DhKemP521HkdfSha512, DhKemX25519HkdfSha256, DhKemX448HkdfSha512, HkdfSha256, HkdfSha384,
    HkdfSha512, Hpke, HpkeError, Kem,
};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        self, AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType,
        HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, SignatureScheme,
    },
};
use p256::{
    ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey},
    EncodedPoint,
};
use rand_core::{RngCore as _, SeedableRng as _};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tls_codec::SecretVLBytes;

use crate::hmac;

#[derive(Debug)]
pub struct RustCrypto {
    rng: RwLock<rand_chacha::ChaCha20Rng>,
}

// For testing we want to clone.
// But really we just create a new Rng.
#[cfg(feature = "test-utils")]
impl Clone for RustCrypto {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl Default for RustCrypto {
    fn default() -> Self {
        Self {
            rng: RwLock::new(rand_chacha::ChaCha20Rng::from_entropy()),
        }
    }
}

/// Bridge from `rand_core` 0.6 to `rand_core` 0.9.
///
/// `rand_chacha` 0.3 (and `ed25519-dalek 2` / `p256 0.13`) speak `rand_core`
/// 0.6 traits; `hpke-ng` requires `rand_core` 0.9. The wrapper forwards the
/// three `RngCore` methods that 0.9 actually defines (no `try_fill_bytes`) and
/// re-asserts `CryptoRng`.
struct RngCompat09<'a, R: rand_core::RngCore + rand_core::CryptoRng>(&'a mut R);

impl<R: rand_core::RngCore + rand_core::CryptoRng> rand_core_09::RngCore for RngCompat09<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.fill_bytes(dst);
    }
}

impl<R: rand_core::RngCore + rand_core::CryptoRng> rand_core_09::CryptoRng for RngCompat09<'_, R> {}

/// Dispatch on `(kem, kdf, aead)` to the matching `hpke-ng` `Hpke<K, F, A>`.
///
/// Each arm declares two type aliases — `$kem` for `K` and `$suite` for the
/// fully-parameterized `Hpke<K, F, A>` — then evaluates `$body` with both in
/// scope. Only the 15 KEM-KDF-AEAD combinations whose KEM/KDF SHA sizes line
/// up are handled (these are the only ones that appear in real MLS
/// ciphersuites). `XWingKemDraft6` mirrors `openmls_rust_crypto`'s
/// `unimplemented!()`.
macro_rules! dispatch_hpke {
    ($config:expr, |$kem:ident, $suite:ident| $body:block) => {
        match ($config.0, $config.1, $config.2) {
            (HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                #[allow(dead_code)]
                type $kem = DhKemX25519HkdfSha256;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, HpkeAes128Gcm>;
                $body
            }
            (HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm256) => {
                #[allow(dead_code)]
                type $kem = DhKemX25519HkdfSha256;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, HpkeAes256Gcm>;
                $body
            }
            (HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
                #[allow(dead_code)]
                type $kem = DhKemX25519HkdfSha256;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemX25519HkdfSha256, HkdfSha256, HpkeChaCha20Poly1305>;
                $body
            }
            (HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                #[allow(dead_code)]
                type $kem = DhKemP256HkdfSha256;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemP256HkdfSha256, HkdfSha256, HpkeAes128Gcm>;
                $body
            }
            (HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm256) => {
                #[allow(dead_code)]
                type $kem = DhKemP256HkdfSha256;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemP256HkdfSha256, HkdfSha256, HpkeAes256Gcm>;
                $body
            }
            (HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
                #[allow(dead_code)]
                type $kem = DhKemP256HkdfSha256;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemP256HkdfSha256, HkdfSha256, HpkeChaCha20Poly1305>;
                $body
            }
            (HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm128) => {
                #[allow(dead_code)]
                type $kem = DhKemP384HkdfSha384;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemP384HkdfSha384, HkdfSha384, HpkeAes128Gcm>;
                $body
            }
            (HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
                #[allow(dead_code)]
                type $kem = DhKemP384HkdfSha384;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemP384HkdfSha384, HkdfSha384, HpkeAes256Gcm>;
                $body
            }
            (HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::ChaCha20Poly1305) => {
                #[allow(dead_code)]
                type $kem = DhKemP384HkdfSha384;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemP384HkdfSha384, HkdfSha384, HpkeChaCha20Poly1305>;
                $body
            }
            (HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm128) => {
                #[allow(dead_code)]
                type $kem = DhKemP521HkdfSha512;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemP521HkdfSha512, HkdfSha512, HpkeAes128Gcm>;
                $body
            }
            (HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm256) => {
                #[allow(dead_code)]
                type $kem = DhKemP521HkdfSha512;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemP521HkdfSha512, HkdfSha512, HpkeAes256Gcm>;
                $body
            }
            (HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::ChaCha20Poly1305) => {
                #[allow(dead_code)]
                type $kem = DhKemP521HkdfSha512;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemP521HkdfSha512, HkdfSha512, HpkeChaCha20Poly1305>;
                $body
            }
            (HpkeKemType::DhKem448, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm128) => {
                #[allow(dead_code)]
                type $kem = DhKemX448HkdfSha512;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemX448HkdfSha512, HkdfSha512, HpkeAes128Gcm>;
                $body
            }
            (HpkeKemType::DhKem448, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm256) => {
                #[allow(dead_code)]
                type $kem = DhKemX448HkdfSha512;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemX448HkdfSha512, HkdfSha512, HpkeAes256Gcm>;
                $body
            }
            (HpkeKemType::DhKem448, HpkeKdfType::HkdfSha512, HpkeAeadType::ChaCha20Poly1305) => {
                #[allow(dead_code)]
                type $kem = DhKemX448HkdfSha512;
                #[allow(dead_code)]
                type $suite = Hpke<DhKemX448HkdfSha512, HkdfSha512, HpkeChaCha20Poly1305>;
                $body
            }
            (HpkeKemType::XWingKemDraft6, _, _) => {
                unimplemented!("XWingKemDraft6 is not supported by the RustCrypto provider.")
            }
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    };
}

/// Mirrors the original provider's hpke-rs error mapping: only "the input was
/// the wrong shape" is `InvalidLength`; everything else is collapsed to the
/// generic library error.
fn map_seal_err(e: HpkeError) -> CryptoError {
    match e {
        HpkeError::InvalidPublicKey
        | HpkeError::InvalidPrivateKey
        | HpkeError::InvalidEncappedKey => CryptoError::InvalidLength,
        _ => CryptoError::CryptoLibraryError,
    }
}

fn map_derive_err(e: HpkeError) -> CryptoError {
    match e {
        HpkeError::DeriveKeyPairError | HpkeError::InvalidPrivateKey => CryptoError::InvalidLength,
        _ => CryptoError::CryptoLibraryError,
    }
}

impl OpenMlsCrypto for RustCrypto {
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

    fn hkdf_extract(
        &self,
        hash_type: openmls_traits::types::HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, openmls_traits::types::CryptoError> {
        #[allow(deprecated)]
        match hash_type {
            HashType::Sha2_256 => Ok(Hkdf::<Sha256>::extract(Some(salt), ikm).0.as_slice().into()),
            HashType::Sha2_384 => Ok(Hkdf::<Sha384>::extract(Some(salt), ikm).0.as_slice().into()),
            HashType::Sha2_512 => Ok(Hkdf::<Sha512>::extract(Some(salt), ikm).0.as_slice().into()),
        }
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        hmac::hmac(hash_type, key, message)
    }

    fn hkdf_expand(
        &self,
        hash_type: openmls_traits::types::HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => {
                let hkdf = Hkdf::<Sha256>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                Ok(okm.into())
            }
            HashType::Sha2_512 => {
                let hkdf = Hkdf::<Sha512>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                Ok(okm.into())
            }
            HashType::Sha2_384 => {
                let hkdf = Hkdf::<Sha384>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                Ok(okm.into())
            }
        }
    }

    fn hash(
        &self,
        hash_type: openmls_traits::types::HashType,
        data: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        #[allow(deprecated)]
        match hash_type {
            HashType::Sha2_256 => Ok(Sha256::digest(data).as_slice().into()),
            HashType::Sha2_384 => Ok(Sha384::digest(data).as_slice().into()),
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
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                chacha_poly
                    .encrypt(nonce.into(), Payload { msg: data, aad })
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
                aes.decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            AeadType::ChaCha20Poly1305 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                chacha_poly
                    .decrypt(nonce.into(), Payload { msg: ct_tag, aad })
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
                #[allow(deprecated)]
                Ok((k.to_bytes().as_slice().into(), pk))
            }
            SignatureScheme::ED25519 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let sk = ed25519_dalek::SigningKey::generate(&mut *rng);
                let pk = sk.verifying_key().to_bytes().into();
                Ok((sk.to_bytes().into(), pk))
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
                let k = ed25519_dalek::VerifyingKey::try_from(pk)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
                    return Err(CryptoError::CryptoLibraryError);
                }
                let mut sig = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
                sig.clone_from_slice(signature);
                k.verify_strict(data, &ed25519_dalek::Signature::from(sig))
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
                let k = SigningKey::from_bytes(key.into())
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: Signature = k.sign(data);
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::SigningKey::try_from(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature = k.sign(data);
                Ok(signature.to_bytes().into())
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<types::HpkeCiphertext, CryptoError> {
        let mut rng_guard = self
            .rng
            .write()
            .map_err(|_| CryptoError::InsufficientRandomness)?;
        let mut compat = RngCompat09(&mut *rng_guard);
        dispatch_hpke!(config, |K, Suite| {
            let pk = K::pk_from_bytes(pk_r).map_err(map_seal_err)?;
            let (enc, ciphertext) =
                Suite::seal_base(&mut compat, &pk, info, aad, ptxt).map_err(map_seal_err)?;
            Ok(HpkeCiphertext {
                kem_output: enc.as_ref().to_vec().into(),
                ciphertext: ciphertext.into(),
            })
        })
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &types::HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        dispatch_hpke!(config, |K, Suite| {
            let sk = K::sk_from_bytes(sk_r).map_err(|_| CryptoError::HpkeDecryptionError)?;
            let enc = K::enc_from_bytes(input.kem_output.as_slice())
                .map_err(|_| CryptoError::HpkeDecryptionError)?;
            Suite::open_base(&enc, &sk, info, aad, input.ciphertext.as_slice())
                .map_err(|_| CryptoError::HpkeDecryptionError)
        })
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(Vec<u8>, ExporterSecret), CryptoError> {
        let mut rng_guard = self
            .rng
            .write()
            .map_err(|_| CryptoError::InsufficientRandomness)?;
        let mut compat = RngCompat09(&mut *rng_guard);
        dispatch_hpke!(config, |K, Suite| {
            let pk = K::pk_from_bytes(pk_r).map_err(|_| CryptoError::SenderSetupError)?;
            let (enc, exporter) =
                Suite::send_export_base(&mut compat, &pk, info, exporter_context, exporter_length)
                    .map_err(|e| match e {
                        HpkeError::ExportLengthExceeded => CryptoError::ExporterError,
                        _ => CryptoError::SenderSetupError,
                    })?;
            Ok((enc.as_ref().to_vec(), exporter.into()))
        })
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
        dispatch_hpke!(config, |K, Suite| {
            let sk = K::sk_from_bytes(sk_r).map_err(|_| CryptoError::ReceiverSetupError)?;
            let enc = K::enc_from_bytes(enc).map_err(|_| CryptoError::ReceiverSetupError)?;
            let exporter =
                Suite::receiver_export_base(&enc, &sk, info, exporter_context, exporter_length)
                    .map_err(|e| match e {
                        HpkeError::ExportLengthExceeded => CryptoError::ExporterError,
                        _ => CryptoError::ReceiverSetupError,
                    })?;
            Ok(exporter.into())
        })
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<types::HpkeKeyPair, CryptoError> {
        dispatch_hpke!(config, |K, Suite| {
            // `Suite` is unused here — derivation happens on the KEM alone — but
            // the dispatch macro always declares both aliases. Mark it consumed
            // so `clippy::redundant_pub_crate` / `unused_type_aliases` stay
            // quiet without needing per-arm allow attributes.
            let _ = core::marker::PhantomData::<Suite>;
            let (sk, pk) = K::derive_key_pair(ikm).map_err(map_derive_err)?;
            Ok(HpkeKeyPair {
                private: K::sk_to_bytes(&sk).as_slice().into(),
                public: K::pk_to_bytes(&pk).as_slice().into(),
            })
        })
    }
}

impl OpenMlsRand for RustCrypto {
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
