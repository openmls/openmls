use hpke_rs_libcrux::HpkeLibcrux;

use std::sync::{Mutex, MutexGuard};

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
    HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
};

use rand::{rngs::OsRng, rngs::ReseedingRng, CryptoRng, RngCore};
use rand_chacha::ChaCha20Core;

use tls_codec::SecretVLBytes;

/// The libcrux-backed cryptography provider for OpenMLS
pub struct CryptoProvider {
    pub(super) rng: Mutex<ReseedingRng<ChaCha20Core, OsRng>>,
}

impl CryptoProvider {
    /// Instantiate a libcrux-based CryptoProvider
    pub fn new() -> Result<Self, CryptoError> {
        let reseeding_rng = ReseedingRng::<ChaCha20Core, _>::new(0x100000000, OsRng)
            .map_err(|_| CryptoError::InsufficientRandomness)?;

        Ok(Self {
            rng: Mutex::new(reseeding_rng),
        })
    }
}

impl OpenMlsCrypto for CryptoProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite.aead_algorithm() {
            AeadType::ChaCha20Poly1305 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }?;

        match ciphersuite.signature_algorithm() {
            SignatureScheme::ED25519 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }?;

        match ciphersuite.hash_algorithm() {
            HashType::Sha2_256 | HashType::Sha2_384 | HashType::Sha2_512 => Ok(()),
        }?;

        match ciphersuite.hpke_aead_algorithm() {
            HpkeAeadType::ChaCha20Poly1305 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }?;

        Ok(())
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
        ]
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        let alg = hkdf_alg(hash_type);
        let out = libcrux_hkdf::extract(alg, salt, ikm).map_err(|e| match e {
            libcrux_hkdf::Error::ArgumentsTooLarge => CryptoError::InvalidLength,
            _ => CryptoError::CryptoLibraryError,
        })?;

        Ok(out.into())
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        let alg = hkdf_alg(hash_type);

        libcrux_hkdf::expand(alg, prk, info, okm_len)
            .map_err(|e| match e {
                libcrux_hkdf::Error::OkmTooLarge => CryptoError::HkdfOutputLengthInvalid,
                libcrux_hkdf::Error::ArgumentsTooLarge => CryptoError::InvalidLength,
            })
            .map(<Vec<u8> as Into<SecretVLBytes>>::into)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let out = match hash_type {
            HashType::Sha2_256 => libcrux_sha2::sha256(data).to_vec(),
            HashType::Sha2_384 => libcrux_sha2::sha384(data).to_vec(),
            HashType::Sha2_512 => libcrux_sha2::sha512(data).to_vec(),
        };

        Ok(out)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // The only supported AeadType (as of openmls_traits v0.3.0) is ChaCha20Poly1305
        if !matches!(alg, AeadType::ChaCha20Poly1305) {
            return Err(CryptoError::UnsupportedAeadAlgorithm);
        }

        use libcrux_chacha20poly1305::TAG_LEN;

        // only fails on wrong length
        let iv = <&[u8; 12]>::try_from(nonce).map_err(|_| CryptoError::InvalidLength)?;

        let key = <&[u8; 32]>::try_from(key).map_err(|_| CryptoError::InvalidLength)?;

        let mut msg_ctxt: Vec<u8> = vec![0; data.len() + TAG_LEN];
        libcrux_chacha20poly1305::encrypt(key, data, &mut msg_ctxt, aad, iv)
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        Ok(msg_ctxt)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // The only supported AeadType (as of openmls_traits v0.4.0) is ChaCha20Poly1305
        if !matches!(alg, AeadType::ChaCha20Poly1305) {
            return Err(CryptoError::UnsupportedAeadAlgorithm);
        }
        use libcrux_chacha20poly1305::TAG_LEN;

        if ct_tag.len() < TAG_LEN {
            return Err(CryptoError::InvalidLength);
        }

        let boundary = ct_tag.len() - TAG_LEN;

        let mut ptext = vec![0; boundary];

        let iv = <&[u8; 12]>::try_from(nonce).map_err(|_| CryptoError::InvalidLength)?;

        let key = <&[u8; 32]>::try_from(key).map_err(|_| CryptoError::InvalidLength)?;

        libcrux_chacha20poly1305::decrypt(key, &mut ptext, ct_tag, aad, iv).map_err(
            |e| match e {
                libcrux_chacha20poly1305::AeadError::InvalidCiphertext => {
                    CryptoError::AeadDecryptionError
                }
                _ => CryptoError::CryptoLibraryError,
            },
        )?;

        Ok(ptext)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if !matches!(alg, SignatureScheme::ED25519) {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }

        let mut rng = self
            .rng
            .lock()
            .map_err(|_| CryptoError::CryptoLibraryError)
            .map(GuardedRng)?;

        libcrux_ed25519::generate_key_pair(&mut rng)
            .map_err(|_| CryptoError::SigningError)
            .map(|(signing_key, verification_key)| {
                (
                    signing_key.into_bytes().to_vec(),
                    verification_key.into_bytes().to_vec(),
                )
            })
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if !matches!(alg, SignatureScheme::ED25519) {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }

        let pk = <&[u8; 32]>::try_from(pk).map_err(|_| CryptoError::InvalidLength)?;
        let sk = <&[u8; 64]>::try_from(signature).map_err(|_| CryptoError::InvalidLength)?;

        libcrux_ed25519::verify(data, pk, sk).map_err(|e| match e {
            libcrux_ed25519::Error::InvalidSignature => CryptoError::InvalidSignature,
            _ => CryptoError::SigningError,
        })
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !matches!(alg, SignatureScheme::ED25519) {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }

        let key = <&[u8; 32]>::try_from(key).map_err(|_| CryptoError::InvalidLength)?;
        libcrux_ed25519::sign(data, key)
            .map_err(|_| CryptoError::SigningError)
            .map(|sig| sig.to_vec())
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        let mut config = hpke_config(config);

        let pk_r = hpke_rs::HpkePublicKey::new(pk_r.to_vec());

        let (kem_output, ciphertext) = config
            .seal(&pk_r, info, aad, ptxt, None, None, None)
            .map_err(|e| match e {
                hpke_rs::HpkeError::InvalidConfig => CryptoError::SenderSetupError,
                _ => CryptoError::HpkeEncryptionError,
            })?;

        let kem_output = kem_output.into();
        let ciphertext = ciphertext.into();

        Ok(HpkeCiphertext {
            kem_output,
            ciphertext,
        })
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let config = hpke_config(config);

        let sk_r = hpke_rs::HpkePrivateKey::new(sk_r.to_vec());

        config
            .open(
                input.kem_output.as_ref(),
                &sk_r,
                info,
                aad,
                input.ciphertext.as_ref(),
                None,
                None,
                None,
            )
            .map_err(|e| match e {
                hpke_rs::HpkeError::InvalidConfig => CryptoError::ReceiverSetupError,
                _ => CryptoError::HpkeDecryptionError,
            })
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        let mut config = hpke_config(config);

        let pk_r = hpke_rs::HpkePublicKey::new(pk_r.to_vec());

        let (enc, ctx) = config
            .setup_sender(&pk_r, info, None, None, None)
            .map_err(|_| CryptoError::SenderSetupError)?;

        ctx.export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)
            .map(|exported| (enc, exported.into()))
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
        let config = hpke_config(config);

        let sk_r = hpke_rs::HpkePrivateKey::new(sk_r.to_vec());

        let ctx = config
            .setup_receiver(enc, &sk_r, info, None, None, None)
            .map_err(|_| CryptoError::ReceiverSetupError)?;

        ctx.export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)
            .map(ExporterSecret::from)
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        let config = hpke_config(config);

        let key_pair: hpke_rs::HpkeKeyPair = config.derive_key_pair(ikm).map_err(|e| match e {
            hpke_rs::HpkeError::InvalidConfig => CryptoError::InvalidLength,
            _ => CryptoError::CryptoLibraryError,
        })?;

        let (sk, pk) = key_pair.into_keys();

        Ok(HpkeKeyPair {
            private: sk.as_slice().to_vec().into(),
            public: pk.as_slice().to_vec(),
        })
    }
}

fn hpke_config(config: HpkeConfig) -> hpke_rs::Hpke<HpkeLibcrux> {
    let kem = hpke_kem(config.0);
    let kdf = hpke_kdf(config.1);
    let aead = hpke_aead(config.2);

    hpke_rs::Hpke::new(hpke_rs::Mode::Base, kem, kdf, aead)
}

fn hpke_kdf(kdf: HpkeKdfType) -> hpke_rs_crypto::types::KdfAlgorithm {
    match kdf {
        HpkeKdfType::HkdfSha256 => hpke_rs_crypto::types::KdfAlgorithm::HkdfSha256,
        HpkeKdfType::HkdfSha384 => hpke_rs_crypto::types::KdfAlgorithm::HkdfSha384,
        HpkeKdfType::HkdfSha512 => hpke_rs_crypto::types::KdfAlgorithm::HkdfSha512,
    }
}

fn hpke_kem(kem: HpkeKemType) -> hpke_rs_crypto::types::KemAlgorithm {
    match kem {
        HpkeKemType::DhKemP256 => hpke_rs_crypto::types::KemAlgorithm::DhKemP256,
        HpkeKemType::DhKemP384 => hpke_rs_crypto::types::KemAlgorithm::DhKemP384,
        HpkeKemType::DhKemP521 => hpke_rs_crypto::types::KemAlgorithm::DhKemP521,
        HpkeKemType::DhKem25519 => hpke_rs_crypto::types::KemAlgorithm::DhKem25519,
        HpkeKemType::DhKem448 => hpke_rs_crypto::types::KemAlgorithm::DhKem448,
        HpkeKemType::XWingKemDraft6 => hpke_rs_crypto::types::KemAlgorithm::XWingDraft06,
    }
}

fn hpke_aead(aead: HpkeAeadType) -> hpke_rs_crypto::types::AeadAlgorithm {
    match aead {
        HpkeAeadType::AesGcm128 => hpke_rs_crypto::types::AeadAlgorithm::Aes128Gcm,
        HpkeAeadType::AesGcm256 => hpke_rs_crypto::types::AeadAlgorithm::Aes256Gcm,
        HpkeAeadType::ChaCha20Poly1305 => hpke_rs_crypto::types::AeadAlgorithm::ChaCha20Poly1305,
        HpkeAeadType::Export => hpke_rs_crypto::types::AeadAlgorithm::HpkeExport,
    }
}

fn hkdf_alg(hash_type: HashType) -> libcrux_hkdf::Algorithm {
    match hash_type {
        HashType::Sha2_256 => libcrux_hkdf::Algorithm::Sha256,
        HashType::Sha2_384 => libcrux_hkdf::Algorithm::Sha384,
        HashType::Sha2_512 => libcrux_hkdf::Algorithm::Sha512,
    }
}
struct GuardedRng<'a, Rng: RngCore>(MutexGuard<'a, Rng>);

impl<Rng: RngCore> RngCore for GuardedRng<'_, Rng> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
}

impl<Rng: RngCore + CryptoRng> CryptoRng for GuardedRng<'_, Rng> {}
