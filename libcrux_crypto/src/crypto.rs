use hpke_rs_libcrux::HpkeLibcrux;

use std::sync::Mutex;

#[cfg(feature = "targeted-messages-draft")]
use openmls_traits::crypto::HpkeSealPskResolvedAadError;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
    HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
};

use libcrux_hmac_drbg::{HmacDrbgSha256, MAX_GENERATE_BYTES};
use rand::rngs::SysRng;

use tls_codec::SecretVLBytes;

/// Application-specific personalization string mixed into the HMAC-DRBG seed.
const PERSONALIZATION: &[u8] = b"openmls-libcrux-hmac-drbg-v1";

/// The libcrux-backed cryptography provider for OpenMLS
pub struct CryptoProvider {
    pub(super) rng: Mutex<HmacDrbgSha256>,
}

impl CryptoProvider {
    /// Instantiate a libcrux-based CryptoProvider
    pub fn new() -> Result<Self, CryptoError> {
        // Seed the HMAC-DRBG from the operating system's entropy source.
        let drbg = HmacDrbgSha256::new_from_sys_rng(PERSONALIZATION)
            .map_err(|_| CryptoError::InsufficientRandomness)?;

        Ok(Self {
            rng: Mutex::new(drbg),
        })
    }

    /// Fill `out` with fresh randomness from the HMAC-DRBG.
    ///
    /// Reseeds from the operating system's entropy source when the DRBG's
    /// reseed interval is reached, and splits requests larger than
    /// [`MAX_GENERATE_BYTES`] into multiple `generate` calls. Any failure to
    /// obtain OS entropy for a reseed is propagated rather than panicking.
    pub(super) fn fill_random(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        let mut drbg = self
            .rng
            .lock()
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        for chunk in out.chunks_mut(MAX_GENERATE_BYTES) {
            if drbg.needs_reseed() {
                drbg.reseed_from_rng(&mut SysRng, &[])
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
            }
            drbg.generate(chunk, &[])
                .map_err(|_| CryptoError::InsufficientRandomness)?;
        }

        Ok(())
    }
}

impl OpenMlsCrypto for CryptoProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite.aead_algorithm() {
            AeadType::ChaCha20Poly1305 | AeadType::Aes128Gcm | AeadType::Aes256Gcm => Ok(()),
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
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            // TODO: enable
            //Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        ]
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        let alg = hkdf_alg(hash_type);

        let mut prk = vec![0u8; alg.hash_len()];

        libcrux_hkdf::extract(alg, &mut prk, salt, ikm)
            .map_err(|e| match e {
                libcrux_hkdf::ExtractError::ArgumentTooLong => CryptoError::InvalidLength,
                _ => CryptoError::CryptoLibraryError,
            })
            .map(|_| prk.into())
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        let alg = hash_alg(hash_type);
        let out = libcrux_hmac::hmac(alg, key, message, None);
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

        let mut okm = vec![0u8; okm_len];

        libcrux_hkdf::expand(alg, &mut okm, prk, info)
            .map_err(|e| match e {
                libcrux_hkdf::ExpandError::OutputTooLong => CryptoError::HkdfOutputLengthInvalid,
                libcrux_hkdf::ExpandError::ArgumentTooLong => CryptoError::InvalidLength,
                // TODO: Potentially extend `CryptoError` with a variant for the `PrkTooShort` case
                libcrux_hkdf::ExpandError::PrkTooShort => CryptoError::InvalidLength,
                libcrux_hkdf::ExpandError::Unknown => CryptoError::CryptoLibraryError,
            })
            .map(|_| okm.into())
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
        let alg = aead_alg(alg);

        use libcrux_traits::aead::typed_refs::Aead as _;

        // set up buffers for ptxt, ctxt and tag
        let mut msg_ctxt: Vec<u8> = vec![0; data.len() + alg.tag_len()];
        let (msg, tag) = msg_ctxt.split_at_mut(data.len());

        // set up nonce
        let nonce = alg
            .new_nonce(nonce)
            .map_err(|_| CryptoError::InvalidLength)?;

        // set up key
        let key = alg.new_key(key).map_err(|_| CryptoError::InvalidLength)?;

        // set up tag
        let tag = alg
            .new_tag_mut(tag)
            .map_err(|_| CryptoError::InvalidLength)?;

        key.encrypt(msg, tag, nonce, aad, data)
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
        let alg = aead_alg(alg);

        use libcrux_traits::aead::typed_refs::{Aead as _, DecryptError};

        if ct_tag.len() < alg.tag_len() {
            return Err(CryptoError::InvalidLength);
        }

        let boundary = ct_tag.len() - alg.tag_len();

        // set up buffers for ptext, ctext, and tag
        let mut ptext = vec![0; boundary];
        let (ctext, tag) = ct_tag.split_at(boundary);

        // set up nonce
        let nonce = alg
            .new_nonce(nonce)
            .map_err(|_| CryptoError::InvalidLength)?;

        // set up key
        let key = alg.new_key(key).map_err(|_| CryptoError::InvalidLength)?;

        // set up tag
        let tag = alg.new_tag(tag).map_err(|_| CryptoError::InvalidLength)?;

        key.decrypt(&mut ptext, nonce, aad, ctext, tag)
            .map_err(|e| match e {
                DecryptError::InvalidTag => CryptoError::AeadDecryptionError,
                DecryptError::AadTooLong => CryptoError::InvalidLength,

                _ => CryptoError::CryptoLibraryError,
            })?;

        Ok(ptext)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if !matches!(alg, SignatureScheme::ED25519) {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }

        // Ed25519 key generation is just sampling a non-zero 32-byte secret and
        // deriving the public point. We do it here (rather than via
        // `libcrux_ed25519::generate_key_pair`, which requires an infallible
        // `CryptoRng`) so that a DRBG reseed failure is propagated as an error.
        const LIMIT: usize = 100;
        let mut sk = [0u8; 32];
        let mut found = false;
        for _ in 0..LIMIT {
            self.fill_random(&mut sk)?;
            // Reject the all-zero secret key.
            if sk.iter().any(|&b| b != 0) {
                found = true;
                break;
            }
        }
        if !found {
            return Err(CryptoError::SigningError);
        }

        let mut pk = [0u8; 32];
        libcrux_ed25519::secret_to_public(&mut pk, &sk);

        Ok((sk.to_vec(), pk.to_vec()))
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

    #[cfg(feature = "targeted-messages-draft")]
    fn hpke_open_psk(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        hpke_psk_from_config(config)
            .open(
                input.kem_output.as_slice(),
                &sk_r.into(),
                info,
                aad,
                input.ciphertext.as_slice(),
                Some(psk),
                Some(psk_id),
                None,
            )
            .map_err(|_| CryptoError::HpkeDecryptionError)
    }

    #[cfg(feature = "targeted-messages-draft")]
    fn hpke_seal_psk_resolved_aad<F, E>(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        ptxt: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        aad_builder: F,
    ) -> Result<HpkeCiphertext, HpkeSealPskResolvedAadError<E>>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    {
        let mut hpke = hpke_psk_from_config(config);
        // Split the single-shot seal into setup and seal so the AAD can be built
        // from the KEM output. The setup and seal must share the same context.
        let (kem_output, mut context) = hpke
            .setup_sender(&pk_r.into(), info, Some(psk), Some(psk_id), None)
            .map_err(|_| HpkeSealPskResolvedAadError::CryptoError(CryptoError::SenderSetupError))?;
        let aad = aad_builder(kem_output.as_slice())
            .map_err(HpkeSealPskResolvedAadError::AadBuildError)?;
        let ciphertext = context.seal(&aad, ptxt).map_err(|e| match e {
            hpke_rs::HpkeError::InvalidInput => {
                HpkeSealPskResolvedAadError::CryptoError(CryptoError::InvalidLength)
            }
            hpke_rs::HpkeError::InsufficientRandomness => {
                HpkeSealPskResolvedAadError::CryptoError(CryptoError::InsufficientRandomness)
            }
            _ => HpkeSealPskResolvedAadError::CryptoError(CryptoError::HpkeEncryptionError),
        })?;
        Ok(HpkeCiphertext {
            kem_output: kem_output.into(),
            ciphertext: ciphertext.into(),
        })
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn ff1_aes128_encrypt(&self, key: &[u8; 16], plaintext: u32) -> Result<u32, CryptoError> {
        crate::ff1::encrypt(key, plaintext)
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn ff1_aes128_decrypt(&self, key: &[u8; 16], ciphertext: u32) -> Result<u32, CryptoError> {
        crate::ff1::decrypt(key, ciphertext)
    }
}

fn hpke_config(config: HpkeConfig) -> hpke_rs::Hpke<HpkeLibcrux> {
    let kem = hpke_kem(config.0);
    let kdf = hpke_kdf(config.1);
    let aead = hpke_aead(config.2);

    hpke_rs::Hpke::new(hpke_rs::Mode::Base, kem, kdf, aead)
}

#[cfg(feature = "targeted-messages-draft")]
fn hpke_psk_from_config(config: HpkeConfig) -> hpke_rs::Hpke<HpkeLibcrux> {
    let kem = hpke_kem(config.0);
    let kdf = hpke_kdf(config.1);
    let aead = hpke_aead(config.2);

    hpke_rs::Hpke::new(hpke_rs::Mode::Psk, kem, kdf, aead)
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
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        HpkeKemType::XWingKemDraft6 => hpke_rs_crypto::types::KemAlgorithm::XWingDraft06,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        HpkeKemType::MlKem768 => hpke_rs_crypto::types::KemAlgorithm::MlKem768,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        HpkeKemType::MlKem1024 => hpke_rs_crypto::types::KemAlgorithm::MlKem1024,
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

fn hash_alg(hash_type: HashType) -> libcrux_hmac::Algorithm {
    match hash_type {
        HashType::Sha2_256 => libcrux_hmac::Algorithm::Sha256,
        HashType::Sha2_384 => libcrux_hmac::Algorithm::Sha384,
        HashType::Sha2_512 => libcrux_hmac::Algorithm::Sha512,
    }
}

fn aead_alg(alg_type: AeadType) -> libcrux_aead::Aead {
    match alg_type {
        AeadType::ChaCha20Poly1305 => libcrux_aead::Aead::ChaCha20Poly1305,
        AeadType::Aes128Gcm => libcrux_aead::Aead::AesGcm128,
        AeadType::Aes256Gcm => libcrux_aead::Aead::AesGcm256,
    }
}
