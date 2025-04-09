use std::sync::{Mutex, MutexGuard};

use libcrux::drbg::{Drbg, RngCore};
use libcrux::hpke::{self, HPKEConfig};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
    HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
};

use rand::CryptoRng;
use tls_codec::SecretVLBytes;

/// The libcrux-backed cryptography provider for OpenMLS
pub struct CryptoProvider {
    drbg: Mutex<Drbg>,
}

impl Default for CryptoProvider {
    fn default() -> Self {
        let mut seed = [0u8; 16];
        getrandom::getrandom(&mut seed).unwrap();
        Self {
            drbg: Mutex::new(
                Drbg::new_with_entropy(libcrux::digest::Algorithm::Sha256, &seed).unwrap(),
            ),
        }
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
        let out = libcrux_hkdf::extract(alg, salt, ikm);

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
                libcrux_hkdf::Error::OkmLengthTooLarge => CryptoError::HkdfOutputLengthInvalid,
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

        // only fails on wrong length
        let iv = libcrux::aead::Iv::new(nonce).map_err(|err| match err {
            libcrux::aead::InvalidArgumentError::InvalidIv => CryptoError::InvalidLength,
            _ => CryptoError::CryptoLibraryError,
        })?;

        // TODO: instead, use key generation from chachapoly crate
        // so that the length will be correct
        let key: &[u8; 32] = key.try_into().unwrap();

        let mut msg_ctx: Vec<u8> = vec![0; data.len() + 16];
        libcrux_chacha20poly1305::encrypt(key, data, &mut msg_ctx, aad, &iv.0)
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        Ok(msg_ctx)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // The only supported AeadType (as of openmls_traits v0.3.0) is ChaCha20Poly1305
        if !matches!(alg, AeadType::ChaCha20Poly1305) {
            return Err(CryptoError::UnsupportedAeadAlgorithm);
        }

        if ct_tag.len() < 16 || nonce.len() != 12 {
            return Err(CryptoError::InvalidLength);
        }

        let boundary = ct_tag.len() - 16;

        let mut ptext = vec![0; boundary];

        let iv = libcrux::aead::Iv::new(nonce).map_err(|_| CryptoError::InvalidLength)?;

        // TODO: instead, use key conversion from chachapoly crate, when available,
        // so that the length will be correct
        let key = key.try_into().unwrap();

        libcrux_chacha20poly1305::decrypt(&key, &mut ptext, ct_tag, aad, &iv.0).map_err(
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
            .drbg
            .lock()
            .map_err(|_| CryptoError::CryptoLibraryError)
            .map(GuardedRng)?;

        // TODO: replace with key generation from libcrux-ed25519 crate, once available
        libcrux::signature::key_gen(libcrux::signature::Algorithm::Ed25519, &mut rng)
            .map_err(|_| CryptoError::SigningError)
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

        let pk: &[u8; 32] = pk.try_into().map_err(|_| CryptoError::InvalidPublicKey)?;
        let sk: &[u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;

        libcrux_ed25519::verify(data, pk, sk).map_err(|e| match e {
            libcrux_ed25519::Error::InvalidSignature => CryptoError::InvalidSignature,
            _ => CryptoError::SigningError,
        })
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !matches!(alg, SignatureScheme::ED25519) {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }

        let key: &[u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidPublicKey)?;
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
        let config = hpke_config(config);
        let randomness = {
            let mut rng = self
                .drbg
                .lock()
                .map_err(|_| CryptoError::CryptoLibraryError)?;
            rng.generate_vec(libcrux::hpke::kem::Nsk(config.1))
                .map_err(|_| CryptoError::CryptoLibraryError)?
        };

        let pk_r = libcrux::hpke::kem::DeserializePublicKey(config.1, pk_r)
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        let libcrux::hpke::HPKECiphertext(kem_output, ciphertext) =
            libcrux::hpke::HpkeSeal(config, &pk_r, info, aad, ptxt, None, None, None, randomness)
                .map_err(|e| match e {
                hpke::errors::HpkeError::ValidationError => CryptoError::InvalidPublicKey,
                hpke::errors::HpkeError::UnsupportedAlgorithm => {
                    CryptoError::UnsupportedCiphersuite
                }
                hpke::errors::HpkeError::InvalidParameters => CryptoError::InvalidLength,
                _ => CryptoError::CryptoLibraryError,
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
        let ctxt = libcrux::hpke::HPKECiphertext(
            input.kem_output.as_ref().to_vec(),
            input.ciphertext.as_ref().to_vec(),
        );

        libcrux::hpke::HpkeOpen(config, &ctxt, sk_r, info, aad, None, None, None).map_err(|e| {
            match e {
                libcrux::hpke::errors::HpkeError::OpenError
                | libcrux::hpke::errors::HpkeError::DecapError
                | libcrux::hpke::errors::HpkeError::ValidationError => {
                    CryptoError::HpkeDecryptionError
                }
                _ => CryptoError::CryptoLibraryError,
            }
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
        let config = hpke_config(config);
        let randomness = self
            .drbg
            .lock()
            .map_err(|_| CryptoError::CryptoLibraryError)?
            .generate_vec(libcrux::hpke::kem::Nsk(config.1))
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        let pk_r = libcrux::hpke::kem::DeserializePublicKey(config.1, pk_r)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        let (enc, ctx) = libcrux::hpke::SetupBaseS(config, &pk_r, info, randomness)
            .map_err(|_| CryptoError::ReceiverSetupError)?;

        libcrux::hpke::Context_Export(config, &ctx, exporter_context.to_vec(), exporter_length)
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

        let ctx = libcrux::hpke::SetupBaseR(config, enc, sk_r, info)
            .map_err(|_| CryptoError::ReceiverSetupError)?;

        libcrux::hpke::Context_Export(config, &ctx, exporter_context.to_vec(), exporter_length)
            .map_err(|_| CryptoError::ExporterError)
            .map(ExporterSecret::from)
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        let config = hpke_config(config);
        let HPKEConfig(_, alg, _, _) = config;
        let (sk, pk) = hpke::kem::DeriveKeyPair(alg, ikm).map_err(|e| match e {
            hpke::errors::HpkeError::InvalidParameters => CryptoError::InvalidLength,
            _ => CryptoError::CryptoLibraryError,
        })?;

        Ok(HpkeKeyPair {
            private: sk.into(),
            public: hpke::kem::SerializePublicKey(alg, pk),
        })
    }
}

fn hkdf_alg(hash_type: HashType) -> libcrux_hkdf::Algorithm {
    match hash_type {
        HashType::Sha2_256 => libcrux_hkdf::Algorithm::Sha256,
        HashType::Sha2_384 => libcrux_hkdf::Algorithm::Sha384,
        HashType::Sha2_512 => libcrux_hkdf::Algorithm::Sha512,
    }
}

fn hpke_config(config: HpkeConfig) -> libcrux::hpke::HPKEConfig {
    libcrux::hpke::HPKEConfig(
        libcrux::hpke::Mode::mode_base,
        hpke_kem(config.0),
        hpke_kdf(config.1),
        hpke_aead(config.2),
    )
}

fn hpke_kdf(kdf: HpkeKdfType) -> libcrux::hpke::kdf::KDF {
    match kdf {
        HpkeKdfType::HkdfSha256 => libcrux::hpke::kdf::KDF::HKDF_SHA256,
        HpkeKdfType::HkdfSha384 => libcrux::hpke::kdf::KDF::HKDF_SHA384,
        HpkeKdfType::HkdfSha512 => libcrux::hpke::kdf::KDF::HKDF_SHA512,
    }
}

fn hpke_kem(kem: HpkeKemType) -> libcrux::hpke::kem::KEM {
    match kem {
        HpkeKemType::DhKemP256 => libcrux::hpke::kem::KEM::DHKEM_P256_HKDF_SHA256,
        HpkeKemType::DhKemP384 => libcrux::hpke::kem::KEM::DHKEM_P384_HKDF_SHA384,
        HpkeKemType::DhKemP521 => libcrux::hpke::kem::KEM::DHKEM_P521_HKDF_SHA512,
        HpkeKemType::DhKem25519 => libcrux::hpke::kem::KEM::DHKEM_X25519_HKDF_SHA256,
        HpkeKemType::DhKem448 => libcrux::hpke::kem::KEM::DHKEM_X448_HKDF_SHA512,
        HpkeKemType::XWingKemDraft2 => libcrux::hpke::kem::KEM::XWingDraft02,
    }
}

fn hpke_aead(aead: HpkeAeadType) -> libcrux::hpke::aead::AEAD {
    use libcrux::hpke::aead::AEAD as CruxAead;
    match aead {
        HpkeAeadType::AesGcm128 => CruxAead::AES_128_GCM,
        HpkeAeadType::AesGcm256 => CruxAead::AES_256_GCM,
        HpkeAeadType::ChaCha20Poly1305 => CruxAead::ChaCha20Poly1305,
        HpkeAeadType::Export => CruxAead::Export_only,
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

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl<Rng: RngCore + CryptoRng> CryptoRng for GuardedRng<'_, Rng> {}
