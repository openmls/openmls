use std::sync::{RwLock, RwLockWriteGuard};

use libcrux::drbg::{Drbg, RngCore};
use libcrux::hpke::{self, HPKECiphertext, HPKEConfig};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
    HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
};

use rand::CryptoRng;
use tls_codec::SecretVLBytes;

const MAX_DATA_LEN: usize = 0x10000000;

pub struct CryptoProvider {
    drbg: RwLock<Drbg>,
}

impl Default for CryptoProvider {
    fn default() -> Self {
        let mut seed = [0u8; 64];
        getrandom::getrandom(&mut seed).unwrap();
        Self {
            drbg: RwLock::new(
                Drbg::new_with_entropy(libcrux::digest::Algorithm::Sha256, &seed).unwrap(),
            ),
        }
    }
}

impl OpenMlsCrypto for CryptoProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match (ciphersuite.aead_algorithm(), libcrux::aes_ni_support()) {
            (AeadType::Aes128Gcm, true)
            | (AeadType::Aes256Gcm, true)
            | (AeadType::ChaCha20Poly1305, true)
            | (AeadType::ChaCha20Poly1305, false) => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }?;

        match ciphersuite.signature_algorithm() {
            SignatureScheme::ECDSA_SECP256R1_SHA256 | SignatureScheme::ED25519 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }?;

        match ciphersuite.hash_algorithm() {
            HashType::Sha2_256 | HashType::Sha2_384 | HashType::Sha2_512 => Ok(()),
        }?;

        match ciphersuite.hpke_aead_algorithm() {
            HpkeAeadType::ChaCha20Poly1305 => Ok(()),
            HpkeAeadType::AesGcm128 | HpkeAeadType::AesGcm256 if libcrux::aes_ni_support() => {
                Ok(())
            }
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }?;

        Ok(())
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        if libcrux::aes_ni_support() {
            vec![
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            ]
        } else {
            vec![Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519]
        }
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        let alg = hkdf_alg(hash_type);
        let out = libcrux::hkdf::extract(alg, salt, ikm);

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

        libcrux::hkdf::expand(alg, prk, info, okm_len)
            .map_err(|e| match e {
                libcrux::hkdf::Error::OkmLengthTooLarge => CryptoError::HkdfOutputLengthInvalid,
            })
            .map(<Vec<u8> as Into<SecretVLBytes>>::into)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let out = match hash_type {
            HashType::Sha2_256 => libcrux::digest::sha2_256(data).to_vec(),
            HashType::Sha2_384 => libcrux::digest::sha2_384(data).to_vec(),
            HashType::Sha2_512 => libcrux::digest::sha2_512(data).to_vec(),
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
        if data.len() > MAX_DATA_LEN {
            return Err(CryptoError::TooMuchData);
        }

        // only fails on wrong length
        let iv = libcrux::aead::Iv::new(nonce).map_err(|_| CryptoError::InvalidLength)?;
        let key = aead_key(alg, key)?;

        let mut msg_ctx: Vec<u8> = data.to_vec();
        let tag = libcrux::aead::encrypt(&key, &mut msg_ctx, iv, aad).map_err(|e| match e {
            libcrux::aead::Error::UnsupportedAlgorithm => CryptoError::UnsupportedAeadAlgorithm,
            libcrux::aead::Error::EncryptionError => CryptoError::CryptoLibraryError,
            _ => unreachable!(),
        })?;

        msg_ctx.extend_from_slice(tag.as_ref());
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
        if ct_tag.len() < 16 {
            return Err(CryptoError::AeadDecryptionError);
        }

        // TODO better way to split these?
        let boundary = ct_tag.len() - 16;
        let mut c = ct_tag[..boundary].to_vec();
        let tag = &ct_tag[boundary..];

        let iv = libcrux::aead::Iv::new(nonce).map_err(|_| CryptoError::InvalidLength)?;
        let key = aead_key(alg, key)?;
        let tag = libcrux::aead::Tag::from_slice(tag).expect("failed despite correct length");

        libcrux::aead::decrypt(&key, &mut c, iv, aad, &tag).map_err(|e| match e {
            libcrux::aead::Error::UnsupportedAlgorithm => CryptoError::UnsupportedAeadAlgorithm,
            libcrux::aead::Error::EncryptionError => CryptoError::AeadDecryptionError,
            libcrux::aead::Error::DecryptionFailed => CryptoError::AeadDecryptionError,
            _ => unreachable!(),
        })?;

        Ok(c)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let alg = sig_alg(alg)?;
        let mut rng = self
            .drbg
            .write()
            .map_err(|_| CryptoError::CryptoLibraryError)
            .map(GuardedRng)?;

        libcrux::signature::key_gen(alg, &mut rng).map_err(|_| CryptoError::SigningError)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let signature = sig(alg, signature)?;
        libcrux::signature::verify(data, &signature, pk).map_err(|_| CryptoError::InvalidSignature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let alg = sig_alg(alg)?;
        let drbg = self
            .drbg
            .write()
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        libcrux::signature::sign(alg, data, key, &mut GuardedRng(drbg))
            .map_err(|_| CryptoError::SigningError)
            .map(|sig| sig.into_vec())
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> HpkeCiphertext {
        let config = hpke_config(config);
        let randomness = vec![];

        let libcrux::hpke::HPKECiphertext(kem_output, ciphertext) =
            libcrux::hpke::HpkeSeal(config, pk_r, info, aad, ptxt, None, None, None, randomness)
                .map_err(|e| match e {
                    libcrux::hpke::errors::HpkeError::ValidationError => {
                        CryptoError::InvalidPublicKey
                    }
                    libcrux::hpke::errors::HpkeError::EncapError => {
                        CryptoError::HpkeEncryptionError
                    }
                    libcrux::hpke::errors::HpkeError::UnsupportedAlgorithm => {
                        CryptoError::CryptoLibraryError
                    }
                    libcrux::hpke::errors::HpkeError::InvalidParameters => {
                        CryptoError::CryptoLibraryError
                    }
                    libcrux::hpke::errors::HpkeError::CryptoError => {
                        CryptoError::CryptoLibraryError
                    }
                    _ => todo!(),
                })
                .unwrap();

        let kem_output = kem_output.into();
        let ciphertext = ciphertext.into();

        HpkeCiphertext {
            kem_output,
            ciphertext,
        }
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
                libcrux::hpke::errors::HpkeError::DeriveKeyPairError
                | libcrux::hpke::errors::HpkeError::UnsupportedAlgorithm
                | libcrux::hpke::errors::HpkeError::InvalidParameters
                | libcrux::hpke::errors::HpkeError::CryptoError => CryptoError::CryptoLibraryError,
                _ => unreachable!(),
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
            .write()
            .map_err(|_| CryptoError::CryptoLibraryError)?
            .generate_vec(libcrux::hpke::kem::Nsk(config.1))
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        libcrux::hpke::SendExport(
            config,
            pk_r,
            info,
            exporter_context.to_vec(),
            exporter_length,
            None,
            None,
            None,
            randomness,
        )
        .map_err(|_| todo!())
        .map(|HPKECiphertext(enc, exported)| (enc, exported.into()))
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

        libcrux::hpke::ReceiveExport(
            config,
            enc,
            sk_r,
            info,
            exporter_context.to_vec(),
            exporter_length,
            None,
            None,
            None,
        )
        .map_err(|_| todo!())
        .map(|bytes| ExporterSecret::from(bytes))
    }

    fn derive_hpke_keypair(&self, config: HpkeConfig, ikm: &[u8]) -> HpkeKeyPair {
        let config = hpke_config(config);
        let HPKEConfig(_, alg, _, _) = config;
        let (sk, pk) = hpke::kem::DeriveKeyPair(alg, ikm).unwrap(); // XXX return err

        HpkeKeyPair {
            private: sk.into(),
            public: hpke::kem::SerializePublicKey(alg, pk),
        }
    }
}

fn hkdf_alg(hash_type: HashType) -> libcrux::hkdf::Algorithm {
    match hash_type {
        HashType::Sha2_256 => libcrux::hkdf::Algorithm::Sha256,
        HashType::Sha2_384 => libcrux::hkdf::Algorithm::Sha384,
        HashType::Sha2_512 => libcrux::hkdf::Algorithm::Sha512,
    }
}

fn aead_key(alg: AeadType, key: &[u8]) -> Result<libcrux::aead::Key, CryptoError> {
    let key = match alg {
        AeadType::Aes128Gcm => {
            const ALG: libcrux::aead::Algorithm = libcrux::aead::Algorithm::Aes128Gcm;
            let key: [u8; ALG.key_size()] =
                key.try_into().map_err(|_| CryptoError::InvalidLength)?;
            libcrux::aead::Key::Aes128(libcrux::aead::Aes128Key(key))
        }
        AeadType::Aes256Gcm => {
            const ALG: libcrux::aead::Algorithm = libcrux::aead::Algorithm::Aes256Gcm;
            let key: [u8; ALG.key_size()] =
                key.try_into().map_err(|_| CryptoError::InvalidLength)?;
            libcrux::aead::Key::Aes256(libcrux::aead::Aes256Key(key))
        }
        AeadType::ChaCha20Poly1305 => {
            const ALG: libcrux::aead::Algorithm = libcrux::aead::Algorithm::Chacha20Poly1305;
            let key: [u8; ALG.key_size()] =
                key.try_into().map_err(|_| CryptoError::InvalidLength)?;
            libcrux::aead::Key::Chacha20Poly1305(libcrux::aead::Chacha20Key(key))
        }
    };

    Ok(key)
}

fn sig(alg: SignatureScheme, sig: &[u8]) -> Result<libcrux::signature::Signature, CryptoError> {
    match alg {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(libcrux::signature::Signature::EcDsaP256(
            libcrux::signature::EcDsaP256Signature::from_bytes(
                sig.try_into().map_err(|_| CryptoError::InvalidSignature)?,
                libcrux::signature::Algorithm::EcDsaP256(
                    libcrux::signature::DigestAlgorithm::Sha256,
                ),
            ),
        )),
        SignatureScheme::ED25519 => libcrux::signature::Ed25519Signature::from_slice(sig)
            .map(libcrux::signature::Signature::Ed25519)
            .map_err(|e| match e {
                libcrux::signature::Error::InvalidSignature => CryptoError::InvalidSignature,
                _ => unreachable!(),
            }),
        _ => Err(CryptoError::UnsupportedSignatureScheme),
    }
}

fn sig_alg(alg: SignatureScheme) -> Result<libcrux::signature::Algorithm, CryptoError> {
    match alg {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(libcrux::signature::Algorithm::EcDsaP256(
            libcrux::signature::DigestAlgorithm::Sha256,
        )),
        SignatureScheme::ED25519 => Ok(libcrux::signature::Algorithm::Ed25519),
        _ => Err(CryptoError::UnsupportedSignatureScheme),
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

struct GuardedRng<'a, Rng: RngCore>(RwLockWriteGuard<'a, Rng>);

impl<'a, Rng: RngCore> RngCore for GuardedRng<'a, Rng> {
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

impl<'a, Rng: RngCore + CryptoRng> CryptoRng for GuardedRng<'a, Rng> {}
