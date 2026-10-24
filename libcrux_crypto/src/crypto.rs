use hpke_rs_libcrux::{HpkeLibcrux, HpkeLibcruxPrng};

use std::sync::Mutex;

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
    HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
};

use libcrux_hmac_drbg::{HmacDrbgSha256, MAX_GENERATE_BYTES};
use rand::{rngs::SysRng, TryCryptoRng};

use tls_codec::SecretVLBytes;

/// Application-specific personalization string mixed into the HMAC-DRBG seed.
const PERSONALIZATION: &[u8] = b"openmls-libcrux-hmac-drbg-v1";

/// The libcrux-backed cryptography provider for OpenMLS
///
/// All randomness this provider uses, both through
/// [`OpenMlsRand`](openmls_traits::random::OpenMlsRand) and inside
/// [`OpenMlsCrypto`] operations (signature key generation, hedged ML-DSA
/// signing, HPKE encapsulation), is drawn from a single HMAC-DRBG. The DRBG is
/// seeded and reseeded from the entropy source `R`, which is the operating
/// system's RNG unless one is given with
/// [`CryptoProvider::with_entropy_source`].
pub struct CryptoProvider<R = SysRng> {
    pub(super) rng: Mutex<DrbgState<R>>,
}

/// The HMAC-DRBG together with the entropy source it reseeds from.
pub(super) struct DrbgState<R> {
    drbg: HmacDrbgSha256,
    source: R,
}

impl<R: TryCryptoRng> DrbgState<R> {
    /// Fill `out` from the HMAC-DRBG.
    ///
    /// Reseeds from the entropy source when the DRBG's reseed interval is
    /// reached, and splits requests larger than [`MAX_GENERATE_BYTES`] into
    /// multiple `generate` calls. Any failure to obtain entropy for a reseed is
    /// propagated rather than panicking.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        for chunk in out.chunks_mut(MAX_GENERATE_BYTES) {
            if self.drbg.needs_reseed() {
                self.drbg
                    .reseed_from_rng(&mut self.source, &[])
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
            }
            self.drbg
                .generate(chunk, &[])
                .map_err(|_| CryptoError::InsufficientRandomness)?;
        }

        Ok(())
    }
}

/// Lets libcrux primitives that take an RNG (ECDSA key generation and
/// signing) draw from the DRBG, with the same reseeding as [`DrbgState::fill`].
impl<R: TryCryptoRng> rand::TryRng for DrbgState<R> {
    type Error = CryptoError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.fill(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(dst)
    }
}

impl<R: TryCryptoRng> TryCryptoRng for DrbgState<R> {}

impl CryptoProvider {
    /// Instantiate a libcrux-based CryptoProvider
    ///
    /// The HMAC-DRBG is seeded and reseeded from the operating system's
    /// entropy source.
    pub fn new() -> Result<Self, CryptoError> {
        Self::with_entropy_source(SysRng)
    }
}

impl<R: TryCryptoRng> CryptoProvider<R> {
    /// Instantiate a libcrux-based CryptoProvider whose HMAC-DRBG is seeded
    /// and reseeded from `source`.
    ///
    /// `source` must implement the `rand` 0.10 [`TryCryptoRng`] trait. A
    /// failure of `source`, now or on a later reseed, is reported as
    /// [`CryptoError::InsufficientRandomness`].
    pub fn with_entropy_source(mut source: R) -> Result<Self, CryptoError> {
        let drbg = HmacDrbgSha256::new_from_rng(&mut source, PERSONALIZATION)
            .map_err(|_| CryptoError::InsufficientRandomness)?;

        Ok(Self {
            rng: Mutex::new(DrbgState { drbg, source }),
        })
    }

    /// Fill `out` with fresh randomness from the HMAC-DRBG, reseeding from the
    /// entropy source when needed (see [`DrbgState::fill`]).
    pub(super) fn fill_random(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        self.rng
            .lock()
            .map_err(|_| CryptoError::CryptoLibraryError)?
            .fill(out)
    }

    /// An HPKE instance for the sender side, whose encapsulation randomness
    /// is drawn from the HMAC-DRBG.
    ///
    /// `hpke_rs::Hpke::new` seeds its own PRNG from the operating system, so
    /// the sender paths construct the instance with a PRNG seeded from this
    /// provider instead.
    fn hpke_sender(
        &self,
        config: HpkeConfig,
        mode: hpke_rs::Mode,
    ) -> Result<hpke_rs::Hpke<HpkeLibcrux>, CryptoError> {
        let mut seed = [0u8; 32];
        self.fill_random(&mut seed)?;
        let prng = HpkeLibcruxPrng::try_from_seed(seed)
            .map_err(|_| CryptoError::InsufficientRandomness)?;

        Ok(hpke_rs::Hpke::new_with_rng(
            mode,
            hpke_kem(config.0),
            hpke_kdf(config.1),
            hpke_aead(config.2),
            prng,
        ))
    }
}

impl<R: TryCryptoRng + Send> OpenMlsCrypto for CryptoProvider<R> {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite.aead_algorithm() {
            AeadType::ChaCha20Poly1305 | AeadType::Aes128Gcm | AeadType::Aes256Gcm => Ok(()),
        }?;

        match ciphersuite.signature_algorithm() {
            SignatureScheme::ED25519 | SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(()),
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA44 | SignatureScheme::MLDSA65 | SignatureScheme::MLDSA87 => {
                Ok(())
            }
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }?;

        match ciphersuite.hash_algorithm() {
            HashType::Sha2_256 | HashType::Sha2_384 | HashType::Sha2_512 => Ok(()),
        }?;

        // The hpke-rs libcrux backend only implements these KEMs (pure ML-KEM
        // and the ML-KEM + NIST curve hybrids need its `draft-ietf-hpke-pq`
        // feature, which `draft-ietf-mls-pq-ciphersuites` enables).
        match ciphersuite.hpke_kem_algorithm() {
            HpkeKemType::DhKemP256 | HpkeKemType::DhKem25519 => Ok(()),
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            HpkeKemType::XWingKemDraft6 => Ok(()),
            HpkeKemType::DhKemP384 | HpkeKemType::DhKemP521 | HpkeKemType::DhKem448 => {
                Err(CryptoError::UnsupportedCiphersuite)
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            HpkeKemType::MlKem768
            | HpkeKemType::MlKem1024
            | HpkeKemType::MlKem768P256
            | HpkeKemType::MlKem1024P384 => Ok(()),
        }?;

        match ciphersuite.hpke_aead_algorithm() {
            HpkeAeadType::AesGcm128
            | HpkeAeadType::AesGcm256
            | HpkeAeadType::ChaCha20Poly1305
            | HpkeAeadType::Export => Ok(()),
        }?;

        Ok(())
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519,
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44,
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256,
            // `MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384` and
            // `MLS_192_MLKEM1024_AES256GCM_SHA384_P384` are not supported:
            // libcrux has no ECDSA P-384 implementation yet.
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
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
        let mut out = vec![0u8; libcrux_hmac::tag_size(alg)];
        libcrux_hmac::hmac(alg, key, message, &mut out);
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
        match alg {
            SignatureScheme::ED25519 => {
                // Ed25519 key generation is just sampling a non-zero 32-byte
                // secret and deriving the public point. We do it here (rather
                // than via `libcrux_ed25519::generate_key_pair`, which requires
                // an infallible `CryptoRng`) so that a DRBG reseed failure is
                // propagated as an error.
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
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let mut drbg = self
                    .rng
                    .lock()
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let sk = libcrux_ecdsa::p256::PrivateKey::random(&mut *drbg)
                    .map_err(|_| CryptoError::SigningError)?;
                // Same wire format as the RustCrypto provider: the private key
                // is the raw 32-byte scalar, the public key the uncompressed
                // SEC1 point.
                let pk = sk.public_key().map_err(|_| CryptoError::SigningError)?;
                let mut pk_sec1 = Vec::with_capacity(65);
                pk_sec1.push(0x04);
                pk_sec1.extend_from_slice(pk.as_ref());
                Ok((AsRef::<[u8; 32]>::as_ref(&sk).to_vec(), pk_sec1))
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA44 | SignatureScheme::MLDSA65 | SignatureScheme::MLDSA87 => {
                // Same wire format as the RustCrypto provider: the private key
                // is the 32-byte seed, the public key is the encoded
                // verification key.
                let mut seed = [0u8; libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE];
                self.fill_random(&mut seed)?;
                let pk = ml_dsa::verification_key(alg, seed)?;
                Ok((seed.to_vec(), pk))
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        match alg {
            SignatureScheme::ED25519 => {
                let pk = <&[u8; 32]>::try_from(pk).map_err(|_| CryptoError::InvalidLength)?;
                let sk =
                    <&[u8; 64]>::try_from(signature).map_err(|_| CryptoError::InvalidLength)?;

                libcrux_ed25519::verify(data, pk, sk).map_err(|e| match e {
                    libcrux_ed25519::Error::InvalidSignature => CryptoError::InvalidSignature,
                    _ => CryptoError::SigningError,
                })
            }
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let pk = libcrux_ecdsa::p256::uncompressed_to_coordinates(pk)
                    .map_err(|_| CryptoError::InvalidLength)?;
                let signature = libcrux_ecdsa::p256::Signature::from_der(signature)
                    .map_err(|_| CryptoError::InvalidSignature)?;
                libcrux_ecdsa::p256::verify(
                    libcrux_ecdsa::DigestAlgorithm::Sha256,
                    data,
                    &signature,
                    &libcrux_ecdsa::p256::PublicKey(pk),
                )
                .map_err(|_| CryptoError::InvalidSignature)
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA44 | SignatureScheme::MLDSA65 | SignatureScheme::MLDSA87 => {
                ml_dsa::verify(alg, pk, data, signature)
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match alg {
            SignatureScheme::ED25519 => {
                let key = <&[u8; 32]>::try_from(key).map_err(|_| CryptoError::InvalidLength)?;
                libcrux_ed25519::sign(data, key)
                    .map_err(|_| CryptoError::SigningError)
                    .map(|sig| sig.to_vec())
            }
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let sk = libcrux_ecdsa::p256::PrivateKey::try_from(key)
                    .map_err(|_| CryptoError::InvalidLength)?;
                // The ECDSA nonce is rejection-sampled inside libcrux through
                // the provider DRBG; a randomness failure surfaces as an error.
                let mut drbg = self
                    .rng
                    .lock()
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature = libcrux_ecdsa::p256::rand::sign(
                    libcrux_ecdsa::DigestAlgorithm::Sha256,
                    data,
                    &sk,
                    &mut *drbg,
                )
                .map_err(|_| CryptoError::SigningError)?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA44 | SignatureScheme::MLDSA65 | SignatureScheme::MLDSA87 => {
                let seed = <[u8; libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE]>::try_from(key)
                    .map_err(|_| CryptoError::InvalidLength)?;
                // Hedged signing (FIPS 204 §3.4): fresh randomness per signature.
                let mut rnd = [0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
                self.fill_random(&mut rnd)?;
                ml_dsa::sign(alg, seed, data, rnd)
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
    ) -> Result<HpkeCiphertext, CryptoError> {
        let mut config = self.hpke_sender(config, hpke_rs::Mode::Base)?;

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
        let mut config = self.hpke_sender(config, hpke_rs::Mode::Base)?;

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
        #[cfg(feature = "legacy-pq-key-derivation")]
        if is_legacy_xwing_config(&config) {
            return derive_legacy_xwing_keypair(ikm);
        }

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
    fn hpke_seal_psk(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        let mut config = self.hpke_sender(config, hpke_rs::Mode::Psk)?;

        let pk_r = hpke_rs::HpkePublicKey::new(pk_r.to_vec());

        let (kem_output, ciphertext) = config
            .seal(&pk_r, info, aad, ptxt, Some(psk), Some(psk_id), None)
            .map_err(|e| match e {
                hpke_rs::HpkeError::InvalidConfig => CryptoError::SenderSetupError,
                _ => CryptoError::HpkeEncryptionError,
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

/// The RNG of the HPKE instances for operations that draw no randomness
/// (receiver side and key derivation).
///
/// It never yields any bytes: if such an operation asked for randomness, it
/// would fail rather than fall back to another source. Unlike
/// `hpke_rs::Hpke::new`, constructing an instance with it does not read the
/// operating system's RNG.
struct NoRandomness;

#[derive(Debug)]
struct NoRandomnessError;

impl std::fmt::Display for NoRandomnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "this HPKE instance has no randomness")
    }
}

impl std::error::Error for NoRandomnessError {}

impl rand::TryRng for NoRandomness {
    type Error = NoRandomnessError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(NoRandomnessError)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(NoRandomnessError)
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        Err(NoRandomnessError)
    }
}

impl TryCryptoRng for NoRandomness {}

/// An HPKE instance for operations that draw no randomness (receiver side and
/// key derivation). Sender paths use [`CryptoProvider::hpke_sender`].
fn hpke_config(config: HpkeConfig) -> hpke_rs::Hpke<HpkeLibcrux<NoRandomness>> {
    hpke_receiver(config, hpke_rs::Mode::Base)
}

/// A PSK-mode HPKE instance for the receiver side. Sender paths use
/// [`CryptoProvider::hpke_sender`].
#[cfg(feature = "targeted-messages-draft")]
fn hpke_psk_from_config(config: HpkeConfig) -> hpke_rs::Hpke<HpkeLibcrux<NoRandomness>> {
    hpke_receiver(config, hpke_rs::Mode::Psk)
}

fn hpke_receiver(
    config: HpkeConfig,
    mode: hpke_rs::Mode,
) -> hpke_rs::Hpke<HpkeLibcrux<NoRandomness>> {
    hpke_rs::Hpke::new_with_rng(
        mode,
        hpke_kem(config.0),
        hpke_kdf(config.1),
        hpke_aead(config.2),
        NoRandomness,
    )
}

fn hpke_kdf(kdf: HpkeKdfType) -> hpke_rs_crypto::types::KdfAlgorithm {
    match kdf {
        HpkeKdfType::HkdfSha256 => hpke_rs_crypto::types::KdfAlgorithm::HkdfSha256,
        HpkeKdfType::HkdfSha384 => hpke_rs_crypto::types::KdfAlgorithm::HkdfSha384,
        HpkeKdfType::HkdfSha512 => hpke_rs_crypto::types::KdfAlgorithm::HkdfSha512,
    }
}

/// The HPKE configuration of `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`
/// (0x004D). No draft-ietf-mls-pq-ciphersuites suite uses this combination
/// (TBD1 uses AES-128-GCM, TBD9 HKDF-SHA384), so matching on it only affects
/// the legacy suite.
#[cfg(feature = "legacy-pq-key-derivation")]
fn is_legacy_xwing_config(config: &HpkeConfig) -> bool {
    matches!(
        config,
        HpkeConfig(
            HpkeKemType::XWingKemDraft6,
            HpkeKdfType::HkdfSha256,
            HpkeAeadType::ChaCha20Poly1305,
        )
    )
}

/// openmls_libcrux_crypto 0.4.0 derived X-Wing key pairs from the unlabeled `SHAKE256(ikm, 32)`
/// rather than draft-ietf-hpke-pq's `SHAKE256.LabeledDerive`. The private key
/// is the 32-byte X-Wing seed in both cases, so only the derivation differs.
#[cfg(feature = "legacy-pq-key-derivation")]
fn derive_legacy_xwing_keypair(ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    use hpke_rs_crypto::HpkeCrypto;

    let seed = libcrux_sha3::shake256::<32>(ikm);
    let (public, private) =
        <HpkeLibcrux>::kem_key_gen_derand(hpke_rs_crypto::types::KemAlgorithm::XWingDraft06, &seed)
            .map_err(|_| CryptoError::CryptoLibraryError)?;

    Ok(HpkeKeyPair {
        private: private.into(),
        public,
    })
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
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        HpkeKemType::MlKem768P256 => hpke_rs_crypto::types::KemAlgorithm::MlKem768P256,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        HpkeKemType::MlKem1024P384 => hpke_rs_crypto::types::KemAlgorithm::MlKem1024P384,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_ciphersuites_are_supported() {
        let provider = CryptoProvider::new().unwrap();
        for ciphersuite in provider.supported_ciphersuites() {
            assert!(
                provider.supports(ciphersuite).is_ok(),
                "{ciphersuite:?} is advertised by supported_ciphersuites() \
                 but rejected by supports()"
            );
        }
    }

    #[test]
    fn advertised_ciphersuites_actually_work() {
        let provider = CryptoProvider::new().unwrap();
        for ciphersuite in provider.supported_ciphersuites() {
            let key = vec![0u8; ciphersuite.aead_key_length()];
            let nonce = vec![0u8; ciphersuite.aead_nonce_length()];
            let ciphertext = provider
                .aead_encrypt(
                    ciphersuite.aead_algorithm(),
                    &key,
                    b"plaintext",
                    &nonce,
                    b"aad",
                )
                .unwrap_or_else(|e| panic!("{ciphersuite:?}: aead_encrypt failed: {e:?}"));
            let plaintext = provider
                .aead_decrypt(
                    ciphersuite.aead_algorithm(),
                    &key,
                    &ciphertext,
                    &nonce,
                    b"aad",
                )
                .unwrap_or_else(|e| panic!("{ciphersuite:?}: aead_decrypt failed: {e:?}"));
            assert_eq!(plaintext, b"plaintext", "{ciphersuite:?}: aead round trip");

            let mut ikm = vec![0u8; ciphersuite.hash_length()];
            provider.fill_random(&mut ikm).unwrap();
            let key_pair = provider
                .derive_hpke_keypair(ciphersuite.hpke_config(), &ikm)
                .unwrap_or_else(|e| panic!("{ciphersuite:?}: derive_hpke_keypair failed: {e:?}"));
            let sealed = provider
                .hpke_seal(
                    ciphersuite.hpke_config(),
                    &key_pair.public,
                    b"info",
                    b"aad",
                    b"plaintext",
                )
                .unwrap_or_else(|e| panic!("{ciphersuite:?}: hpke_seal failed: {e:?}"));
            let opened = provider
                .hpke_open(
                    ciphersuite.hpke_config(),
                    &sealed,
                    &key_pair.private,
                    b"info",
                    b"aad",
                )
                .unwrap_or_else(|e| panic!("{ciphersuite:?}: hpke_open failed: {e:?}"));
            assert_eq!(
                opened.as_slice(),
                b"plaintext",
                "{ciphersuite:?}: hpke round trip"
            );
        }
    }

    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Checks `derive_hpke_keypair` against `sk` and `SHA-256(pk)`.
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    fn assert_derived_keypair(
        provider: &CryptoProvider,
        ciphersuite: Ciphersuite,
        ikm: &str,
        sk: &str,
        pk_sha256: &str,
    ) {
        let key_pair = provider
            .derive_hpke_keypair(ciphersuite.hpke_config(), &hex(ikm))
            .unwrap_or_else(|e| panic!("{ciphersuite:?}: derive_hpke_keypair failed: {e:?}"));
        assert_eq!(&key_pair.private[..], hex(sk), "{ciphersuite:?}: sk");
        let pk_hash = provider.hash(HashType::Sha2_256, &key_pair.public).unwrap();
        assert_eq!(pk_hash, hex(pk_sha256), "{ciphersuite:?}: pk");
    }

    /// `ikmR`/`skRm`/`pkRm` from the draft-ietf-hpke-pq test vectors
    /// (https://github.com/hpkewg/hpke-pq/blob/main/test-vectors.json).
    /// DeriveKeyPair depends only on the KEM, so the KDF/AEAD of the chosen
    /// ciphersuite need not match the vector's.
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    #[test]
    fn derive_hpke_keypair_matches_hpke_pq_kat() {
        let provider = CryptoProvider::new().unwrap();
        // MLKEM768-X25519 (0x647a)
        assert_derived_keypair(
            &provider,
            Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
            "c8575d137deab99ac98fb0873048c83c3a1f47ef5b409f609c0ca652f58c83e0",
            "b6bfa0299b955e85224df2e468f29eeab377ff3b96d4462b39447a22d32b91be",
            "ad42b3d8669605eb351273b945e2f4bfe62986517b411e606c225d96d4de9099",
        );
        // ML-KEM-768 (0x0041)
        assert_derived_keypair(
            &provider,
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519,
            "a60b35f174ce9ac7a4ff5b9f81e38125b03506ecbd56a3a55c31ece0f59070520729773a61a499d5137daaef824b493848b6e4dd332a815ff19aa9f58a381eb8",
            "80008d036609972cf761d7e2d3b831e48d3e941cda94fbf9bae09bca87373f9bb7411f58fd3324ba1d0daa5a7b42768c5b53e1df29c28d4f5428a8233a905089",
            "80aabb142999e683475598517f3bca6b9b8c8f01109ec8f861b450d2a8b9148d",
        );
        // ML-KEM-1024 (0x0042)
        assert_derived_keypair(
            &provider,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
            "d6688a981deeff1d1273426af8a44aab877c50b6e8ac74b11e01a5960d97c03bffd9634894d255c424c80c74e0930b85b9f4c60e22a3efb09f4bad4749be427b",
            "73a9ffe155d39edcc023b11171ad6cf541ff85eff68c33b521ba25cbb1b7079bf848b63f5b8ca53f809255b51f1bef24b342d706a77cb460981e16b2ce737552",
            "b45440fa44f6a7046ecf45d77fdd4fd9f02982defa787501ba365f0c264d9f73",
        );
        // MLKEM768-P256 (0x0050)
        assert_derived_keypair(
            &provider,
            Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
            "3bf888035cc5f48fa476c2ccdb73a5482e97a0d0578fa710b1e393ca9716b6f0",
            "1f25a59a6b22ef57b8e48a6cfe739b9ec13e9cf57e82dfd6e0480e0324cf905b",
            "58906fb2678e7c53e22220d398ffc2bec8e95e9ee1369bbfdea67db2628378b4",
        );
        // MLKEM1024-P384 (0x0051). The ciphersuite itself is unsupported (no
        // ECDSA P-384), but its HPKE KEM is.
        assert_derived_keypair(
            &provider,
            Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
            "14c036a5e3c4af452baccdcd62cf818f250607076c299636e5c8074b3c757df1",
            "0ba4a1ff718a4444da0016d59f449e28d8abdeac107ee105e5ac0dc1e8219b37",
            "2fa438cda8bdfa993e8286a31a3c7d90766dacd114131cd5dfecf466eab936e3",
        );
    }

    /// Expected values were produced by openmls_libcrux_crypto 0.4.0 (openmls 0.9.0).
    #[cfg(feature = "legacy-pq-key-derivation")]
    #[test]
    fn legacy_xwing_derivation_matches_v0_4() {
        let provider = CryptoProvider::new().unwrap();
        assert_derived_keypair(
            &provider,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "69f07c8840ce80024db30939882c3d5bbc9c98b3e31e4513ebd2ca9b4503cdd3",
            "e735f8e75ba7883aae5d6456ae03c14086b769d73502147370f2963b397e4d4a",
        );
    }
}

/// ML-DSA (FIPS 204) glue over `libcrux-ml-dsa`.
///
/// Wire format matches the RustCrypto provider so keys and signatures
/// interoperate across providers: private key = 32-byte key-generation seed,
/// public key = encoded verification key, empty signing context.
#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
mod ml_dsa {
    use libcrux_ml_dsa::{
        ml_dsa_44, ml_dsa_65, ml_dsa_87, MLDSASignature, MLDSAVerificationKey,
        KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE,
    };
    use openmls_traits::types::{CryptoError, SignatureScheme};

    /// The context string is always empty for MLS signatures.
    const CONTEXT: &[u8] = &[];

    /// Dispatch `$body` to the libcrux module for the ML-DSA parameter set
    /// selected by `$alg`. libcrux exposes each parameter set as its own module
    /// with distinct fixed-size key/signature types, so the body is
    /// instantiated once per module with `$m` bound to it.
    macro_rules! with_parameter_set {
        ($alg:expr, $m:ident => $body:expr) => {
            match $alg {
                SignatureScheme::MLDSA44 => {
                    use ml_dsa_44 as $m;
                    $body
                }
                SignatureScheme::MLDSA65 => {
                    use ml_dsa_65 as $m;
                    $body
                }
                SignatureScheme::MLDSA87 => {
                    use ml_dsa_87 as $m;
                    $body
                }
                _ => Err(CryptoError::UnsupportedSignatureScheme),
            }
        };
    }

    /// The encoded verification key derived from `seed`.
    pub(super) fn verification_key(
        alg: SignatureScheme,
        seed: [u8; KEY_GENERATION_RANDOMNESS_SIZE],
    ) -> Result<Vec<u8>, CryptoError> {
        with_parameter_set!(alg, m => Ok(
            m::generate_key_pair(seed).verification_key.as_slice().to_vec()
        ))
    }

    pub(super) fn sign(
        alg: SignatureScheme,
        seed: [u8; KEY_GENERATION_RANDOMNESS_SIZE],
        data: &[u8],
        randomness: [u8; SIGNING_RANDOMNESS_SIZE],
    ) -> Result<Vec<u8>, CryptoError> {
        with_parameter_set!(alg, m => {
            let key_pair = m::generate_key_pair(seed);
            m::sign(&key_pair.signing_key, data, CONTEXT, randomness)
                .map(|sig| sig.as_slice().to_vec())
                .map_err(|_| CryptoError::SigningError)
        })
    }

    pub(super) fn verify(
        alg: SignatureScheme,
        pk: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        with_parameter_set!(alg, m => {
            let pk = pk.try_into().map_err(|_| CryptoError::InvalidLength)?;
            let signature = signature
                .try_into()
                .map_err(|_| CryptoError::InvalidLength)?;
            m::verify(
                &MLDSAVerificationKey::new(pk),
                data,
                CONTEXT,
                &MLDSASignature::new(signature),
            )
            .map_err(|_| CryptoError::InvalidSignature)
        })
    }
}
