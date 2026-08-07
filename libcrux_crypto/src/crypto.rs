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

#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
use libcrux_ecdsa::{p256 as ecdsa_p256, DigestAlgorithm};
#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
use libcrux_traits::ecdh::arrayref::EcdhArrayref;

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
            SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(()),

            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA44 | SignatureScheme::MLDSA65 | SignatureScheme::MLDSA87 => {
                Ok(())
            }

            _ => Err(CryptoError::UnsupportedCiphersuite),
        }?;

        match ciphersuite.hash_algorithm() {
            HashType::Sha2_256 | HashType::Sha2_384 | HashType::Sha2_512 => Ok(()),
        }?;

        match ciphersuite.hpke_kem_algorithm() {
            HpkeKemType::DhKemP256 | HpkeKemType::DhKem25519 => Ok(()),

            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            HpkeKemType::MlKem768X25519
            | HpkeKemType::MlKem768P256
            | HpkeKemType::MlKem768
            | HpkeKemType::MlKem1024 => Ok(()),

            // The `draft-ietf-hpke-pq`-enabled HPKE backend this provider
            // depends on only implements the current X-Wing code point
            // (`MlKem768X25519`, 0x647a), not the obsolete one this variant
            // uses (0x004D) — see libcrux_crypto/Readme.md.
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            HpkeKemType::XWingKemDraft6 => Err(CryptoError::UnsupportedCiphersuite),

            // No libcrux P-384 signing crate exists yet, so ciphersuites using
            // this KEM are unimplemented; see libcrux_crypto/Readme.md.
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            HpkeKemType::MlKem1024P384 => Err(CryptoError::UnsupportedCiphersuite),

            HpkeKemType::DhKemP384 | HpkeKemType::DhKemP521 | HpkeKemType::DhKem448 => {
                Err(CryptoError::UnsupportedCiphersuite)
            }
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
        // MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 is not advertised:
        // its (obsolete) X-Wing code point is no longer implemented by the
        // `draft-ietf-hpke-pq`-enabled HPKE backend this provider depends
        // on. See libcrux_crypto/Readme.md.
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        let pq_draft = vec![
            Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44,
            Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
        ];

        #[allow(unused_mut)]
        let mut suites = vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        ];
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        suites.extend(pq_draft);

        suites
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
        match alg {
            SignatureScheme::ED25519 => {
                // Ed25519 key generation is just sampling a non-zero 32-byte secret
                // and deriving the public point. We do it here (rather than via
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
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                // Sample a valid ECDSA private scalar via rejection sampling (see
                // the Ed25519 comment above for why we don't use
                // `ecdsa_p256::PrivateKey::random`, which needs an infallible
                // `CryptoRng`), then derive the public key as `sk * G`.
                const LIMIT: usize = 100;
                let mut sk = [0u8; 32];
                let mut found = false;
                for _ in 0..LIMIT {
                    self.fill_random(&mut sk)?;
                    if ecdsa_p256::PrivateKey::try_from(&sk).is_ok() {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(CryptoError::SigningError);
                }

                let mut coordinates = [0u8; 64];
                libcrux_p256::P256::secret_to_public(&mut coordinates, &sk)
                    .map_err(|_| CryptoError::SigningError)?;

                // Return the public key in SEC1 uncompressed form (`0x04 || x || y`)
                // to match the encoding used by the RustCrypto provider.
                let mut public = Vec::with_capacity(65);
                public.push(0x04);
                public.extend_from_slice(&coordinates);
                Ok((sk.to_vec(), public))
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA44 => {
                let mut seed = [0u8; 32];
                self.fill_random(&mut seed)?;
                let key_pair = libcrux_ml_dsa::ml_dsa_44::generate_key_pair(seed);
                Ok((seed.to_vec(), key_pair.verification_key.as_slice().to_vec()))
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA65 => {
                let mut seed = [0u8; 32];
                self.fill_random(&mut seed)?;
                let key_pair = libcrux_ml_dsa::ml_dsa_65::generate_key_pair(seed);
                Ok((seed.to_vec(), key_pair.verification_key.as_slice().to_vec()))
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA87 => {
                let mut seed = [0u8; 32];
                self.fill_random(&mut seed)?;
                let key_pair = libcrux_ml_dsa::ml_dsa_87::generate_key_pair(seed);
                Ok((seed.to_vec(), key_pair.verification_key.as_slice().to_vec()))
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
                let sig =
                    <&[u8; 64]>::try_from(signature).map_err(|_| CryptoError::InvalidLength)?;

                libcrux_ed25519::verify(data, pk, sig).map_err(|e| match e {
                    libcrux_ed25519::Error::InvalidSignature => CryptoError::InvalidSignature,
                    _ => CryptoError::SigningError,
                })
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                // MLS carries ECDSA signatures DER-encoded; libcrux works on the
                // raw `(r, s)` scalars.
                let (r, s) =
                    crate::ecdsa_der::der_to_raw(signature).ok_or(CryptoError::InvalidSignature)?;
                let sig = ecdsa_p256::Signature::from_raw(r, s);
                let public_key = p256_public_key(pk)?;

                ecdsa_p256::verify(DigestAlgorithm::Sha256, data, &sig, &public_key)
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA44 => {
                let vk = libcrux_ml_dsa::ml_dsa_44::MLDSA44VerificationKey::new(
                    pk.try_into().map_err(|_| CryptoError::InvalidLength)?,
                );
                let sig = libcrux_ml_dsa::ml_dsa_44::MLDSA44Signature::new(
                    signature
                        .try_into()
                        .map_err(|_| CryptoError::InvalidLength)?,
                );
                libcrux_ml_dsa::ml_dsa_44::verify(&vk, data, b"", &sig)
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA65 => {
                let vk = libcrux_ml_dsa::ml_dsa_65::MLDSA65VerificationKey::new(
                    pk.try_into().map_err(|_| CryptoError::InvalidLength)?,
                );
                let sig = libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature::new(
                    signature
                        .try_into()
                        .map_err(|_| CryptoError::InvalidLength)?,
                );
                libcrux_ml_dsa::ml_dsa_65::verify(&vk, data, b"", &sig)
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA87 => {
                let vk = libcrux_ml_dsa::ml_dsa_87::MLDSA87VerificationKey::new(
                    pk.try_into().map_err(|_| CryptoError::InvalidLength)?,
                );
                let sig = libcrux_ml_dsa::ml_dsa_87::MLDSA87Signature::new(
                    signature
                        .try_into()
                        .map_err(|_| CryptoError::InvalidLength)?,
                );
                libcrux_ml_dsa::ml_dsa_87::verify(&vk, data, b"", &sig)
                    .map_err(|_| CryptoError::InvalidSignature)
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
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let key = <&[u8; 32]>::try_from(key).map_err(|_| CryptoError::InvalidLength)?;
                let private =
                    ecdsa_p256::PrivateKey::try_from(key).map_err(|_| CryptoError::SigningError)?;

                // `ecdsa_p256::Nonce` can only be constructed via `Nonce::random`,
                // which needs an infallible `CryptoRng`. Our DRBG is fallible (see
                // `fill_random`), so it's wrapped in `UnwrapErr`, which panics on a
                // DRBG failure instead of propagating it as a `CryptoError` — the
                // same trade-off the HPKE provider we depend on makes for its own
                // PRNG. A DRBG failure here means the OS entropy source failed on
                // reseed, an unrecoverable condition in practice.
                let mut rng = rand::rand_core::UnwrapErr(DrbgTryRng(self));
                let sig = ecdsa_p256::rand::sign(DigestAlgorithm::Sha256, data, &private, &mut rng)
                    .map_err(|_| CryptoError::SigningError)?;

                let (r, s) = sig.as_bytes();
                Ok(crate::ecdsa_der::raw_to_der(r, s))
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA44 => {
                let seed: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidLength)?;
                let signing_key = libcrux_ml_dsa::ml_dsa_44::generate_key_pair(seed).signing_key;
                let mut randomness = [0u8; 32];
                self.fill_random(&mut randomness)?;
                libcrux_ml_dsa::ml_dsa_44::sign(&signing_key, data, b"", randomness)
                    .map_err(|_| CryptoError::SigningError)
                    .map(|sig| sig.as_slice().to_vec())
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA65 => {
                let seed: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidLength)?;
                let signing_key = libcrux_ml_dsa::ml_dsa_65::generate_key_pair(seed).signing_key;
                let mut randomness = [0u8; 32];
                self.fill_random(&mut randomness)?;
                libcrux_ml_dsa::ml_dsa_65::sign(&signing_key, data, b"", randomness)
                    .map_err(|_| CryptoError::SigningError)
                    .map(|sig| sig.as_slice().to_vec())
            }
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            SignatureScheme::MLDSA87 => {
                let seed: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidLength)?;
                let signing_key = libcrux_ml_dsa::ml_dsa_87::generate_key_pair(seed).signing_key;
                let mut randomness = [0u8; 32];
                self.fill_random(&mut randomness)?;
                libcrux_ml_dsa::ml_dsa_87::sign(&signing_key, data, b"", randomness)
                    .map_err(|_| CryptoError::SigningError)
                    .map(|sig| sig.as_slice().to_vec())
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
        // `HpkeKemType::XWingKemDraft6` (0x004D) is the obsolete X-Wing code
        // point; `MlKem768X25519` (0x647a) is the current one used by
        // draft-ietf-mls-pq-ciphersuites below. `supports()` rejects this
        // variant — the HPKE backend this provider depends on no longer
        // implements the obsolete code point — so this arm exists only for
        // match exhaustiveness. See libcrux_crypto/Readme.md.
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        #[allow(deprecated)]
        HpkeKemType::XWingKemDraft6 => hpke_rs_crypto::types::KemAlgorithm::XWingDraft06Obsolete,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        HpkeKemType::MlKem768X25519 => hpke_rs_crypto::types::KemAlgorithm::XWingDraft06,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        HpkeKemType::MlKem768P256 => hpke_rs_crypto::types::KemAlgorithm::MlKem768P256,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        HpkeKemType::MlKem768 => hpke_rs_crypto::types::KemAlgorithm::MlKem768,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        HpkeKemType::MlKem1024 => hpke_rs_crypto::types::KemAlgorithm::MlKem1024,
        // Not supported: `supports()` rejects this KEM (no libcrux P-384
        // signing crate exists yet), so this is unreachable in practice. See
        // libcrux_crypto/Readme.md.
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        HpkeKemType::MlKem1024P384 => {
            unreachable!("MlKem1024P384 is not supported by this provider")
        }
    }
}

/// Parse an ECDSA P-256 public key into the coordinate form libcrux expects.
///
/// Accepts SEC1 uncompressed (`0x04 || x || y`, 65 bytes), compressed, or the
/// raw `x || y` concatenation (64 bytes).
#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
fn p256_public_key(pk: &[u8]) -> Result<ecdsa_p256::PublicKey, CryptoError> {
    let coordinates = ecdsa_p256::uncompressed_to_coordinates(pk)
        .or_else(|_| ecdsa_p256::compressed_to_coordinates(pk))
        .or_else(|_| <[u8; 64]>::try_from(pk))
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    Ok(ecdsa_p256::PublicKey(coordinates))
}

/// Adapts [`CryptoProvider::fill_random`] to the `rand_core` traits that
/// `libcrux-ecdsa`'s randomized nonce generation needs.
///
/// `try_fill_bytes` propagates DRBG failures as [`CryptoError`]; wrap in
/// [`rand::rand_core::UnwrapErr`] to get a `CryptoRng` (which panics on that
/// error instead, since `CryptoRng` requires an infallible source).
#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
struct DrbgTryRng<'a>(&'a CryptoProvider);

#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
impl rand::TryRng for DrbgTryRng<'_> {
    type Error = CryptoError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.0.fill_random(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.0.fill_random(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_random(dst)
    }
}

#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
impl rand::TryCryptoRng for DrbgTryRng<'_> {}

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

            let sig_alg = ciphersuite.signature_algorithm();
            let (sk, pk) = provider
                .signature_key_gen(sig_alg)
                .unwrap_or_else(|e| panic!("{ciphersuite:?}: signature_key_gen failed: {e:?}"));
            let signature = provider
                .sign(sig_alg, b"plaintext", &sk)
                .unwrap_or_else(|e| panic!("{ciphersuite:?}: sign failed: {e:?}"));
            provider
                .verify_signature(sig_alg, b"plaintext", &pk, &signature)
                .unwrap_or_else(|e| panic!("{ciphersuite:?}: verify_signature failed: {e:?}"));
            assert!(
                provider
                    .verify_signature(sig_alg, b"tampered", &pk, &signature)
                    .is_err(),
                "{ciphersuite:?}: verify_signature accepted a signature over the wrong message"
            );
        }
    }
}
