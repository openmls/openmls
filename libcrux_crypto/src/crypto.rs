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

impl CryptoProvider {
    #[inline(always)]
    fn aes_support(&self) -> bool {
        libcrux::aes_ni_support() && cfg!(target_arch = "x86_64")
    }
}

impl OpenMlsCrypto for CryptoProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match (ciphersuite.aead_algorithm(), self.aes_support()) {
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
            HpkeAeadType::AesGcm128 | HpkeAeadType::AesGcm256 if self.aes_support() => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }?;

        Ok(())
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        if self.aes_support() {
            vec![
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            ]
        } else {
            vec![
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            ]
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
        // only fails on wrong length
        let iv = libcrux::aead::Iv::new(nonce).map_err(|err| match err {
            libcrux::aead::InvalidArgumentError::InvalidIv => CryptoError::InvalidLength,
            _ => CryptoError::CryptoLibraryError,
        })?;
        let key = aead_key(alg, key)?;

        let mut msg_ctx: Vec<u8> = data.to_vec();
        let tag = libcrux::aead::encrypt(&key, &mut msg_ctx, iv, aad).map_err(|e| match e {
            libcrux::aead::EncryptError::InvalidArgument(
                libcrux::aead::InvalidArgumentError::UnsupportedAlgorithm,
            ) => CryptoError::UnsupportedAeadAlgorithm,
            _ => CryptoError::CryptoLibraryError,
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
        if ct_tag.len() < 16 || nonce.len() != 12 {
            return Err(CryptoError::InvalidLength);
        }

        let boundary = ct_tag.len() - 16;
        let mut c = ct_tag[..boundary].to_vec();
        let tag = &ct_tag[boundary..];

        let iv = libcrux::aead::Iv::new(nonce).map_err(|_| CryptoError::InvalidLength)?;
        let key = aead_key(alg, key)?;
        let tag = libcrux::aead::Tag::from_slice(tag).expect("failed despite correct length");

        libcrux::aead::decrypt(&key, &mut c, iv, aad, &tag).map_err(|e| match e {
            libcrux::aead::DecryptError::InvalidArgument(
                libcrux::aead::InvalidArgumentError::UnsupportedAlgorithm,
            ) => CryptoError::UnsupportedAeadAlgorithm,
            libcrux::aead::DecryptError::DecryptionFailed => CryptoError::AeadDecryptionError,
            _ => CryptoError::CryptoLibraryError,
        })?;

        Ok(c)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let alg = sig_alg(alg)?;
        let mut rng = self
            .drbg
            .lock()
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
            .lock()
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
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            let decoded: [u8; 64] = der_decode(sig)?
                .try_into()
                .map_err(|_| CryptoError::InvalidSignature)?;

            Ok(libcrux::signature::Signature::EcDsaP256(
                libcrux::signature::EcDsaP256Signature::from_bytes(
                    decoded,
                    libcrux::signature::Algorithm::EcDsaP256(
                        libcrux::signature::DigestAlgorithm::Sha256,
                    ),
                ),
            ))
        }
        SignatureScheme::ED25519 => libcrux::signature::Ed25519Signature::from_slice(sig)
            .map(libcrux::signature::Signature::Ed25519)
            .map_err(|e| match e {
                libcrux::signature::Error::InvalidSignature => CryptoError::InvalidSignature,
                _ => CryptoError::CryptoLibraryError,
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
impl<R: std::io::Read + ?Sized> ReadU8 for R {}

pub trait ReadU8: std::io::Read {
    /// A small helper function to read a u8 from a Reader.
    #[inline]
    fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

/// This function takes a DER encoded ECDSA signature and decodes it to the
/// bytes representing the concatenated scalars. If the decoding fails, it
/// will throw a `CryptoError`.
fn der_decode(mut signature_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // A small function to DER decode a single scalar.
    fn decode_scalar<R: std::io::Read>(mut buffer: R) -> Result<Vec<u8>, CryptoError> {
        // Check header bytes of encoded scalar.

        // 1 byte INTEGER tag should be 0x02
        let integer_tag = buffer
            .read_u8()
            .map_err(|_| CryptoError::SignatureDecodingError)?;
        if integer_tag != INTEGER_TAG {
            return Err(CryptoError::SignatureDecodingError);
        };

        // 1 byte length tag should be at most 0x21, i.e. 32 plus at most 1
        // byte indicating that the integer is unsigned.
        let mut scalar_length = buffer
            .read_u8()
            .map_err(|_| CryptoError::SignatureDecodingError)?
            as usize;
        if scalar_length > P256_SCALAR_LENGTH + 1 {
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
        return Err(CryptoError::SignatureDecodingError);
    }

    // The remaining bytes should be equal to the encoded length.
    if signature_bytes.len() != length {
        return Err(CryptoError::SignatureDecodingError);
    }

    let mut r = decode_scalar(&mut signature_bytes)?;
    let mut s = decode_scalar(&mut signature_bytes)?;

    // If there are bytes remaining, the encoded length was larger than the
    // length of the individual scalars..
    if !signature_bytes.is_empty() {
        return Err(CryptoError::SignatureDecodingError);
    }

    let mut out = Vec::with_capacity(2 * P256_SCALAR_LENGTH);
    out.append(&mut r);
    out.append(&mut s);
    Ok(out)
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
