//! # OpenMLS Types
//!
//! This module holds a number of types that are needed by the traits.

use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use tls_codec::{TlsByteVecU16, TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
/// AEAD types
pub enum AeadType {
    /// AES GCM 128
    Aes128Gcm = 0x0001,

    /// AES GCM 256
    Aes256Gcm = 0x0002,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305 = 0x0003,
}

impl AeadType {
    /// Get the tag size of the [`AeadType`] in bytes.
    pub const fn tag_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 16,
            AeadType::ChaCha20Poly1305 => 16,
        }
    }

    /// Get the key size of the [`AeadType`] in bytes.
    pub const fn key_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 32,
            AeadType::ChaCha20Poly1305 => 32,
        }
    }

    /// Get the nonce size of the [`AeadType`] in bytes.
    pub const fn nonce_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm | AeadType::Aes256Gcm | AeadType::ChaCha20Poly1305 => 12,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
#[allow(non_camel_case_types)]
/// Hash types
pub enum HashType {
    Sha2_256 = 0x04,
    Sha2_384 = 0x05,
    Sha2_512 = 0x06,
}

impl HashType {
    /// Returns the output size of a hash by [`HashType`].
    #[inline]
    pub const fn size(&self) -> usize {
        match self {
            HashType::Sha2_256 => 32,
            HashType::Sha2_384 => 48,
            HashType::Sha2_512 => 64,
        }
    }
}

/// SignatureScheme according to IANA TLS parameters
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(
    Copy,
    Hash,
    Eq,
    PartialEq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
)]
#[repr(u16)]
pub enum SignatureScheme {
    /// ECDSA_SECP256R1_SHA256
    ECDSA_SECP256R1_SHA256 = 0x0403,
    /// ECDSA_SECP384R1_SHA384
    ECDSA_SECP384R1_SHA384 = 0x0503,
    /// ECDSA_SECP521R1_SHA512
    ECDSA_SECP521R1_SHA512 = 0x0603,
    /// ED25519
    ED25519 = 0x0807,
    /// ED448
    ED448 = 0x0808,
}

impl TryFrom<u16> for SignatureScheme {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0403 => Ok(SignatureScheme::ECDSA_SECP256R1_SHA256),
            0x0503 => Ok(SignatureScheme::ECDSA_SECP384R1_SHA384),
            0x0603 => Ok(SignatureScheme::ECDSA_SECP521R1_SHA512),
            0x0807 => Ok(SignatureScheme::ED25519),
            0x0808 => Ok(SignatureScheme::ED448),
            _ => Err(format!("Unsupported SignatureScheme: {}", value)),
        }
    }
}

/// Trait errors.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Error {
    CryptoError(CryptoError),
}

/// Crypto errors.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CryptoError {
    CryptoLibraryError,
    AeadDecryptionError,
    HpkeDecryptionError,
    UnsupportedSignatureScheme,
    KdfLabelTooLarge,
    KdfSerializationError,
    HkdfOutputLengthInvalid,
    InsufficientRandomness,
    InvalidSignature,
    UnsupportedAeadAlgorithm,
    UnsupportedKdf,
    InvalidLength,
    UnsupportedHashAlgorithm,
    SignatureEncodingError,
    SignatureDecodingError,
    SenderSetupError,
    ReceiverSetupError,
    ExporterError,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CryptoError {}

// === HPKE === //

/// Convenience tuple struct for an HPKE configuration.
#[derive(Debug)]
pub struct HpkeConfig(pub HpkeKemType, pub HpkeKdfType, pub HpkeAeadType);

/// KEM Types for HPKE
#[derive(PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKemType {
    /// DH KEM on P256
    DhKemP256 = 0x0010,

    /// DH KEM on P384
    DhKemP384 = 0x0011,

    /// DH KEM on P521
    DhKemP521 = 0x0012,

    /// DH KEM on x25519
    DhKem25519 = 0x0020,

    /// DH KEM on x448
    DhKem448 = 0x0021,
}

/// KDF Types for HPKE
#[derive(PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKdfType {
    /// HKDF SHA 256
    HkdfSha256 = 0x0001,

    /// HKDF SHA 384
    HkdfSha384 = 0x0002,

    /// HKDF SHA 512
    HkdfSha512 = 0x0003,
}

/// AEAD Types for HPKE.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeAeadType {
    /// AES GCM 128
    AesGcm128 = 0x0001,

    /// AES GCM 256
    AesGcm256 = 0x0002,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305 = 0x0003,

    /// Export-only
    Export = 0xFFFF,
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     opaque kem_output<0..2^16-1>;
///     opaque ciphertext<0..2^16-1>;
/// } HPKECiphertext;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct HpkeCiphertext {
    pub kem_output: TlsByteVecU16,
    pub ciphertext: TlsByteVecU16,
}

/// Helper holding a (private, public) key pair as byte vectors.
#[derive(Debug, Clone)]
pub struct HpkeKeyPair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

pub type ExporterSecret = Vec<u8>;
pub type KemOutput = Vec<u8>;

/// MLS ciphersuites.
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum CiphersuiteName {
    MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
    MLS10_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,
}

impl core::fmt::Display for CiphersuiteName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<&CiphersuiteName> for u16 {
    #[inline(always)]
    fn from(s: &CiphersuiteName) -> u16 {
        *s as u16
    }
}

impl TryFrom<u16> for CiphersuiteName {
    type Error = tls_codec::Error;

    #[inline(always)]
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            0x0002 => Ok(CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256),
            0x0003 => Ok(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            0x0004 => Ok(CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448),
            0x0005 => Ok(CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521),
            0x0006 => Ok(CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),
            _ => Err(Self::Error::DecodingError(format!(
                "{} is not a valid cipher suite value",
                v
            ))),
        }
    }
}

impl From<CiphersuiteName> for SignatureScheme {
    #[inline(always)]
    fn from(ciphersuite_name: CiphersuiteName) -> Self {
        ciphersuite_name.signature_algorithm()
    }
}

impl From<CiphersuiteName> for AeadType {
    #[inline(always)]
    fn from(ciphersuite_name: CiphersuiteName) -> Self {
        ciphersuite_name.aead_algorithm()
    }
}

impl From<CiphersuiteName> for HpkeKemType {
    #[inline(always)]
    fn from(ciphersuite_name: CiphersuiteName) -> Self {
        ciphersuite_name.hpke_kem_algorithm()
    }
}

impl From<CiphersuiteName> for HpkeAeadType {
    #[inline(always)]
    fn from(ciphersuite_name: CiphersuiteName) -> Self {
        ciphersuite_name.hpke_aead_algorithm()
    }
}

impl From<CiphersuiteName> for HpkeKdfType {
    #[inline(always)]
    fn from(ciphersuite_name: CiphersuiteName) -> Self {
        ciphersuite_name.hpke_kdf_algorithm()
    }
}

impl From<CiphersuiteName> for HashType {
    #[inline(always)]
    fn from(ciphersuite_name: CiphersuiteName) -> Self {
        ciphersuite_name.hash_algorithm()
    }
}

impl CiphersuiteName {
    /// Get the [`HashType`] of the [`CiphersuiteName`]
    pub const fn hash_algorithm(&self) -> HashType {
        match self {
            CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
            | CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                HashType::Sha2_256
            }
            CiphersuiteName::MLS10_256_DHKEMP384_AES256GCM_SHA384_P384 => HashType::Sha2_384,
            CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
            | CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                HashType::Sha2_512
            }
        }
    }

    pub const fn signature_algorithm(&self) -> SignatureScheme {
        match self {
            CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                SignatureScheme::ED25519
            }
            CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                SignatureScheme::ECDSA_SECP256R1_SHA256
            }
            CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                SignatureScheme::ECDSA_SECP521R1_SHA512
            }
            CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                SignatureScheme::ED448
            }
            CiphersuiteName::MLS10_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                SignatureScheme::ECDSA_SECP384R1_SHA384
            }
        }
    }

    pub const fn aead_algorithm(&self) -> AeadType {
        match self {
            CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => AeadType::Aes128Gcm,
            CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                AeadType::ChaCha20Poly1305
            }
            CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
            | CiphersuiteName::MLS10_256_DHKEMP384_AES256GCM_SHA384_P384 => AeadType::Aes256Gcm,
        }
    }

    pub const fn hpke_kdf_algorithm(&self) -> HpkeKdfType {
        match self {
            CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
            | CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                HpkeKdfType::HkdfSha256
            }
            CiphersuiteName::MLS10_256_DHKEMP384_AES256GCM_SHA384_P384 => HpkeKdfType::HkdfSha384,
            CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
            | CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                HpkeKdfType::HkdfSha512
            }
        }
    }

    pub const fn hpke_kem_algorithm(&self) -> HpkeKemType {
        match self {
            CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                HpkeKemType::DhKem25519
            }
            CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => HpkeKemType::DhKemP256,
            CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                HpkeKemType::DhKem448
            }
            CiphersuiteName::MLS10_256_DHKEMP384_AES256GCM_SHA384_P384 => HpkeKemType::DhKemP384,
            CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => HpkeKemType::DhKemP521,
        }
    }

    pub const fn hpke_aead_algorithm(&self) -> HpkeAeadType {
        match self {
            CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => HpkeAeadType::AesGcm128,
            CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                HpkeAeadType::ChaCha20Poly1305
            }
            CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CiphersuiteName::MLS10_256_DHKEMP384_AES256GCM_SHA384_P384
            | CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => HpkeAeadType::AesGcm256,
            CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                HpkeAeadType::ChaCha20Poly1305
            }
        }
    }
}
