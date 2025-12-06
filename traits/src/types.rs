//! # OpenMLS Types
//!
//! This module holds a number of types that are needed by the traits.

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use tls_codec::{
    SecretVLBytes, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Serialize, Deserialize)]
/// AEAD types
pub enum AeadType {
    /// AES GCM 128
    Aes128Gcm,

    /// AES GCM 256
    Aes256Gcm,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305,

    /// Custom AEAD type
    Custom {
        /// The raw value for this custom AEAD type
        value: u16,
        /// Tag size in bytes
        tag_size: usize,
        /// Key size in bytes
        key_size: usize,
        /// Nonce size in bytes
        nonce_size: usize,
    },
}

impl AeadType {
    /// Get the tag size of the [`AeadType`] in bytes.
    pub const fn tag_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 16,
            AeadType::ChaCha20Poly1305 => 16,
            AeadType::Custom { tag_size, .. } => *tag_size,
        }
    }

    /// Get the key size of the [`AeadType`] in bytes.
    pub const fn key_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 32,
            AeadType::ChaCha20Poly1305 => 32,
            AeadType::Custom { key_size, .. } => *key_size,
        }
    }

    /// Get the nonce size of the [`AeadType`] in bytes.
    pub const fn nonce_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm | AeadType::Aes256Gcm | AeadType::ChaCha20Poly1305 => 12,
            AeadType::Custom { nonce_size, .. } => *nonce_size,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
/// Hash types
pub enum HashType {
    Sha2_256,
    Sha2_384,
    Sha2_512,
    /// Custom hash type
    Custom {
        /// The raw value for this custom hash type
        value: u8,
        /// Output size in bytes
        size: usize,
    },
}

impl HashType {
    /// Returns the output size of a hash by [`HashType`].
    #[inline]
    pub const fn size(&self) -> usize {
        match self {
            HashType::Sha2_256 => 32,
            HashType::Sha2_384 => 48,
            HashType::Sha2_512 => 64,
            HashType::Custom { size, .. } => *size,
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
)]
pub enum SignatureScheme {
    /// ECDSA_SECP256R1_SHA256
    ECDSA_SECP256R1_SHA256,
    /// ECDSA_SECP384R1_SHA384
    ECDSA_SECP384R1_SHA384,
    /// ECDSA_SECP521R1_SHA512
    ECDSA_SECP521R1_SHA512,
    /// ED25519
    ED25519,
    /// ED448
    ED448,
    /// Custom signature scheme
    Custom {
        /// The raw value for this custom signature scheme
        value: u16,
    },
}

impl SignatureScheme {
    /// Get the u16 value for this signature scheme
    pub const fn value(&self) -> u16 {
        match self {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => 0x0403,
            SignatureScheme::ECDSA_SECP384R1_SHA384 => 0x0503,
            SignatureScheme::ECDSA_SECP521R1_SHA512 => 0x0603,
            SignatureScheme::ED25519 => 0x0807,
            SignatureScheme::ED448 => 0x0808,
            SignatureScheme::Custom { value } => *value,
        }
    }
}

impl tls_codec::Size for SignatureScheme {
    fn tls_serialized_len(&self) -> usize {
        2 // u16
    }
}

impl tls_codec::Serialize for SignatureScheme {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.value().tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for SignatureScheme {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let value = u16::tls_deserialize(bytes)?;
        Ok(SignatureScheme::from(value))
    }
}

impl tls_codec::DeserializeBytes for SignatureScheme {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error> {
        let (value, rest) = u16::tls_deserialize_bytes(bytes)?;
        Ok((SignatureScheme::from(value), rest))
    }
}

impl From<u16> for SignatureScheme {
    fn from(value: u16) -> Self {
        match value {
            0x0403 => SignatureScheme::ECDSA_SECP256R1_SHA256,
            0x0503 => SignatureScheme::ECDSA_SECP384R1_SHA384,
            0x0603 => SignatureScheme::ECDSA_SECP521R1_SHA512,
            0x0807 => SignatureScheme::ED25519,
            0x0808 => SignatureScheme::ED448,
            _ => SignatureScheme::Custom { value },
        }
    }
}

/// Crypto errors.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CryptoError {
    CryptoLibraryError,
    AeadDecryptionError,
    HpkeDecryptionError,
    HpkeEncryptionError,
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
    UnsupportedCiphersuite,
    TlsSerializationError,
    TooMuchData,
    SigningError,
    InvalidPublicKey,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CryptoError {}

// === HPKE === //

/// Convenience tuple struct for an HPKE configuration.
#[derive(Debug)]
pub struct HpkeConfig(pub HpkeKemType, pub HpkeKdfType, pub HpkeAeadType);

/// KEM Types for HPKE
#[derive(PartialEq, Eq, Copy, Clone, Debug, Hash, Serialize, Deserialize)]
pub enum HpkeKemType {
    /// DH KEM on P256
    DhKemP256,

    /// DH KEM on P384
    DhKemP384,

    /// DH KEM on P521
    DhKemP521,

    /// DH KEM on x25519
    DhKem25519,

    /// DH KEM on x448
    DhKem448,

    /// XWing combiner for ML-KEM and X25519
    XWingKemDraft6,

    /// Custom KEM type
    Custom {
        /// The raw value for this custom KEM type
        value: u16,
    },
}

impl HpkeKemType {
    /// Get the u16 value for this KEM type
    pub const fn value(&self) -> u16 {
        match self {
            HpkeKemType::DhKemP256 => 0x0010,
            HpkeKemType::DhKemP384 => 0x0011,
            HpkeKemType::DhKemP521 => 0x0012,
            HpkeKemType::DhKem25519 => 0x0020,
            HpkeKemType::DhKem448 => 0x0021,
            HpkeKemType::XWingKemDraft6 => 0x004D,
            HpkeKemType::Custom { value } => *value,
        }
    }
}

impl From<u16> for HpkeKemType {
    fn from(value: u16) -> Self {
        match value {
            0x0010 => HpkeKemType::DhKemP256,
            0x0011 => HpkeKemType::DhKemP384,
            0x0012 => HpkeKemType::DhKemP521,
            0x0020 => HpkeKemType::DhKem25519,
            0x0021 => HpkeKemType::DhKem448,
            0x004D => HpkeKemType::XWingKemDraft6,
            _ => HpkeKemType::Custom { value },
        }
    }
}

/// KDF Types for HPKE
#[derive(PartialEq, Eq, Copy, Clone, Debug, Hash, Serialize, Deserialize)]
pub enum HpkeKdfType {
    /// HKDF SHA 256
    HkdfSha256,

    /// HKDF SHA 384
    HkdfSha384,

    /// HKDF SHA 512
    HkdfSha512,

    /// Custom KDF type
    Custom {
        /// The raw value for this custom KDF type
        value: u16,
    },
}

impl HpkeKdfType {
    /// Get the u16 value for this KDF type
    pub const fn value(&self) -> u16 {
        match self {
            HpkeKdfType::HkdfSha256 => 0x0001,
            HpkeKdfType::HkdfSha384 => 0x0002,
            HpkeKdfType::HkdfSha512 => 0x0003,
            HpkeKdfType::Custom { value } => *value,
        }
    }
}

impl From<u16> for HpkeKdfType {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => HpkeKdfType::HkdfSha256,
            0x0002 => HpkeKdfType::HkdfSha384,
            0x0003 => HpkeKdfType::HkdfSha512,
            _ => HpkeKdfType::Custom { value },
        }
    }
}

/// AEAD Types for HPKE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HpkeAeadType {
    /// AES GCM 128
    AesGcm128,

    /// AES GCM 256
    AesGcm256,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305,

    /// Export-only
    Export,

    /// Custom HPKE AEAD type
    Custom {
        /// The raw value for this custom HPKE AEAD type
        value: u16,
    },
}

impl HpkeAeadType {
    /// Get the u16 value for this HPKE AEAD type
    pub const fn value(&self) -> u16 {
        match self {
            HpkeAeadType::AesGcm128 => 0x0001,
            HpkeAeadType::AesGcm256 => 0x0002,
            HpkeAeadType::ChaCha20Poly1305 => 0x0003,
            HpkeAeadType::Export => 0xFFFF,
            HpkeAeadType::Custom { value } => *value,
        }
    }
}

impl From<u16> for HpkeAeadType {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => HpkeAeadType::AesGcm128,
            0x0002 => HpkeAeadType::AesGcm256,
            0x0003 => HpkeAeadType::ChaCha20Poly1305,
            0xFFFF => HpkeAeadType::Export,
            _ => HpkeAeadType::Custom { value },
        }
    }
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     opaque kem_output<V>;
///     opaque ciphertext<V>;
/// } HPKECiphertext;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct HpkeCiphertext {
    pub kem_output: VLBytes,
    pub ciphertext: VLBytes,
}

/// A simple type for HPKE private keys.
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
#[cfg_attr(feature = "test-utils", derive(PartialEq, Eq))]
#[serde(transparent)]
pub struct HpkePrivateKey(SecretVLBytes);

impl From<Vec<u8>> for HpkePrivateKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }
}

impl From<&[u8]> for HpkePrivateKey {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }
}

impl std::ops::Deref for HpkePrivateKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

/// Helper holding a (private, public) key pair as byte vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeKeyPair {
    pub private: HpkePrivateKey,
    pub public: Vec<u8>,
}

pub type KemOutput = Vec<u8>;
#[derive(Clone, Debug)]
pub struct ExporterSecret(SecretVLBytes);

impl Deref for ExporterSecret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl From<Vec<u8>> for ExporterSecret {
    fn from(secret: Vec<u8>) -> Self {
        Self(secret.into())
    }
}

/// A currently unknown ciphersuite.
///
/// Used to accept unknown values, e.g., in `Capabilities`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct VerifiableCiphersuite(u16);

impl VerifiableCiphersuite {
    pub fn new(value: u16) -> Self {
        Self(value)
    }
}

impl From<Ciphersuite> for VerifiableCiphersuite {
    fn from(value: Ciphersuite) -> Self {
        Self(value.value())
    }
}

impl TryFrom<VerifiableCiphersuite> for Ciphersuite {
    type Error = tls_codec::Error;

    fn try_from(value: VerifiableCiphersuite) -> Result<Self, Self::Error> {
        Ciphersuite::try_from(value.0)
    }
}

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
)]
pub enum Ciphersuite {
    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,

    /// DH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P256
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256,

    /// DH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,

    /// DH KEM x448 | AES-GCM 256 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,

    /// DH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521,

    /// DH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,

    /// DH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384,

    /// X-WING KEM draft-01 | Chacha20Poly1305 | SHA2-256 | Ed25519
    MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,

    /// Custom ciphersuite with user-provided algorithms
    Custom {
        /// The raw value for this custom ciphersuite
        value: u16,
        /// The hash algorithm to use
        hash_algorithm: HashType,
        /// The signature scheme to use
        signature_algorithm: SignatureScheme,
        /// The AEAD algorithm to use
        aead_algorithm: AeadType,
        /// The HPKE KDF algorithm to use
        hpke_kdf_algorithm: HpkeKdfType,
        /// The HPKE KEM algorithm to use
        hpke_kem_algorithm: HpkeKemType,
        /// The HPKE AEAD algorithm to use
        hpke_aead_algorithm: HpkeAeadType,
    },
}

impl Ciphersuite {
    /// Get the u16 value for this ciphersuite
    pub const fn value(&self) -> u16 {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => 0x0001,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => 0x0002,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => 0x0003,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 => 0x0004,
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => 0x0005,
            Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => 0x0006,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => 0x0007,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => 0x004D,
            Ciphersuite::Custom { value, .. } => *value,
        }
    }
}

impl tls_codec::Size for Ciphersuite {
    fn tls_serialized_len(&self) -> usize {
        2 // u16
    }
}

impl tls_codec::Serialize for Ciphersuite {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.value().tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for Ciphersuite {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let value = u16::tls_deserialize(bytes)?;
        Ciphersuite::try_from(value)
    }
}

impl tls_codec::DeserializeBytes for Ciphersuite {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error> {
        let (value, rest) = u16::tls_deserialize_bytes(bytes)?;
        Ok((Ciphersuite::try_from(value)?, rest))
    }
}

impl core::fmt::Display for Ciphersuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<Ciphersuite> for u16 {
    #[inline(always)]
    fn from(s: Ciphersuite) -> u16 {
        s.value()
    }
}

impl From<&Ciphersuite> for u16 {
    #[inline(always)]
    fn from(s: &Ciphersuite) -> u16 {
        s.value()
    }
}

impl TryFrom<u16> for Ciphersuite {
    type Error = tls_codec::Error;

    #[inline(always)]
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            0x0002 => Ok(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
            0x0003 => Ok(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            0x0004 => Ok(Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448),
            0x0005 => Ok(Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521),
            0x0006 => Ok(Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),
            0x0007 => Ok(Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384),
            0x004D => Ok(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519),
            _ => Err(Self::Error::DecodingError(format!(
                "{v} is not a valid ciphersuite value"
            ))),
        }
    }
}

impl From<Ciphersuite> for SignatureScheme {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.signature_algorithm()
    }
}

impl From<Ciphersuite> for AeadType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.aead_algorithm()
    }
}

impl From<Ciphersuite> for HpkeKemType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hpke_kem_algorithm()
    }
}

impl From<Ciphersuite> for HpkeAeadType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hpke_aead_algorithm()
    }
}

impl From<Ciphersuite> for HpkeKdfType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hpke_kdf_algorithm()
    }
}

impl From<Ciphersuite> for HashType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hash_algorithm()
    }
}

impl Ciphersuite {
    /// Get the [`HashType`] for this [`Ciphersuite`]
    #[inline]
    pub const fn hash_algorithm(&self) -> HashType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => HashType::Sha2_256,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => HashType::Sha2_384,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => HashType::Sha2_512,
            Ciphersuite::Custom { hash_algorithm, .. } => *hash_algorithm,
        }
    }

    /// Get the [`SignatureScheme`] for this [`Ciphersuite`].
    #[inline]
    pub const fn signature_algorithm(&self) -> SignatureScheme {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                SignatureScheme::ED25519
            }
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                SignatureScheme::ECDSA_SECP256R1_SHA256
            }
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                SignatureScheme::ECDSA_SECP521R1_SHA512
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                SignatureScheme::ED448
            }
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                SignatureScheme::ECDSA_SECP384R1_SHA384
            }
            Ciphersuite::Custom { signature_algorithm, .. } => *signature_algorithm,
        }
    }

    /// Get the [`AeadType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn aead_algorithm(&self) -> AeadType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => AeadType::Aes128Gcm,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                AeadType::ChaCha20Poly1305
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => AeadType::Aes256Gcm,
            Ciphersuite::Custom { aead_algorithm, .. } => *aead_algorithm,
        }
    }

    /// Get the [`HpkeKdfType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_kdf_algorithm(&self) -> HpkeKdfType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Self::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => HpkeKdfType::HkdfSha256,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => HpkeKdfType::HkdfSha384,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                HpkeKdfType::HkdfSha512
            }
            Ciphersuite::Custom { hpke_kdf_algorithm, .. } => *hpke_kdf_algorithm,
        }
    }

    /// Get the [`HpkeKemType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_kem_algorithm(&self) -> HpkeKemType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                HpkeKemType::DhKem25519
            }
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => HpkeKemType::DhKemP256,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => HpkeKemType::DhKem448,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => HpkeKemType::DhKemP384,
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => HpkeKemType::DhKemP521,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                HpkeKemType::XWingKemDraft6
            }
            Ciphersuite::Custom { hpke_kem_algorithm, .. } => *hpke_kem_algorithm,
        }
    }

    /// Get the [`HpkeAeadType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_aead_algorithm(&self) -> HpkeAeadType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => HpkeAeadType::AesGcm128,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                HpkeAeadType::ChaCha20Poly1305
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => HpkeAeadType::AesGcm256,
            Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                HpkeAeadType::ChaCha20Poly1305
            }
            Ciphersuite::Custom { hpke_aead_algorithm, .. } => *hpke_aead_algorithm,
        }
    }

    /// Get the [`HpkeConfig`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_config(&self) -> HpkeConfig {
        HpkeConfig(
            self.hpke_kem_algorithm(),
            self.hpke_kdf_algorithm(),
            self.hpke_aead_algorithm(),
        )
    }

    /// Get the length of the used hash algorithm.
    #[inline]
    pub const fn hash_length(&self) -> usize {
        self.hash_algorithm().size()
    }

    /// Get the length of the AEAD tag.
    #[inline]
    pub const fn mac_length(&self) -> usize {
        self.aead_algorithm().tag_size()
    }

    /// Returns the key size of the used AEAD.
    #[inline]
    pub const fn aead_key_length(&self) -> usize {
        self.aead_algorithm().key_size()
    }

    /// Returns the length of the nonce of the AEAD.
    #[inline]
    pub const fn aead_nonce_length(&self) -> usize {
        self.aead_algorithm().nonce_size()
    }
}
