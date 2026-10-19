//! # OpenMLS Types
//!
//! This module holds a number of types that are needed by the traits.

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use tls_codec::{
    SecretVLBytes, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSerializeBytes, TlsSize,
    VLBytes,
};

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
    TlsSerializeBytes,
    TlsDeserialize,
    TlsDeserializeBytes,
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
    /// ML-DSA44
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLDSA44 = 0x0904,
    /// ML-DSA65
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLDSA65 = 0x0905,
    /// ML-DSA87
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLDSA87 = 0x0906,
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
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            0x0904 => Ok(SignatureScheme::MLDSA44),
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            0x0905 => Ok(SignatureScheme::MLDSA65),
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            0x0906 => Ok(SignatureScheme::MLDSA87),
            _ => Err(format!("Unsupported SignatureScheme: {value}")),
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
#[derive(PartialEq, Eq, Copy, Clone, Debug, Serialize, Deserialize)]
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

    /// ML-KEM-768
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MlKem768 = 0x0041,

    /// ML-KEM-1024
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MlKem1024 = 0x0042,

    /// ML-KEM-768 + P-256 hybrid KEM
    ///
    /// Code point from [draft-ietf-hpke-pq], which registers it as
    /// `MLKEM768-P256` (the instance from [draft-irtf-cfrg-concrete-hybrid-kems]).
    ///
    /// [draft-ietf-hpke-pq]: https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq
    /// [draft-irtf-cfrg-concrete-hybrid-kems]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MlKem768P256 = 0x0050,

    /// ML-KEM-1024 + P-384 hybrid KEM
    ///
    /// Code point from [draft-ietf-hpke-pq], which registers it as
    /// `MLKEM1024-P384` (the instance from [draft-irtf-cfrg-concrete-hybrid-kems]).
    ///
    /// [draft-ietf-hpke-pq]: https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq
    /// [draft-irtf-cfrg-concrete-hybrid-kems]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MlKem1024P384 = 0x0051,

    /// XWing combiner for ML-KEM and X25519
    ///
    /// Code point from [draft-ietf-hpke-pq], which registers it as
    /// `MLKEM768-X25519`.
    ///
    /// [draft-ietf-hpke-pq]: https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    XWingKemDraft6 = 0x647a,
}

/// KDF Types for HPKE
#[derive(PartialEq, Eq, Copy, Clone, Debug, Serialize, Deserialize)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

impl std::fmt::Debug for HpkePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dt = f.debug_tuple("HpkePrivateKey");

        #[cfg(feature = "crypto-debug")]
        dt.field(&self.0);
        #[cfg(not(feature = "crypto-debug"))]
        dt.field(&"***");

        dt.finish()
    }
}

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
#[derive(Clone)]
pub struct ExporterSecret(SecretVLBytes);

impl std::fmt::Debug for ExporterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dt = f.debug_tuple("ExporterSecret");

        #[cfg(feature = "crypto-debug")]
        dt.field(&self.0);
        #[cfg(not(feature = "crypto-debug"))]
        dt.field(&"***");

        dt.finish()
    }
}

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

    /// Returns the raw u16 value of this ciphersuite.
    pub fn value(&self) -> u16 {
        self.0
    }

    /// Returns true if this is a GREASE ciphersuite value.
    ///
    /// GREASE values are used to ensure implementations properly handle unknown
    /// ciphersuites. See [RFC 9420 Section 13.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5).
    ///
    /// GREASE ciphersuites cannot be used for actual cryptographic operations.
    pub fn is_grease(&self) -> bool {
        crate::grease::is_grease_value(self.0)
    }
}

impl From<Ciphersuite> for VerifiableCiphersuite {
    fn from(value: Ciphersuite) -> Self {
        Self(value as u16)
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
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
#[repr(u16)]
pub enum Ciphersuite {
    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,

    /// DH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P256
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,

    /// DH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,

    /// DH KEM x448 | AES-GCM 256 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,

    /// DH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,

    /// DH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,

    /// DH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,

    /// X-WING KEM draft-01 | Chacha20Poly1305 | SHA2-256 | Ed25519
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 = 0x004D,

    /// ML-KEM1024 | AES-GCM256 | SHA2-512 | ML-DSA87
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87 = 0x0906,

    /// ML-KEM768 + X25519 (XWing) | AES-GCM128 | SHA2-256 | Ed25519
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD1 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519 = 0x004F,

    /// ML-KEM768 + X25519 (XWing) | AES-GCM256 | SHA2-384 | Ed25519
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD2 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519 = 0x004E,

    /// ML-KEM768 + P-256 | AES-GCM128 | SHA2-256 | EcDSA P256
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD3 (custom provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_128_MLKEM768P256_AES128GCM_SHA256_P256 = 0xF050,

    /// ML-KEM768 + P-256 | AES-GCM256 | SHA2-384 | EcDSA P256
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD4 (custom provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_128_MLKEM768P256_AES256GCM_SHA384_P256 = 0xF051,

    /// ML-KEM1024 + P-384 | AES-GCM256 | SHA2-384 | EcDSA P384
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD5 (custom provisional code point)
    ///
    /// Not supported by any of the OpenMLS crypto providers yet: libcrux has no
    /// ECDSA P-384 implementation and the RustCrypto HPKE backend has no
    /// ML-KEM1024 + P-384 hybrid KEM.
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384 = 0xF052,

    /// ML-KEM768 | AES-GCM256 | SHA2-384 | Ed25519
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD6 (custom provisional code point, kept from the
    /// former AIR_128_MLKEM768_AES256GCM_SHA384_Ed25519 ciphersuite for backwards compatibility)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519 = 0xF042,

    /// ML-KEM768 | AES-GCM256 | SHA2-384 | EcDSA P256
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD7 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_128_MLKEM768_AES256GCM_SHA384_P256 = 0x0050,

    /// ML-KEM1024 | AES-GCM256 | SHA2-384 | EcDSA P384
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD8 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_192_MLKEM1024_AES256GCM_SHA384_P384 = 0x0042,

    /// ML-KEM768 + X25519 (XWing) | Chacha20Poly1305 | SHA2-384 | ML-DSA44
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD9 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44 = 0x0052,

    /// ML-KEM768 | AES-GCM256 | SHA2-384 | ML-DSA65
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD10 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65 = 0x0051,

    /// ML-KEM1024 | AES-GCM256 | SHA2-384 | ML-DSA87
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD11 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 = 0x0907,
}

impl core::fmt::Display for Ciphersuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<Ciphersuite> for u16 {
    #[inline(always)]
    fn from(s: Ciphersuite) -> u16 {
        s as u16
    }
}

impl From<&Ciphersuite> for u16 {
    #[inline(always)]
    fn from(s: &Ciphersuite) -> u16 {
        *s as u16
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
            _ => Self::pq_from_u16(v).ok_or_else(|| {
                Self::Error::DecodingError(format!("{v} is not a valid ciphersuite value"))
            }),
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

/// The algorithms of a ciphersuite: (KEM, KDF, AEAD, Hash, Signature), as in the
/// ciphersuite tables of RFC 9420 and draft-ietf-mls-pq-ciphersuites.
type CiphersuiteAlgorithms = (
    HpkeKemType,
    HpkeKdfType,
    AeadType,
    HashType,
    SignatureScheme,
);

impl Ciphersuite {
    #[rustfmt::skip]
    #[inline]
    const fn algorithms(&self) -> CiphersuiteAlgorithms {
        use AeadType::*;
        use HashType::*;
        use HpkeKdfType::*;
        use HpkeKemType::*;
        use SignatureScheme::*;

        match self {
            Self::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519        => (DhKem25519, HkdfSha256, Aes128Gcm,        Sha2_256, ED25519),
            Self::MLS_128_DHKEMP256_AES128GCM_SHA256_P256             => (DhKemP256,  HkdfSha256, Aes128Gcm,        Sha2_256, ECDSA_SECP256R1_SHA256),
            Self::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => (DhKem25519, HkdfSha256, ChaCha20Poly1305, Sha2_256, ED25519),
            Self::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448            => (DhKem448,   HkdfSha512, Aes256Gcm,        Sha2_512, ED448),
            Self::MLS_256_DHKEMP521_AES256GCM_SHA512_P521             => (DhKemP521,  HkdfSha512, Aes256Gcm,        Sha2_512, ECDSA_SECP521R1_SHA512),
            Self::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448     => (DhKem448,   HkdfSha512, ChaCha20Poly1305, Sha2_512, ED448),
            Self::MLS_256_DHKEMP384_AES256GCM_SHA384_P384             => (DhKemP384,  HkdfSha384, Aes256Gcm,        Sha2_384, ECDSA_SECP384R1_SHA384),
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            pq => pq.pq_algorithms(),
        }
    }

    /// The [`Self::algorithms`] of the [draft-ietf-mls-pq-ciphersuites] ciphersuites.
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    #[rustfmt::skip]
    #[inline]
    const fn pq_algorithms(&self) -> CiphersuiteAlgorithms {
        use AeadType::*;
        use HashType::*;
        use HpkeKdfType::*;
        use HpkeKemType::*;
        use SignatureScheme::*;

        match self {
            Self::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519          => (XWingKemDraft6, HkdfSha256, ChaCha20Poly1305, Sha2_256, ED25519),
            Self::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87             => (MlKem1024,      HkdfSha512, Aes256Gcm,        Sha2_512, MLDSA87),
            Self::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519        => (XWingKemDraft6, HkdfSha256, Aes128Gcm,        Sha2_256, ED25519),
            Self::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519        => (XWingKemDraft6, HkdfSha384, Aes256Gcm,        Sha2_384, ED25519),
            Self::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256             => (MlKem768P256,   HkdfSha256, Aes128Gcm,        Sha2_256, ECDSA_SECP256R1_SHA256),
            Self::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256             => (MlKem768P256,   HkdfSha384, Aes256Gcm,        Sha2_384, ECDSA_SECP256R1_SHA256),
            Self::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384            => (MlKem1024P384,  HkdfSha384, Aes256Gcm,        Sha2_384, ECDSA_SECP384R1_SHA384),
            Self::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519              => (MlKem768,       HkdfSha384, Aes256Gcm,        Sha2_384, ED25519),
            Self::MLS_128_MLKEM768_AES256GCM_SHA384_P256                 => (MlKem768,       HkdfSha384, Aes256Gcm,        Sha2_384, ECDSA_SECP256R1_SHA256),
            Self::MLS_192_MLKEM1024_AES256GCM_SHA384_P384                => (MlKem1024,      HkdfSha384, Aes256Gcm,        Sha2_384, ECDSA_SECP384R1_SHA384),
            Self::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44 => (XWingKemDraft6, HkdfSha384, ChaCha20Poly1305, Sha2_384, MLDSA44),
            Self::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65              => (MlKem768,       HkdfSha384, Aes256Gcm,        Sha2_384, MLDSA65),
            Self::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87             => (MlKem1024,      HkdfSha384, Aes256Gcm,        Sha2_384, MLDSA87),
            // Listed explicitly rather than `_`, so that a ciphersuite missing
            // from both tables is a compile error instead of endless recursion.
            Self::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Self::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Self::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Self::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Self::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Self::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | Self::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => self.algorithms(),
        }
    }

    /// Decodes the code points of the [draft-ietf-mls-pq-ciphersuites] ciphersuites.
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    const fn pq_from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0x004D => Self::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            0x0906 => Self::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
            0x004F => Self::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
            0x004E => Self::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
            0xF050 => Self::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
            0xF051 => Self::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256,
            0xF052 => Self::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
            0xF042 => Self::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519,
            0x0050 => Self::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
            0x0042 => Self::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
            0x0052 => Self::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44,
            0x0051 => Self::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
            0x0907 => Self::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
            _ => return None,
        })
    }

    #[cfg(not(feature = "draft-ietf-mls-pq-ciphersuites"))]
    const fn pq_from_u16(_v: u16) -> Option<Self> {
        None
    }

    /// Get the [`HashType`] for this [`Ciphersuite`]
    #[inline]
    pub const fn hash_algorithm(&self) -> HashType {
        self.algorithms().3
    }

    /// Get the [`SignatureScheme`] for this [`Ciphersuite`].
    #[inline]
    pub const fn signature_algorithm(&self) -> SignatureScheme {
        self.algorithms().4
    }

    /// Get the [`AeadType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn aead_algorithm(&self) -> AeadType {
        self.algorithms().2
    }

    /// Get the [`HpkeKdfType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_kdf_algorithm(&self) -> HpkeKdfType {
        self.algorithms().1
    }

    /// Get the [`HpkeKemType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_kem_algorithm(&self) -> HpkeKemType {
        self.algorithms().0
    }

    /// Get the [`HpkeAeadType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_aead_algorithm(&self) -> HpkeAeadType {
        // A ciphersuite has a single AEAD, used both by MLS and HPKE.
        match self.aead_algorithm() {
            AeadType::Aes128Gcm => HpkeAeadType::AesGcm128,
            AeadType::Aes256Gcm => HpkeAeadType::AesGcm256,
            AeadType::ChaCha20Poly1305 => HpkeAeadType::ChaCha20Poly1305,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphersuite_code_points_round_trip() {
        let mut decoded = 0;
        for v in 0..=u16::MAX {
            if let Ok(ciphersuite) = Ciphersuite::try_from(v) {
                assert_eq!(u16::from(ciphersuite), v, "{ciphersuite}");
                decoded += 1;
            }
        }

        // Update when adding a ciphersuite.
        let expected = if cfg!(feature = "draft-ietf-mls-pq-ciphersuites") {
            20
        } else {
            7
        };
        assert_eq!(decoded, expected);
    }
}
