//! Ciphersuites for MLS
//!
//! This file contains the API to interact with ciphersuites.
//! See `codec.rs` and `ciphersuites.rs` for internals.

use ::tls_codec::{Size, TlsDeserialize, TlsSerialize, TlsSize};
use hpke::prelude::*;
use rand_chacha::ChaCha20Rng;
pub(crate) use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};
use std::{hash::Hash, sync::Mutex};
use tls_codec::{Serialize as TlsSerializeTrait, TlsByteVecU16, TlsByteVecU32, TlsByteVecU8};

// re-export for other parts of the library when we can use it
pub(crate) use hpke::{HpkeKeyPair, HpkePrivateKey, HpkePublicKey};

mod ciphersuites;
mod codec;
mod crypto;
mod errors;
mod rand;
pub mod signable;

mod ser;

use crate::{
    ciphersuite::rand::random_vec,
    config::{Config, ConfigError, ProtocolVersion},
};

use ciphersuites::*;
use crypto::*;
pub(crate) use errors::*;

use self::{rand::random_array, signable::SignedStruct};

#[cfg(test)]
mod tests;

pub(crate) const NONCE_BYTES: usize = 12;
pub(crate) const REUSE_GUARD_BYTES: usize = 4;

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
pub enum CiphersuiteName {
    MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
}

implement_enum_display!(CiphersuiteName);

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
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
#[repr(u16)]
pub enum SignatureScheme {
    /// ECDSA_SECP256R1_SHA256
    ECDSA_SECP256R1_SHA256 = 0x0403,
    /// ECDSA_SECP521R1_SHA512
    ECDSA_SECP521R1_SHA512 = 0x0603,
    /// ED25519
    ED25519 = 0x0807,
    /// ED448
    ED448 = 0x0808,
}

impl SignatureScheme {
    /// Create a new signature key pair and return it.
    pub(crate) fn new_keypair(&self) -> Result<SignatureKeypair, CryptoError> {
        SignatureKeypair::new(*self)
    }
}

impl TryFrom<u16> for SignatureScheme {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0403 => Ok(SignatureScheme::ECDSA_SECP256R1_SHA256),
            0x0603 => Ok(SignatureScheme::ECDSA_SECP521R1_SHA512),
            0x0807 => Ok(SignatureScheme::ED25519),
            0x0808 => Ok(SignatureScheme::ED448),
            _ => Err(format!("Unsupported SignatureScheme: {}", value)),
        }
    }
}

impl From<CiphersuiteName> for SignatureScheme {
    fn from(ciphersuite_name: CiphersuiteName) -> Self {
        match ciphersuite_name {
            CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                SignatureScheme::ED25519
            }
            CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                SignatureScheme::ECDSA_SECP256R1_SHA256
            }
            CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                SignatureScheme::ED25519
            }
            CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 => SignatureScheme::ED448,
            CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                SignatureScheme::ECDSA_SECP521R1_SHA512
            }
            CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                SignatureScheme::ED448
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
/// AEAD types
pub enum AeadType {
    /// AES GCM 128
    Aes128Gcm = 0x0001,

    /// AES GCM 256
    Aes256Gcm = 0x0002,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305 = 0x0003,

    /// HPKE Export-only
    HpkeExport = 0xFFFF,
}

impl AeadType {
    /// Get the tag size of the [`AeadType`] in bytes.
    ///
    /// Note that the function returns `0` for unknown lengths such as the
    /// [`AeadType::HpkeExport`] type.
    pub const fn tag_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 16,
            AeadType::ChaCha20Poly1305 => 16,
            AeadType::HpkeExport => 0,
        }
    }

    /// Get the key size of the [`AeadType`] in bytes.
    ///
    /// Note that the function returns `0` for unknown lengths such as the
    /// [`AeadType::HpkeExport`] type.
    pub const fn key_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 32,
            AeadType::ChaCha20Poly1305 => 32,
            AeadType::HpkeExport => 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
#[allow(non_camel_case_types)]
/// Hash types
pub enum HashType {
    Sha1 = 0x02,
    Sha2_224 = 0x03,
    Sha2_256 = 0x04,
    Sha2_384 = 0x05,
    Sha2_512 = 0x06,
    Sha3_224 = 0x07,
    Sha3_256 = 0x08,
    Sha3_384 = 0x09,
    Sha3_512 = 0x0A,
    Shake_128 = 0x0B,
    Shake_256 = 0x0C,
}

impl HashType {
    /// Returns the output size of a hash by [`HashType`].
    ///
    /// Note that it will return `0` for variable lenght output types such as shake.
    #[inline]
    pub const fn size(&self) -> usize {
        match self {
            HashType::Sha1 => 20,
            HashType::Sha2_224 => 28,
            HashType::Sha2_256 => 32,
            HashType::Sha2_384 => 48,
            HashType::Sha2_512 => 64,
            HashType::Sha3_224 => 28,
            HashType::Sha3_256 => 32,
            HashType::Sha3_384 => 48,
            HashType::Sha3_512 => 64,
            HashType::Shake_128 => 0,
            HashType::Shake_256 => 0,
        }
    }
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
    kem_output: TlsByteVecU16,
    ciphertext: TlsByteVecU16,
}

#[cfg(test)]
impl HpkeCiphertext {
    /// This function flips the last byte of the ciphertext.
    pub fn flip_last_byte(&mut self) {
        let mut last_bits = self.ciphertext.pop().unwrap();
        last_bits ^= 0xff;
        self.ciphertext.push(last_bits);
    }
}

/// `KdfLabel` is later serialized and used in the `label` field of
/// `kdf_expand_label`.
#[derive(TlsSerialize, TlsSize)]
struct KdfLabel {
    length: u16,
    label: TlsByteVecU8,
    context: TlsByteVecU32,
}

impl KdfLabel {
    /// Serialize this label.
    /// Returns the serialized label as byte vector or returns a [`CryptoError`]
    /// if the parameters are invalid.
    fn serialized_label(
        context: &[u8],
        label: String,
        length: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        if length > u16::MAX.into() {
            debug_assert!(
                false,
                "Library error: Trying to derive a key with a too large length field!"
            );
            return Err(CryptoError::KdfLabelTooLarge);
        }
        log::trace!(
            "KDF Label:\n length: {:?}\n label: {:?}\n context: {:x?}",
            length as u16,
            label,
            context
        );
        let kdf_label = KdfLabel {
            length: length as u16,
            label: label.as_bytes().into(),
            context: context.into(),
        };
        kdf_label
            .tls_serialize_detached()
            .map_err(|_| CryptoError::KdfSerializationError)
    }
}

/// Compare two byte slices in a way that's hopefully not optimised out by the
/// compiler.
#[inline(always)]
fn equal_ct(a: &[u8], b: &[u8]) -> bool {
    let mut diff = 0u8;
    for (l, r) in a.iter().zip(b.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}

/// A struct to contain secrets. This is to provide better visibility into where
/// and how secrets are used and to avoid passing secrets in their raw
/// representation.
#[derive(Clone, Debug)]
pub struct Secret {
    ciphersuite: &'static Ciphersuite,
    value: Vec<u8>,
    mls_version: ProtocolVersion,
}

implement_persistence!(Secret, value, mls_version);

impl Default for Secret {
    fn default() -> Self {
        Self {
            ciphersuite: Ciphersuite::default(),
            value: Vec::new(),
            mls_version: ProtocolVersion::default(),
        }
    }
}

impl PartialEq for Secret {
    // Constant time comparison.
    fn eq(&self, other: &Secret) -> bool {
        // These values can be considered public and checked before the actual
        // comparison.
        if self.ciphersuite != other.ciphersuite
            || self.mls_version != other.mls_version
            || self.value.len() != other.value.len()
        {
            log::error!("Incompatible secrets");
            log::trace!(
                "  {} {} {}",
                self.ciphersuite.name,
                self.mls_version,
                self.value.len()
            );
            log::trace!(
                "  {} {} {}",
                other.ciphersuite.name,
                other.mls_version,
                other.value.len()
            );
            return false;
        }
        equal_ct(&self.value, &other.value)
    }
}

impl Secret {
    /// Randomly sample a fresh `Secret`.
    /// This default random initialiser uses the default Secret length of `hash_length`.
    ///
    /// **NOTE: This has to wait until it can acquire the lock to get randomness!**
    /// TODO: This panics if another thread holding the rng panics.
    pub(crate) fn random(
        ciphersuite: &'static Ciphersuite,
        version: impl Into<Option<ProtocolVersion>>,
    ) -> Self {
        let mls_version = version.into().unwrap_or_default();
        log::trace!(
            "Creating a new random secret for {:?} and {:?}",
            ciphersuite.name,
            mls_version
        );
        let mut rng = ciphersuite.rng.lock().unwrap();
        Secret {
            value: random_vec(&mut *rng, ciphersuite.hash_length()),
            mls_version,
            ciphersuite,
        }
    }

    /// Create an all zero secret.
    pub(crate) fn zero(ciphersuite: &'static Ciphersuite, mls_version: ProtocolVersion) -> Self {
        Self {
            value: vec![0u8; ciphersuite.hash_length()],
            mls_version,
            ciphersuite,
        }
    }

    /// Create a new secret from a byte vector.
    pub(crate) fn from_slice(
        bytes: &[u8],
        mls_version: ProtocolVersion,
        ciphersuite: &'static Ciphersuite,
    ) -> Self {
        Secret {
            value: bytes.to_vec(),
            mls_version,
            ciphersuite,
        }
    }

    /// HKDF extract where `self` is `salt`.
    pub(crate) fn hkdf_extract<'a>(&self, ikm_option: impl Into<Option<&'a Secret>>) -> Self {
        log::trace!("HKDF extract with {:?}", self.ciphersuite.name);
        log_crypto!(trace, "  salt: {:x?}", self.value);
        let zero_secret = Self::zero(self.ciphersuite, self.mls_version);
        let ikm = ikm_option.into().unwrap_or(&zero_secret);
        log_crypto!(trace, "  ikm:  {:x?}", ikm.value);

        // We don't return an error here to keep the error propagation from
        // blowing up. If this fails, something in the library is really wrong
        // and we can't recover from it.
        assert!(
            self.mls_version == ikm.mls_version,
            "{} != {}",
            self.mls_version,
            ikm.mls_version
        );
        assert!(
            self.ciphersuite == ikm.ciphersuite,
            "{} != {}",
            self.ciphersuite,
            ikm.ciphersuite
        );

        Self {
            value: hkdf_extract(
                self.ciphersuite.hash,
                self.value.as_slice(),
                ikm.value.as_slice(),
            )
            .unwrap(),
            mls_version: self.mls_version,
            ciphersuite: self.ciphersuite,
        }
    }

    /// HKDF expand where `self` is `prk`.
    pub(crate) fn hkdf_expand(&self, info: &[u8], okm_len: usize) -> Result<Self, CryptoError> {
        let key = hkdf_expand(self.ciphersuite.hash, &self.value, info, okm_len)?;
        if key.is_empty() {
            return Err(CryptoError::InvalidLength);
        }
        Ok(Self {
            value: key,
            mls_version: self.mls_version,
            ciphersuite: self.ciphersuite,
        })
    }

    /// Expand a `Secret` to a new `Secret` of length `length` including a
    /// `label` and a `context`.
    pub(crate) fn kdf_expand_label(
        &self,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Secret, CryptoError> {
        let full_label = format!("{} {}", self.mls_version, label);
        log::trace!(
            "KDF expand with label \"{}\" and {:?} with context {:x?}",
            &full_label,
            self.ciphersuite.name(),
            context
        );
        let info = KdfLabel::serialized_label(context, full_label, length)?;
        log::trace!("  serialized context: {:x?}", info);
        log_crypto!(trace, "  secret: {:x?}", self.value);
        self.hkdf_expand(&info, length)
    }

    /// Derive a new `Secret` from the this one by expanding it with the given
    /// `label` and an empty `context`.
    pub(crate) fn derive_secret(&self, label: &str) -> Result<Secret, CryptoError> {
        log_crypto!(
            trace,
            "derive secret from {:x?} with label {} and {:?}",
            self.value,
            label,
            self.ciphersuite.name()
        );
        self.kdf_expand_label(label, &[], self.ciphersuite.hash_length())
    }

    /// Update the ciphersuite and MLS version of this secret.
    /// Ideally we wouldn't need this function but the way decoding works right
    /// now this is the easiest for now.
    pub(crate) fn config(
        &mut self,
        ciphersuite: &'static Ciphersuite,
        mls_version: ProtocolVersion,
    ) {
        self.ciphersuite = ciphersuite;
        self.mls_version = mls_version;
    }

    /// Returns the inner bytes of a secret
    pub fn as_slice(&self) -> &[u8] {
        &self.value
    }

    /// Returns the ciphersuite of the secret
    pub(crate) fn ciphersuite(&self) -> &'static Ciphersuite {
        self.ciphersuite
    }

    /// Returns the MLS version of the secret
    pub(crate) fn version(&self) -> ProtocolVersion {
        self.mls_version
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<&[u8]> for Secret {
    fn from(bytes: &[u8]) -> Self {
        log::trace!("Secret from slice");
        Secret {
            value: bytes.to_vec(),
            mls_version: ProtocolVersion::default(),
            ciphersuite: Ciphersuite::default(),
        }
    }
}

/// 9.2 Message framing
///
/// struct {
///     opaque mac_value<0..255>;
/// } MAC;
#[derive(Debug, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct Mac {
    pub(crate) mac_value: TlsByteVecU8,
}

impl PartialEq for Mac {
    // Constant time comparison.
    fn eq(&self, other: &Mac) -> bool {
        equal_ct(self.mac_value.as_slice(), other.mac_value.as_slice())
    }
}

impl Mac {
    /// HMAC-Hash(salt, IKM). For all supported ciphersuites this is the same
    /// HMAC that is also used in HKDF.
    /// Compute the HMAC on `salt` with key `ikm`.
    pub(crate) fn new(salt: &Secret, ikm: &[u8]) -> Self {
        Mac {
            mac_value: salt
                .hkdf_extract(&Secret::from_slice(ikm, salt.mls_version, salt.ciphersuite))
                .value
                .into(),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct AeadKey {
    aead_mode: AeadType,
    value: Vec<u8>,
    mac_len: usize,
}

#[derive(Debug, Clone, Copy, TlsSerialize, TlsDeserialize, TlsSize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ReuseGuard {
    value: [u8; REUSE_GUARD_BYTES],
}

impl ReuseGuard {
    /// Samples a fresh reuse guard uniformly at random.
    ///
    /// **NOTE: This has to wait until it can acquire the lock to get randomness!**
    /// TODO: This panics if another thread holding the rng panics.
    pub fn from_random(ciphersuite: &Ciphersuite) -> Self {
        let mut rng = ciphersuite.rng.lock().unwrap();
        Self {
            value: random_array(&mut *rng),
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct AeadNonce {
    value: [u8; NONCE_BYTES],
}

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct Signature {
    value: TlsByteVecU16,
}

#[cfg(test)]
impl Signature {
    pub(crate) fn modify(&mut self, value: &[u8]) {
        self.value = value.to_vec().into();
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl<T> SignedStruct<T> for Signature {
    fn from_payload(_payload: T, signature: Signature) -> Self {
        signature
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SignaturePrivateKey {
    signature_scheme: SignatureScheme,
    value: Vec<u8>,
}

#[derive(Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePublicKey {
    signature_scheme: SignatureScheme,
    value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignatureKeypair {
    signature_scheme: SignatureScheme,
    private_key: SignaturePrivateKey,
    public_key: SignaturePublicKey,
}

#[derive(Debug)]
pub struct Ciphersuite {
    name: CiphersuiteName,
    signature_scheme: SignatureScheme,
    hpke: Hpke,
    // The rng really must not be accessed concurrently
    rng: Mutex<ChaCha20Rng>,
    hash: HashType,
    aead: AeadType,
}

impl std::fmt::Display for Ciphersuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{}", self.name))
    }
}

// Cloning a ciphersuite sets up a new one to make sure we don't accidentally
// carry over anything we don"t want to.
impl Clone for Ciphersuite {
    fn clone(&self) -> Self {
        Self::new(self.name).unwrap()
    }
}

// Ciphersuites are equal if they have the same name.
impl PartialEq for Ciphersuite {
    fn eq(&self, other: &Ciphersuite) -> bool {
        self.name == other.name
    }
}

#[inline(always)]
fn hash_from_suite(ciphersuite_name: &CiphersuiteName) -> HashType {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => HashType::Sha2_256,
        CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => HashType::Sha2_256,
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            HashType::Sha2_256
        }
        CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 => HashType::Sha2_512,
        CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => HashType::Sha2_512,
        CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => HashType::Sha2_512,
    }
}

#[inline(always)]
fn aead_from_suite(ciphersuite_name: &CiphersuiteName) -> AeadType {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => AeadType::Aes128Gcm,
        CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => AeadType::Aes128Gcm,
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            AeadType::ChaCha20Poly1305
        }
        CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 => AeadType::Aes256Gcm,
        CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => AeadType::Aes256Gcm,
        CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            AeadType::ChaCha20Poly1305
        }
    }
}

impl Ciphersuite {
    /// Create a new ciphersuite from the given `name`.
    pub fn new(name: CiphersuiteName) -> Result<Self, ConfigError> {
        if !Config::supported_ciphersuite_names().contains(&name) {
            return Err(ConfigError::UnsupportedCiphersuite);
        }
        let signature_scheme = SignatureScheme::from(name);
        let hpke_kem = kem_from_suite(&name)?;
        let hpke_kdf = hpke_kdf_from_suite(&name);
        let hpke_aead = hpke_aead_from_suite(&name);
        let rng = rand::init();

        Ok(Ciphersuite {
            name,
            signature_scheme,
            hpke: Hpke::new(Mode::Base, hpke_kem, hpke_kdf, hpke_aead),
            rng: Mutex::new(rng),
            hash: hash_from_suite(&name),
            aead: aead_from_suite(&name),
        })
    }

    /// Get the default ciphersuite.
    pub(crate) fn default() -> &'static Self {
        Config::ciphersuite(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
            .unwrap()
    }

    /// Get the signature scheme of this ciphersuite.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    /// Get the name of this ciphersuite.
    pub fn name(&self) -> CiphersuiteName {
        self.name
    }

    /// Get the AEAD mode
    #[cfg(test)]
    pub(crate) fn aead(&self) -> AeadType {
        self.aead
    }

    /// Hash `payload` and return the digest.
    pub(crate) fn hash(&self, payload: &[u8]) -> Vec<u8> {
        // XXX: remove unwrap
        hash(self.hash, payload).unwrap()
    }

    /// Get the length of the used hash algorithm.
    pub(crate) fn hash_length(&self) -> usize {
        self.hash.size()
    }

    /// Get the length of the AEAD tag.
    pub(crate) fn mac_length(&self) -> usize {
        self.aead.tag_size()
    }

    /// Returns the key size of the used AEAD.
    pub(crate) fn aead_key_length(&self) -> usize {
        self.aead.key_size()
    }

    /// Returns the length of the nonce in the AEAD.
    pub(crate) const fn aead_nonce_length(&self) -> usize {
        NONCE_BYTES
    }

    /// Get random bytes.
    ///
    /// **NOTE: This has to wait until it can acquire the lock to get randomness!**
    /// TODO: This panics if another thread holding the rng panics.
    pub(crate) fn randombytes(&self, n: usize) -> Vec<u8> {
        let mut rng = self.rng.lock().unwrap();
        random_vec(&mut *rng, n)
    }

    /// Reseed the rng.
    /// XXX: This is actually initializing a new rng right now.
    ///
    /// **NOTE: This has to wait until it can acquire the lock to get randomness!**
    /// TODO: This panics if another thread holding the rng panics.
    pub fn reseed(&self) {
        let mut rng = self.rng.lock().unwrap();
        *rng = rand::init();
    }

    /// HPKE single-shot encryption of `ptxt` to `pk_r`, using `info` and `aad`.
    pub(crate) fn hpke_seal(
        &self,
        pk_r: &HpkePublicKey,
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> HpkeCiphertext {
        let (kem_output, ciphertext) = self
            .hpke
            .seal(pk_r, info, aad, ptxt, None, None, None)
            .unwrap();
        HpkeCiphertext {
            kem_output: kem_output.into(),
            ciphertext: ciphertext.into(),
        }
    }

    /// HPKE single-shot encryption specifically to seal a Secret `secret` to
    /// `pk_r`, using `info` and `aad`.
    pub(crate) fn hpke_seal_secret(
        &self,
        pk_r: &HpkePublicKey,
        info: &[u8],
        aad: &[u8],
        secret: &Secret,
    ) -> HpkeCiphertext {
        self.hpke_seal(pk_r, info, aad, &secret.value)
    }

    /// HPKE single-shot decryption of `input` with `sk_r`, using `info` and
    /// `aad`.
    pub(crate) fn hpke_open(
        &self,
        input: &HpkeCiphertext,
        sk_r: &HpkePrivateKey,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.hpke
            .open(
                input.kem_output.as_slice(),
                sk_r,
                info,
                aad,
                input.ciphertext.as_slice(),
                None,
                None,
                None,
            )
            .map_err(|_| CryptoError::HpkeDecryptionError)
    }

    /// Derive a new HPKE keypair from a given Secret.
    pub(crate) fn derive_hpke_keypair(&self, ikm: &Secret) -> HpkeKeyPair {
        self.hpke.derive_key_pair(&ikm.value).unwrap()
    }
}

impl AeadKey {
    /// Create an `AeadKey` from a `Secret`. TODO: This function should
    /// disappear when tackling issue #103.
    pub(crate) fn from_secret(secret: Secret) -> Self {
        log::trace!("AeadKey::from_secret with {}", secret.ciphersuite);
        AeadKey {
            aead_mode: secret.ciphersuite.aead,
            value: secret.value,
            mac_len: secret.ciphersuite.mac_length(),
        }
    }

    #[cfg(test)]
    /// Generate a random AEAD Key
    pub fn random(ciphersuite: &Ciphersuite) -> Self {
        AeadKey {
            aead_mode: ciphersuite.aead(),
            value: aead_key_gen(ciphersuite.aead()),
            mac_len: ciphersuite.mac_length(),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    /// Get a slice to the key value.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }

    /// Encrypt a payload under the AeadKey given a nonce.
    pub(crate) fn aead_seal(
        &self,
        msg: &[u8],
        aad: &[u8],
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, CryptoError> {
        aead_encrypt(
            self.aead_mode,
            self.value.as_slice(),
            msg,
            &nonce.value,
            aad,
        )
    }

    /// AEAD decrypt `ciphertext` with `key`, `aad`, and `nonce`.
    pub(crate) fn aead_open(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, CryptoError> {
        aead_decrypt(
            self.aead_mode,
            self.value.as_slice(),
            ciphertext,
            &nonce.value,
            aad,
        )
    }
}

impl AeadNonce {
    /// Create an `AeadNonce` from a `Secret`. TODO: This function should
    /// disappear when tackling issue #103.
    pub fn from_secret(secret: Secret) -> Self {
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.clone_from_slice(&secret.value);
        AeadNonce { value: nonce }
    }

    /// Generate a new random nonce.
    ///
    /// **NOTE: This has to wait until it can acquire the lock to get randomness!**
    /// TODO: This panics if another thread holding the rng panics.
    #[cfg(test)]
    pub fn random(ciphersuite: &Ciphersuite) -> Self {
        let mut nonce = [0u8; NONCE_BYTES];
        let mut rng = ciphersuite.rng.lock().unwrap();
        nonce.clone_from_slice(random_vec(&mut *rng, NONCE_BYTES).as_slice());
        AeadNonce { value: nonce }
    }

    /// Get a slice to the nonce value.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }

    /// Xor the first bytes of the nonce with the reuse_guard.
    pub(crate) fn xor_with_reuse_guard(&mut self, reuse_guard: &ReuseGuard) {
        log_crypto!(
            trace,
            "  XOR re-use guard {:x?}^{:x?}",
            self.value,
            reuse_guard.value
        );
        for i in 0..REUSE_GUARD_BYTES {
            self.value[i] ^= reuse_guard.value[i]
        }
        log_crypto!(trace, "    = {:x?}", self.value);
    }
}

impl SignatureKeypair {
    /// Sign the `payload` byte slice with this signature key.
    /// Returns a `Result` with a `Signature` or a `CryptoError`.
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, CryptoError> {
        self.private_key.sign(payload)
    }

    /// Verify a `Signature` on the `payload` byte slice with the key pair's
    /// public key.
    pub fn verify(&self, signature: &Signature, payload: &[u8]) -> Result<(), CryptoError> {
        self.public_key.verify(signature, payload)
    }

    /// Get the private and public key objects
    pub fn into_tuple(self) -> (SignaturePrivateKey, SignaturePublicKey) {
        (self.private_key, self.public_key)
    }
}

impl SignatureKeypair {
    pub(crate) fn new(signature_scheme: SignatureScheme) -> Result<SignatureKeypair, CryptoError> {
        let (sk, pk) = signature_key_gen(signature_scheme)?;

        Ok(SignatureKeypair {
            signature_scheme,
            private_key: SignaturePrivateKey {
                value: sk.to_vec(),
                signature_scheme,
            },
            public_key: SignaturePublicKey {
                value: pk.to_vec(),
                signature_scheme,
            },
        })
    }
}

impl SignaturePublicKey {
    /// Create a new signature public key from raw key bytes.
    pub fn new(bytes: Vec<u8>, signature_scheme: SignatureScheme) -> Result<Self, CryptoError> {
        support(signature_scheme)?;
        Ok(Self {
            value: bytes,
            signature_scheme,
        })
    }
    /// Verify a `Signature` on the `payload` byte slice with the key pair's
    /// public key.
    pub fn verify(&self, signature: &Signature, payload: &[u8]) -> Result<(), CryptoError> {
        support(self.signature_scheme)?;
        verify_signature(
            self.signature_scheme,
            payload,
            &self.value,
            signature.value.as_slice(),
        )
    }
}

impl SignaturePrivateKey {
    /// Sign the `payload` byte slice with this signature key.
    /// Returns a `Result` with a `Signature` or a `SignatureError`.
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, CryptoError> {
        match sign(self.signature_scheme, payload, &self.value) {
            Ok(s) => Ok(Signature { value: s.into() }),
            Err(e) => Err(e),
        }
    }
}

/// Make sure that xoring works by xoring a nonce with a reuse guard, testing if
/// it has changed, xoring it again and testing that it's back in its original
/// state.
#[test]
fn test_xor() {
    let ciphersuite = Ciphersuite::default();
    let reuse_guard: ReuseGuard = ReuseGuard::from_random(Ciphersuite::default());
    let original_nonce = AeadNonce::random(ciphersuite);
    let mut nonce = original_nonce.clone();
    nonce.xor_with_reuse_guard(&reuse_guard);
    assert_ne!(
        original_nonce, nonce,
        "xoring with reuse_guard did not change the nonce"
    );
    nonce.xor_with_reuse_guard(&reuse_guard);
    assert_eq!(
        original_nonce, nonce,
        "xoring twice changed the original value"
    );
}
