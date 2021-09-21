//! Ciphersuites for MLS
//!
//! This file contains the API to interact with ciphersuites.
//! See `codec.rs` and `ciphersuites.rs` for internals.

use byteorder::{ReadBytesExt, WriteBytesExt};
use log::error;

use ::tls_codec::{Size, TlsDeserialize, TlsSerialize, TlsSize};
use evercrypt::prelude::{
    aead_decrypt, aead_encrypt, aead_key_size, aead_tag_size, digest_size, hash, hkdf_expand,
    hkdf_extract, p256_ecdsa_random_nonce, random_array, random_vec, sign, signature_key_gen,
    verify, AeadError, AeadMode, DigestMode, HmacMode, SignatureMode,
};
use hpke::prelude::*;
pub(crate) use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};
use std::{
    hash::Hash,
    io::{Read, Write},
};
use tls_codec::{Serialize as TlsSerializeTrait, TlsByteVecU16, TlsByteVecU32, TlsByteVecU8};

// re-export for other parts of the library when we can use it
pub(crate) use hpke::{HpkeKeyPair, HpkePrivateKey, HpkePublicKey};

mod ciphersuites;
mod codec;
mod errors;
pub mod signable;

mod ser;

use crate::config::{Config, ConfigError, ProtocolVersion};

use ciphersuites::*;
pub(crate) use errors::*;

use self::signable::SignedStruct;

#[cfg(test)]
use evercrypt::prelude::aead_key_gen;

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

// TODO #13: This should be independent from EverCrypt
impl TryFrom<SignatureScheme> for SignatureMode {
    type Error = &'static str;
    fn try_from(signature_scheme: SignatureScheme) -> Result<Self, Self::Error> {
        match signature_scheme {
            SignatureScheme::ED25519 => Ok(SignatureMode::Ed25519),
            SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(SignatureMode::P256),
            SignatureScheme::ED448 => Err("SignatureScheme ed448 is not supported."),
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                Err("SignatureScheme ecdsa_secp521r1 is not supported.")
            }
        }
    }
}

// TODO #13: This should be independent from EverCrypt
impl TryFrom<SignatureScheme> for DigestMode {
    type Error = &'static str;
    fn try_from(signature_scheme: SignatureScheme) -> Result<Self, Self::Error> {
        match signature_scheme {
            // The digest mode for ed25519 is not really used
            SignatureScheme::ED25519 => Ok(DigestMode::Sha256),
            SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(DigestMode::Sha256),
            SignatureScheme::ED448 => Err("SignatureScheme ed448 is not supported."),
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                Err("SignatureScheme ecdsa_secp521r1 is not supported.")
            }
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
        Secret {
            value: random_vec(ciphersuite.hash_length()),
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
                self.ciphersuite.hmac,
                self.value.as_slice(),
                ikm.value.as_slice(),
            ),
            mls_version: self.mls_version,
            ciphersuite: self.ciphersuite,
        }
    }

    /// HKDF expand where `self` is `prk`.
    pub(crate) fn hkdf_expand(&self, info: &[u8], okm_len: usize) -> Result<Self, HkdfError> {
        let key = hkdf_expand(self.ciphersuite.hmac, &self.value, info, okm_len);
        if key.is_empty() {
            return Err(HkdfError::InvalidLength);
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
        self.hkdf_expand(&info, length).map_err(|e| e.into())
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
    aead_mode: AeadMode,
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
    pub fn from_random() -> Self {
        Self {
            value: random_array(),
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

// The length of the individual scalars. Since we only support ECDSA with P256,
// this is 32. It would be great if evercrypt were able to return the scalar
// size of a given curve.
const P256_SCALAR_LENGTH: usize = 32;

// DER encoding INTEGER tag.
const INTEGER_TAG: u8 = 0x02;

// DER encoding SEQUENCE tag.
const SEQUENCE_TAG: u8 = 0x30;

impl Signature {
    /// This function takes a DER encoded ECDSA signature and decodes it to the
    /// bytes representing the concatenated scalars. If the decoding fails, it
    /// will throw a `SignatureError`.
    pub(crate) fn der_decode(&self) -> Result<Vec<u8>, SignatureError> {
        // A small function to DER decode a single scalar.
        fn decode_scalar<R: Read>(mut buffer: R) -> Result<Vec<u8>, SignatureError> {
            // Check header bytes of encoded scalar.

            // 1 byte INTEGER tag should be 0x02
            let integer_tag = buffer
                .read_u8()
                .map_err(|_| SignatureError::DecodingError)?;
            if integer_tag != INTEGER_TAG {
                return Err(SignatureError::DecodingError);
            };

            // 1 byte length tag should be at most 0x21, i.e. 32 plus at most 1
            // byte indicating that the integer is unsigned.
            let mut scalar_length = buffer
                .read_u8()
                .map_err(|_| SignatureError::DecodingError)?
                as usize;
            if scalar_length > P256_SCALAR_LENGTH + 1 {
                return Err(SignatureError::DecodingError);
            };

            // If the scalar is 0x21 long, the first byte has to be 0x00,
            // indicating that the following integer is unsigned. We can discard
            // this byte safely. If it's not 0x00, the scalar is too large not
            // thus not a valid point on the curve.
            if scalar_length == P256_SCALAR_LENGTH + 1 {
                if buffer
                    .read_u8()
                    .map_err(|_| SignatureError::DecodingError)?
                    != 0x00
                {
                    return Err(SignatureError::DecodingError);
                };
                // Since we just read that byte, we decrease the length by 1.
                scalar_length -= 1;
            };

            let mut scalar = vec![0; scalar_length];
            buffer
                .read_exact(&mut scalar)
                .map_err(|_| SignatureError::DecodingError)?;

            // The verification algorithm expects the scalars to be 32 bytes
            // long, buffered with zeroes.
            let mut padded_scalar = vec![0u8; P256_SCALAR_LENGTH - scalar_length];
            padded_scalar.append(&mut scalar);

            Ok(padded_scalar)
        }

        let mut signature_bytes = self.value.as_slice();

        // Check header bytes:
        // 1 byte SEQUENCE tag should be 0x30
        let sequence_tag = signature_bytes
            .read_u8()
            .map_err(|_| SignatureError::DecodingError)?;
        if sequence_tag != SEQUENCE_TAG {
            return Err(SignatureError::DecodingError);
        };

        // At most 1 byte encoding the length of the scalars (short form DER
        // length encoding). Length has to be encoded in the short form, as we
        // expect the length not to exceed the maximum length of 70: Two times
        // at most 32 (scalar value) + 1 byte integer tag + 1 byte length tag +
        // at most 1 byte to indicating that the integer is unsigned.
        let length = signature_bytes
            .read_u8()
            .map_err(|_| SignatureError::DecodingError)? as usize;
        if length > 2 * (P256_SCALAR_LENGTH + 3) {
            return Err(SignatureError::DecodingError);
        }

        // The remaining bytes should be equal to the encoded length.
        if signature_bytes.len() != length {
            return Err(SignatureError::DecodingError);
        }

        let mut r = decode_scalar(&mut signature_bytes)?;
        let mut s = decode_scalar(&mut signature_bytes)?;

        // After reading the whole signature, nothing should be left.
        if !signature_bytes.is_empty() {
            return Err(SignatureError::DecodingError);
        }

        let mut out = Vec::with_capacity(2 * P256_SCALAR_LENGTH);
        out.append(&mut r);
        out.append(&mut s);
        Ok(out)
    }

    /// This function DER encodes a given ECDSA signature consisting of bytes
    /// representing the concatenated scalars. If the encoding fails, it will
    /// throw a `SignatureError`.
    pub(crate) fn der_encode(raw_signature: &[u8]) -> Result<Self, SignatureError> {
        // A small function to DER encode single scalar.
        fn encode_scalar<W: Write>(mut scalar: &[u8], mut buffer: W) -> Result<(), SignatureError> {
            // Check that the given scalar has the right length.
            if scalar.len() != P256_SCALAR_LENGTH {
                return Err(SignatureError::EncodingError);
            }

            // The encoded scalar needs to start with integer tag.
            buffer
                .write_u8(INTEGER_TAG)
                .map_err(|_| SignatureError::EncodingError)?;

            // Remove prepending zeros of the given, unencoded scalar.
            let mut msb = scalar
                .read_u8()
                .map_err(|_| SignatureError::EncodingError)?;
            while msb == 0x00 {
                msb = scalar
                    .read_u8()
                    .map_err(|_| SignatureError::EncodingError)?;
            }

            // The length of the scalar is what's left after removing the
            // prepending zeroes, plus 1 for the msb which we've already read.
            let mut scalar_length = scalar.len() + 1;

            // If the most significant bit is 1, we have to prepend 0x00 to indicate
            // that the integer is unsigned.
            let prepend_zero = msb > 0x7F;

            if prepend_zero {
                // This increases the scalar length by 1.
                scalar_length += 1;
            };

            buffer
                // It is safe to convert to u8, because we know that the length
                // of the scalar is at most 33.
                .write_u8(scalar_length as u8)
                .map_err(|_| SignatureError::EncodingError)?;

            if prepend_zero {
                // Now that we've written the length, we can actually prepend
                // the zero.
                buffer
                    .write_u8(0x00)
                    .map_err(|_| SignatureError::EncodingError)?;
            };

            // Write the msb to the encoded scalar.
            buffer
                .write_u8(msb)
                .map_err(|_| SignatureError::EncodingError)?;

            // Write the rest of the scalar.
            buffer
                .write_all(scalar)
                .map_err(|_| SignatureError::EncodingError)?;

            Ok(())
        }

        // Check overall length
        if raw_signature.len() != 2 * P256_SCALAR_LENGTH {
            return Err(SignatureError::EncodingError);
        }

        // We DER encode the ECDSA signature as per spec, assuming that
        // `sign` returns two concatenated values (r||s).
        let r = raw_signature
            .get(..P256_SCALAR_LENGTH)
            .ok_or(SignatureError::EncodingError)?;
        let s = raw_signature
            .get(P256_SCALAR_LENGTH..2 * P256_SCALAR_LENGTH)
            .ok_or(SignatureError::EncodingError)?;

        let mut encoded_signature: Vec<u8> = Vec::with_capacity(2 + 2 * (P256_SCALAR_LENGTH + 3));

        // Write the DER Sequence tag
        encoded_signature
            .write_u8(SEQUENCE_TAG)
            .map_err(|_| SignatureError::EncodingError)?;

        // Write a placeholder byte for length. This will be overwritten once we
        // have encoded the scalars and know the final length.
        encoded_signature
            .write_u8(0x00)
            .map_err(|_| SignatureError::EncodingError)?;

        encode_scalar(&r, &mut encoded_signature)?;
        encode_scalar(&s, &mut encoded_signature)?;

        // Now we can determine the length of the scalars by taking the overall
        // length and removing 1 for the Sequence tag and 1 for the length
        // field. The conversion to u8 is safe, because we know that each of the
        // scalars is at most 33 bytes long.
        *encoded_signature
            .get_mut(1)
            .ok_or(SignatureError::EncodingError)? = (encoded_signature.len() - 2) as u8;

        Ok(Signature {
            value: encoded_signature.into(),
        })
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
    aead: AeadMode,
    hash: DigestMode,
    hmac: HmacMode,
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

        Ok(Ciphersuite {
            name,
            signature_scheme,
            hpke: Hpke::new(Mode::Base, hpke_kem, hpke_kdf, hpke_aead),
            aead: aead_from_suite(&name),
            hash: hash_from_suite(&name),
            hmac: kdf_from_suite(&name),
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
    pub(crate) fn aead(&self) -> AeadMode {
        self.aead
    }

    /// Hash `payload` and return the digest.
    pub(crate) fn hash(&self, payload: &[u8]) -> Vec<u8> {
        hash(self.hash, payload)
    }

    /// Get the length of the used hash algorithm.
    pub(crate) fn hash_length(&self) -> usize {
        digest_size(self.hash)
    }

    /// Get the length of the AEAD tag.
    pub(crate) fn mac_length(&self) -> usize {
        aead_tag_size(self.aead)
    }

    /// Returns the key size of the used AEAD.
    pub(crate) fn aead_key_length(&self) -> usize {
        aead_key_size(self.aead)
    }

    /// Returns the length of the nonce in the AEAD.
    pub(crate) const fn aead_nonce_length(&self) -> usize {
        NONCE_BYTES
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
    ) -> Result<Vec<u8>, AeadError> {
        let (ct, tag) = aead_encrypt(
            self.aead_mode,
            self.value.as_slice(),
            msg,
            &nonce.value,
            aad,
        )?;
        let mut ciphertext = ct;
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    /// AEAD decrypt `ciphertext` with `key`, `aad`, and `nonce`.
    pub(crate) fn aead_open(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, AeadError> {
        if ciphertext.len() < self.mac_len {
            error!(
                "Ciphertext is too short (less than {:?} bytes)",
                self.mac_len
            );
            return Err(AeadError::Decrypting);
        }
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - self.mac_len);
        aead_decrypt(
            self.aead_mode,
            self.value.as_slice(),
            ct,
            tag,
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
    #[cfg(test)]
    pub fn random() -> Self {
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.clone_from_slice(random_vec(NONCE_BYTES).as_slice());
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
    /// Returns a `Result` with a `Signature` or a `SignatureError`.
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, SignatureError> {
        self.private_key.sign(payload)
    }

    /// Verify a `Signature` on the `payload` byte slice with the key pair's
    /// public key.
    pub fn verify(&self, signature: &Signature, payload: &[u8]) -> Result<(), SignatureError> {
        self.public_key.verify(signature, payload)
    }

    /// Get the private and public key objects
    pub fn into_tuple(self) -> (SignaturePrivateKey, SignaturePublicKey) {
        (self.private_key, self.public_key)
    }
}

impl SignatureKeypair {
    pub(crate) fn new(signature_scheme: SignatureScheme) -> Result<SignatureKeypair, CryptoError> {
        let signature_mode = match SignatureMode::try_from(signature_scheme) {
            Ok(signature_mode) => signature_mode,
            Err(_) => return Err(CryptoError::UnsupportedSignatureScheme),
        };
        let (sk, pk) = match signature_key_gen(signature_mode) {
            Ok((sk, pk)) => (sk, pk),
            Err(e) => {
                error!("Key generation really shouldn't fail. {:?}", e);
                return Err(CryptoError::CryptoLibraryError);
            }
        };
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
    pub fn new(bytes: Vec<u8>, signature_scheme: SignatureScheme) -> Result<Self, SignatureError> {
        // TODO #13: This should be independent from EverCrypt
        if SignatureMode::try_from(signature_scheme).is_err() {
            return Err(SignatureError::UnknownAlgorithm);
        }
        if DigestMode::try_from(signature_scheme).is_err() {
            return Err(SignatureError::UnknownAlgorithm);
        }
        Ok(Self {
            value: bytes,
            signature_scheme,
        })
    }
    /// Verify a `Signature` on the `payload` byte slice with the key pair's
    /// public key.
    pub fn verify(&self, signature: &Signature, payload: &[u8]) -> Result<(), SignatureError> {
        let signature_mode = SignatureMode::try_from(self.signature_scheme)
            .map_err(|_| SignatureError::UnknownAlgorithm)?;
        let signature_bytes = match signature_mode {
            SignatureMode::Ed25519 => signature.value.as_slice().to_vec(),
            // As per spec, we expect the signature to be DER encoded.
            SignatureMode::P256 => signature.der_decode()?,
        };
        if verify(
            signature_mode,
            Some(
                DigestMode::try_from(self.signature_scheme)
                    .map_err(|_| SignatureError::UnknownAlgorithm)?,
            ),
            &self.value,
            &signature_bytes,
            payload,
        )? {
            Ok(())
        } else {
            Err(SignatureError::InvalidSignature)
        }
    }
}

impl SignaturePrivateKey {
    /// Sign the `payload` byte slice with this signature key.
    /// Returns a `Result` with a `Signature` or a `SignatureError`.
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, SignatureError> {
        let signature_mode = SignatureMode::try_from(self.signature_scheme)
            .map_err(|_| SignatureError::UnknownAlgorithm)?;
        let (hash, nonce) = match signature_mode {
            SignatureMode::Ed25519 => (None, None),
            SignatureMode::P256 => (
                Some(DigestMode::try_from(self.signature_scheme).unwrap()),
                Some(p256_ecdsa_random_nonce().unwrap()),
            ),
        };
        match (
            sign(signature_mode, hash, &self.value, payload, nonce.as_ref()),
            signature_mode,
        ) {
            (Ok(s), SignatureMode::Ed25519) => Ok(Signature { value: s.into() }),
            (Ok(s), SignatureMode::P256) => Ok(Signature::der_encode(&s)?),
            (Err(e), _) => Err(e)?,
        }
    }
}

/// Make sure that xoring works by xoring a nonce with a reuse guard, testing if
/// it has changed, xoring it again and testing that it's back in its original
/// state.
#[test]
fn test_xor() {
    let reuse_guard: ReuseGuard = ReuseGuard::from_random();
    let original_nonce = AeadNonce::random();
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
