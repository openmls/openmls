//! # Entropy Pool
//!
//! This crate provides the `EntropyPool` struct, which stores entropy as a byte
//! vector.
//!
//! This is an implementation of the entropy pool described in
//! https://github.com/mlswg/mls-protocol/pull/467. The main struct
//! `EntropyPool` allows the injection and extraction of entropy.
//!
//! The design is based on the same extract-expand construction used in the key
//! schedule of TLS 1.3 and MLS 1.0. Whenever entropy is injected into the pool,
//! it is "mixed" with the existing pool using an HKDF.Extract operation.
//! Extraction of entropy from the pool happens in three steps.
//!
//! 1. Entropy from the OS RNG is injected into the pool.
//! 2. Entropy is extracted from the pool using an HKDF.Expand operation.
//! 3. Another HKDF.Expand operation is performed to obtain the new pool value.
//!
//! The first step is necessary to provide at least as much entropy as the OS
//! RNG would. The second and third step are necessary to properly separate the
//! resulting randomness from the remaining pool value.
//!
//! # Injection of External Randomness
//!
//! The ability to inject randomness is provided such that users of the pool can
//! improve entropy by injecting values that contain entropy from other sources
//! than the OS's RNG without compromising the security of the pool. For
//! example, a TLS session could export a secret, to which the partner of the
//! session has contributed entropy, thus improving the quality of the pool.
//! This injection of "external" randomness can improve the quality of the pool
//! in cases where the OS's RNG has no good sources of randomness of its own. Of
//! course, if the OS's RNG is compromised, as well as the partner of the TLS
//! session, this is of no help. Consequently, it is useful to inject entropy
//! from as many external sources as possible.
//!
//! # Security Guarantees
//!
//! The security guarantees provided by the entropy pool is similar to those
//! provided by the TLS 1.3 and MLS 1.0 key schedules. Concretely, this means
//! that arbitrary randomness can be injected into the pool without the pool
//! losing entropy. Additionally, when extracting randomness from the pool, the
//! pool first injects randomness from the OS's RNG, thus ensuring that the
//! extracted randomness contains at least as much entropy as if sampling from
//! the OS's RNG directly.
//!
//! Finally, after extracting randomness from the pool, the pool is "ratcheted
//! forward", ensuring that values extracted in the past cannot be derived from
//! the current pool value.
//!
//! To summarize, the pool provides at least as much entropy as if sampling from
//! the OS's RNG directly and additionally allows the injection of randomness
//! from other sources, such as exporters from TLS, MLS or other network
//! protocols, strictly improving the amount of entropy in the pool.

use ::tls_codec::{Size, TlsSerialize, TlsSize};
use evercrypt::{
    hkdf::{expand, extract},
    prelude::{tag_size, HmacMode},
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tls_codec::{Serialize as TlsSerializeTrait, TlsByteVecU8};

#[cfg(test)]
mod tests;

#[derive(Serialize, Deserialize, Copy, Clone)]
/// The possible `HMAC` modes of the HKDF used by the pool. The mode determines
/// the size of the pool value.
pub enum HkdfMode {
    Sha256,
    Sha384,
    Sha512,
}

impl From<HkdfMode> for HmacMode {
    fn from(hkdf_mode: HkdfMode) -> Self {
        match hkdf_mode {
            HkdfMode::Sha256 => HmacMode::Sha256,
            HkdfMode::Sha384 => HmacMode::Sha384,
            HkdfMode::Sha512 => HmacMode::Sha512,
        }
    }
}

/// An array that contains all possible HKDF modes usable by a pool.
pub const SUPPORTED_HKDF_MODES: [HkdfMode; 3] =
    [HkdfMode::Sha256, HkdfMode::Sha384, HkdfMode::Sha512];

/// This struct contains the current entropy pool value, as well as an
/// `HkdfMode`. The `HkdfMode` determines what mode is used by the HMAC used to
/// construct the HKDF that is used in the inject and extract operations.
///
/// `EntropyPool` supports serialization and deserialization such that a pool
/// can be serialized and persisted to disk for later use.
#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(Clone))]
pub struct EntropyPool {
    hkdf_mode: HkdfMode,
    value: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum EntropyPoolError {
    LengthError,
    SerializationError,
}

#[derive(TlsSerialize, TlsSize)]
struct KdfLabel {
    length: u16,
    label: TlsByteVecU8,
}

impl EntropyPool {
    /// Create a new `EntropyPool`. This should only be done if no other
    /// `EntropyPool` instance exists already. For example, it would be
    /// preferrable to load a previously saved pool from disk.
    pub fn new(hkdf_mode: HkdfMode) -> Self {
        // We initialize the pool with fresh os randomness. This is technically
        // not necessary, as os entropy will be injected upon the first
        // "extract" query.
        let mut initial_entropy_buffer = vec![0u8; tag_size(hkdf_mode.into())];
        OsRng.fill_bytes(&mut initial_entropy_buffer);

        EntropyPool {
            hkdf_mode,
            value: initial_entropy_buffer,
        }
    }

    /// Inject arbitrary randomness into the pool. This improves the quality of
    /// the pool if the source of entropy in the added bytes is external to the
    /// OS's RNG.
    pub fn inject(&mut self, additional_entropy: &[u8]) {
        self.value = extract(self.hkdf_mode.into(), &self.value, additional_entropy);
    }

    /// Extract randomness from the pool after first injecting fresh randomness
    /// from the OS's RNG. Returns an error if the serialization of the label
    /// fails or if the given length exceeds the max length of 255 times the
    /// length of the hash function used by the HKDF.
    pub fn extract(&mut self, length: u16) -> Result<Vec<u8>, EntropyPoolError> {
        let hash_length = tag_size(self.hkdf_mode.into());

        // Check if the requested length is too big for the HKDF as specified by
        // RFC 5869. We can multiply safely here, as the max hash length is 64.
        if length > 255 * hash_length as u16 {
            return Err(EntropyPoolError::LengthError);
        }

        // Before we allow entropy to be extracted from the pool, we first
        // inject some fresh entropy from the OS's RNG.
        let mut os_randomness_buffer = vec![0u8; hash_length];
        OsRng.fill_bytes(&mut os_randomness_buffer);
        self.inject(&os_randomness_buffer);

        // We now derive the random bytes which we will eventually return.
        let kdf_label = KdfLabel {
            length,
            label: "fresh_randomness".as_bytes().into(),
        }
        .tls_serialize_detached()
        .map_err(|_| EntropyPoolError::SerializationError)?;
        let fresh_randomness = expand(
            self.hkdf_mode.into(),
            &self.value,
            &kdf_label,
            length as usize,
        );

        // Before we return the `fresh_randomness`, we first "ratchet the pool
        // forwards" by performing an additional expand operation.
        let kdf_label = KdfLabel {
            length,
            label: "entropy_pool".as_bytes().into(),
        }
        .tls_serialize_detached()
        .map_err(|_| EntropyPoolError::SerializationError)?;
        self.value = expand(self.hkdf_mode.into(), &self.value, &kdf_label, hash_length);

        Ok(fresh_randomness)
    }

    pub fn hkdf_mode(&self) -> HkdfMode {
        self.hkdf_mode
    }
}
