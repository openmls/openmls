//! Ciphersuites for MLS
//!
//! This file contains the API to interact with ciphersuites.
//! See `codec.rs` and `ciphersuites.rs` for internals.

use crate::config::{Config, ConfigError, ProtocolVersion};
use ::tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};
pub use openmls_traits::types::CiphersuiteName;
use openmls_traits::types::{CryptoError, HpkeConfig};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{AeadType, HashType, SignatureScheme},
    OpenMlsCryptoProvider,
};
pub(crate) use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};
use std::hash::Hash;
use tls_codec::{Serialize as TlsSerializeTrait, TlsByteVecU16, TlsByteVecU32, TlsByteVecU8};

mod aead;
mod codec;
mod hpke;
mod kdf_label;
mod mac;
mod reuse_guard;
mod secret;
mod ser;
mod signature;

// Public
pub mod hash_ref;
pub mod signable;

// Crate
pub(crate) use aead::*;
pub(crate) use hpke::*;
pub(crate) use mac::*;
pub(crate) use reuse_guard::*;
pub(crate) use secret::*;
pub(crate) use signature::*;

use self::signable::SignedStruct;

#[cfg(test)]
mod tests;

/// The default NONCE size in bytes.
pub(crate) const NONCE_BYTES: usize = 12;

/// Re-use guard size.
pub(crate) const REUSE_GUARD_BYTES: usize = 4;

/// The `Ciphersuite` object encapsulates all the necessary crypto primitives for
/// a given [`CiphersuiteName`].
#[derive(Debug)]
pub struct Ciphersuite {
    name: CiphersuiteName,
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
        let name = self.name;
        Ciphersuite {
            name,
        }
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

        Ok(Self::new_from_supported(name))
    }

    /// This creates a Ciphersuite from one of the supported ciphersuite names.
    /// This should only be used if it is clear the ciphersuite is supported.
    /// If the ciphersuite is not supported, might lead to inconsistencies.
    /// TODO #701: This should go away.
    pub(crate) fn new_from_supported(name: CiphersuiteName) -> Self {
        Ciphersuite {
            name,
        }
    }

    /// Get the default ciphersuite.
    pub(crate) fn default() -> &'static Self {
        &Config::supported_ciphersuites()[0]
    }

    /// Get the signature scheme of this ciphersuite.
    #[inline]
    pub fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::from(self.name)
    }

    /// Get the name of this ciphersuite.
    #[inline]
    pub fn name(&self) -> CiphersuiteName {
        self.name
    }

    /// Get the AEAD algorithm of the cipher suite
    #[inline]
    pub fn aead(&self) -> AeadType {
        AeadType::from(self.name)
    }

    /// Get the AEAD algorithm of the cipher suite
    #[inline]
    pub fn hash_algorithm(&self) -> HashType {
        HashType::from(self.name)
    }

    /// Hash `payload` and return the digest.
    pub(crate) fn hash(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        backend.crypto().hash(self.hash_algorithm(), payload)
    }

    /// Get the length of the used hash algorithm.
    pub(crate) fn hash_length(&self) -> usize {
        self.hash_algorithm().size()
    }

    /// Get the length of the AEAD tag.
    pub(crate) fn mac_length(&self) -> usize {
        self.aead().tag_size()
    }

    /// Returns the key size of the used AEAD.
    pub(crate) fn aead_key_length(&self) -> usize {
        self.aead().key_size()
    }

    /// Returns the length of the nonce in the AEAD.
    pub(crate) const fn aead_nonce_length(&self) -> usize {
        self.name.aead_algorithm().nonce_size()
    }

    /// Build an [`HpkeConfi`] for this cipher suite.
    pub(crate) fn hpke_config(&self) -> HpkeConfig {
        HpkeConfig(self.name.into(), self.name.into(), self.name.into())
    }
}

/// Compare two byte slices in a way that's hopefully not optimised out by the
/// compiler.
#[inline(never)]
fn equal_ct(a: &[u8], b: &[u8]) -> bool {
    let mut diff = 0u8;
    for (l, r) in a.iter().zip(b.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}
