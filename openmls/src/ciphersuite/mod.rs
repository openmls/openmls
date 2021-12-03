//! Ciphersuites for MLS
//!
//! This file contains the API to interact with ciphersuites.
//! See `codec.rs` and `ciphersuites.rs` for internals.

use crate::config::{Config, ConfigError, ProtocolVersion};
use ::tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};
use openmls_traits::types::{CryptoError, HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType};
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
mod ciphersuites;
mod codec;
mod hash_ref;
mod hpke;
mod kdf_label;
mod mac;
mod reuse_guard;
mod secret;
mod ser;
pub mod signable;
mod signature;

pub(crate) use aead::*;
pub use ciphersuites::*;
pub use hash_ref::*;
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

#[derive(Debug)]
pub struct Ciphersuite {
    name: CiphersuiteName,
    signature_scheme: SignatureScheme,
    hash: HashType,
    aead: AeadType,
    hpke_kem: HpkeKemType,
    hpke_kdf: HpkeKdfType,
    hpke_aead: HpkeAeadType,
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
            signature_scheme: SignatureScheme::from(name),
            hash: hash_from_suite(&name),
            aead: aead_from_suite(&name),
            hpke_kem: self.hpke_kem,
            hpke_kdf: hpke_kdf_from_suite(&name),
            hpke_aead: hpke_aead_from_suite(&name),
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

        Ok(Ciphersuite {
            name,
            signature_scheme: SignatureScheme::from(name),
            hash: hash_from_suite(&name),
            aead: aead_from_suite(&name),
            hpke_kem: kem_from_suite(&name)?,
            hpke_kdf: hpke_kdf_from_suite(&name),
            hpke_aead: hpke_aead_from_suite(&name),
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
    #[cfg(any(test, feature = "test-utils"))]
    pub fn aead(&self) -> AeadType {
        self.aead
    }

    /// Hash `payload` and return the digest.
    pub(crate) fn hash(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        backend.crypto().hash(self.hash, payload)
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
        self.aead.nonce_size()
    }

    /// Build an [`HpkeConfi`] for this cipher suite.
    pub(crate) fn hpke_config(&self) -> HpkeConfig {
        HpkeConfig(self.hpke_kem, self.hpke_kdf, self.hpke_aead)
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
