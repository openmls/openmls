//! # Ciphersuites for MLS
//!
//! This module defines the API for interacting with MLS ciphersuites. For
//! implementation details, refer to `codec.rs` and `ciphersuites.rs`.

use ::tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{AeadType, Ciphersuite, CryptoError, SignatureScheme},
};
use signable::SignedStruct;

use std::hash::Hash;

mod aead;
mod codec;
pub(crate) mod hpke;
mod kdf_label;
mod mac;
mod reuse_guard;
mod secret;

// Public
pub mod hash_ref;
pub mod signable;
pub mod signature;
#[cfg(feature = "extensions-draft-08")]
pub use hpke::{
    safe_decrypt_with_label, safe_encrypt_with_label, Error as HpkeError, SafeEncryptionContext,
};

// Crate
pub(crate) use aead::*;
pub(crate) use mac::*;
pub(crate) use reuse_guard::*;
pub(crate) use secret::*;
pub(crate) use signature::*;

pub(crate) use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests_and_kats;

const LABEL_PREFIX: &str = "MLS 1.0 ";

/// A simple type for HPKE public keys using [`VLBytes`] for (de)serializing.
pub type HpkePublicKey = VLBytes;
pub use openmls_traits::types::HpkePrivateKey;

/// Compare two byte slices in a way that's hopefully not optimised out by the
/// compiler.
#[inline(never)]
fn equal_ct(a: &[u8], b: &[u8]) -> bool {
    // The length values can be considered public and checked before the actual
    // comparison.
    if a.len() != b.len() {
        log::error!("Incompatible values");
        log::trace!("  {} != {}", a.len(), b.len());
        return false;
    }

    let mut diff = 0u8;
    for (l, r) in a.iter().zip(b.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}
