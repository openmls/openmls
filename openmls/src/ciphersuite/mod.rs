//! Ciphersuites for MLS
//!
//! This file contains the API to interact with ciphersuites.
//! See `codec.rs` and `ciphersuites.rs` for internals.

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
    let mut diff = 0u8;
    for (l, r) in a.iter().zip(b.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}
