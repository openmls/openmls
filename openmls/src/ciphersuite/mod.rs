//! Ciphersuites for MLS
//!
//! This file contains the API to interact with ciphersuites.
//! See `codec.rs` and `ciphersuites.rs` for internals.

use crate::versions::ProtocolVersion;
use ::tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{AeadType, Ciphersuite, CryptoError, SignatureScheme},
    OpenMlsCryptoProvider,
};
use signable::SignedStruct;

use std::hash::Hash;

mod aead;
mod codec;
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
mod tests;

/// A simple type for HPKE public keys using [`VLBytes`] for (de)serializing.
pub type HpkePublicKey = VLBytes;

/// A simple type for HPKE private keys using [`VLBytes`] for (de)serializing.
pub type HpkePrivateKey = VLBytes;

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
