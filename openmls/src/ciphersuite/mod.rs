//! # The MLS Ciphersuites
//!
//! The MLS ciphersuites and hash references.

use crate::versions::ProtocolVersion;
use ::tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{AeadType, Ciphersuite, CryptoError, SignatureScheme},
    OpenMlsCryptoProvider,
};
use signable::SignedStruct;

use std::hash::Hash;
use tls_codec::{Serialize as TlsSerializeTrait, TlsByteVecU16, TlsByteVecU32, TlsByteVecU8};

mod aead;
mod codec;
mod hpke;
mod kdf_label;
mod mac;
mod reuse_guard;
mod secret;
mod signature;

// Public re-export
pub use hash_ref::*;

// Crate
pub(crate) use aead::*;
pub(crate) use hpke::*;
pub(crate) use mac::*;
pub(crate) use reuse_guard::*;
pub(crate) use secret::*;
pub(crate) use signature::*;
pub(crate) mod hash_ref;
pub(crate) mod signable;

pub(crate) use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

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
