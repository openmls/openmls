//! # Message framing
//!
//! This module implements framing for MLS messages.
//!
//! See [`MlsPlaintext`] and [`MlsCiphertext`] for details.

use crate::ciphersuite::*;
use crate::credentials::*;
use crate::group::*;
use crate::messages::{proposals::*, *};
use crate::schedule::*;
pub(crate) use serde::{Deserialize, Serialize};
use tls_codec::*;

pub(crate) mod ciphertext;
pub(crate) mod codec;
pub(crate) mod errors;
pub(crate) mod message;
pub(crate) mod plaintext;
pub(crate) mod sender;
pub(crate) mod validation;
pub(crate) use ciphertext::*;
pub(crate) use plaintext::*;

// Crate
pub(crate) use errors::*;
pub(crate) use sender::*;

// Public
pub use message::*;
pub use validation::*;

// Tests
#[cfg(test)]
mod test_framing;

/// Wire format of MLS messages.
#[derive(
    PartialEq, Clone, Copy, Debug, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
#[repr(u8)]
pub enum WireFormat {
    /// Plaintext message
    MlsPlaintext = 1,
    /// Encrypted message
    MlsCiphertext = 2,
}

/// This struct is used to group common framing parameters
/// in order to reduce the number of arguments in function calls.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) struct FramingParameters<'a> {
    aad: &'a [u8],
    wire_format: WireFormat,
}

impl<'a> FramingParameters<'a> {
    pub(crate) fn new(aad: &'a [u8], wire_format: impl Into<WireFormat>) -> Self {
        Self {
            aad,
            wire_format: wire_format.into(),
        }
    }
    pub(crate) fn aad(&self) -> &'a [u8] {
        self.aad
    }
    pub(crate) fn wire_format(&self) -> WireFormat {
        self.wire_format
    }
}
