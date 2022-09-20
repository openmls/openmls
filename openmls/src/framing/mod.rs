//! # Message framing
//!
//! This module contains framing-related operations for MLS messages, including validation operations.
//!
//!  - [`MlsMessageIn`]/[`MlsMessageOut`]: Unified message type for incoming & outgoing MLS messages
//!  - [`ApplicationMessage`]: Application message received through a [`ProcessedMessage`]
//!  - [`UnverifiedMessage`]: Partially checked and potentially decrypted message (if it was originally encrypted)

use crate::ciphersuite::*;
use crate::credentials::*;
use crate::group::*;
use crate::messages::{proposals::*, *};
use crate::schedule::{message_secrets::*, *};
use serde::{Deserialize, Serialize};
use tls_codec::*;

pub(crate) mod ciphertext;
pub(crate) mod codec;
pub(crate) mod message;
pub(crate) mod plaintext;
pub(crate) mod sender;
pub(crate) mod validation;
pub(crate) use ciphertext::*;
pub(crate) use errors::*;
pub(crate) use plaintext::*;

// Crate
pub(crate) use sender::*;

// Public
pub mod errors;

pub use message::*;
pub use sender::*;
pub use validation::*;

// Tests
#[cfg(test)]
mod test_framing;

/// Wire format of MLS messages.
#[derive(
    PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
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
