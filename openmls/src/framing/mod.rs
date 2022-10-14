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
///
/// # MLS Presentation Language
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// enum {
///   reserved(0),
///   mls_plaintext(1),
///   mls_ciphertext(2),
///   mls_welcome(3),
///   mls_group_info(4),
///   mls_key_package(5),
///   (255)
/// } WireFormat;
/// ```
#[derive(
    PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
#[repr(u8)]
pub enum WireFormat {
    /// Reserved
    Reserved = 0,
    /// MLSPlaintext message
    MlsPlaintext = 1,
    /// MLSCiphertext message
    MlsCiphertext = 2,
    /// Welcome message
    MlsWelcome = 3,
    /// GroupInfo message
    MlsGroupInfo = 4,
    /// KeyPackage message
    MlsKeyPackage = 5,
}

impl TryFrom<u8> for WireFormat {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(WireFormat::Reserved),
            1 => Ok(WireFormat::MlsPlaintext),
            2 => Ok(WireFormat::MlsCiphertext),
            3 => Ok(WireFormat::MlsWelcome),
            4 => Ok(WireFormat::MlsGroupInfo),
            5 => Ok(WireFormat::MlsKeyPackage),
            _ => Err(()),
        }
    }
}

impl Into<u8> for WireFormat {
    fn into(self) -> u8 {
        match self {
            WireFormat::Reserved => 0,
            WireFormat::MlsPlaintext => 1,
            WireFormat::MlsCiphertext => 2,
            WireFormat::MlsWelcome => 3,
            WireFormat::MlsGroupInfo => 4,
            WireFormat::MlsKeyPackage => 5,
        }
    }
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
}
