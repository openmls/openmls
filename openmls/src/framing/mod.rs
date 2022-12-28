//! # Message framing
//!
//! This module contains framing-related operations for MLS messages, including validation operations.
//! The general structure of the framing process in OpenMLS closely mirrors the
//! one described in Section 7 of the MLS specification. It can be visualized as follows:
//!
//! ```text
//!                               Proposal        Commit     Application Data
//!                                  |              |              |
//!                                  +--------------+--------------+
//!                                                 |
//!                                                 V
//!                                          FramedContent
//!                                              |  |                -.
//!                                              |  |                  |
//!                                     +--------+  |                  |
//!                                     |           |                  |
//!                                     V           |                  +-- Asymmetric
//!                           FramedContentAuthData |                  |   Sign / Verify
//!                                     |           |                  |
//!                                     +--------+  |                  |
//!                                              |  |                  |
//!                                              V  V                -'
//!                                        AuthenticatedContent
//!                                                 |                -.
//!                                                 |                  |
//!                                                 |                  |
//!                                        +--------+--------+         +-- Symmetric
//!                                        |                 |         |   Protect / Unprotect
//!                                        V                 V         |
//! Welcome  KeyPackage  GroupInfo   PublicMessage    PrivateMessage -'
//!    |          |          |             |                 |
//!    |          |          |             |                 |
//!    +----------+----------+----+--------+-----------------+
//!                               |
//!                               V
//!                           MLSMessage
//! ```
//!
//!  - [`MlsMessageIn`]/[`MlsMessageOut`]: Unified message type for incoming & outgoing MLS messages
//!  - [`ApplicationMessage`]: Application message received through a [`ProcessedMessage`]

use crate::ciphersuite::*;
use crate::credentials::*;
use crate::group::*;
use crate::messages::{proposals::*, *};
use crate::schedule::{message_secrets::*, *};
use serde::{Deserialize, Serialize};
use tls_codec::*;

pub(crate) mod codec;
pub(crate) mod message;
pub(crate) mod mls_auth_content;
pub(crate) mod mls_content;
pub(crate) mod private_message;
pub(crate) mod public_message;
pub(crate) mod sender;
pub(crate) mod validation;
pub(crate) use errors::*;
pub(crate) use private_message::*;
pub(crate) use public_message::*;

#[cfg(any(feature = "test-utils", test))]
pub(crate) use mls_auth_content::*;

#[cfg(test)]
pub(crate) use mls_content::*;

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
    PublicMessage = 1,
    /// Encrypted message
    PrivateMessage = 2,
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
