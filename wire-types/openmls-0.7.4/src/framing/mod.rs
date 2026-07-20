//! # Message framing
//!
//! This module contains framing-related operations for MLS messages, including
//! validation logic.
//!
//! The general structure of the framing process in OpenMLS closely follows the
//! design described in Section 7 of the MLS specification. It can be visualized
//! as follows:
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

use serde::{Deserialize, Serialize};
use tls_codec::*;

use crate::{ciphersuite::*, group::*, messages::*};

pub(crate) mod codec;

pub(crate) mod message_in;
pub(crate) mod message_out;
pub(crate) mod mls_auth_content;
pub(crate) mod mls_auth_content_in;
pub(crate) mod mls_content;
pub(crate) mod mls_content_in;
pub(crate) mod private_message;
pub(crate) mod private_message_in;
pub(crate) mod public_message;
pub(crate) mod public_message_in;
pub(crate) mod sender;

#[cfg(test)]
pub(crate) use mls_auth_content::*;
#[cfg(test)]
pub(crate) use mls_auth_content_in::*;

#[cfg(test)]
pub(crate) use mls_content::*;
#[cfg(test)]
pub(crate) use mls_content_in::*;

// Crate
pub(crate) use sender::*;

// Public
pub mod errors;

pub use message_in::*;
pub use message_out::*;
pub use private_message::*;
pub use private_message_in::*;
pub use public_message::*;
pub use public_message_in::*;
pub use sender::*;

/// Wire format of MLS messages.
///
/// // draft-ietf-mls-protocol-17
/// | Value           | Name                     | Recommended | Reference |
/// |-----------------|--------------------------|-------------|-----------|
/// | 0x0000          | RESERVED                 | N/A         | RFC XXXX  |
/// | 0x0001          | mls_plaintext            | Y           | RFC XXXX  |
/// | 0x0002          | mls_ciphertext           | Y           | RFC XXXX  |
/// | 0x0003          | mls_welcome              | Y           | RFC XXXX  |
/// | 0x0004          | mls_group_info           | Y           | RFC XXXX  |
/// | 0x0005          | mls_key_package          | Y           | RFC XXXX  |
/// | 0xf000 - 0xffff | Reserved for Private Use | N/A         | RFC XXXX  |
#[derive(
    PartialEq,
    Eq,
    Clone,
    Copy,
    Debug,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
#[repr(u16)]
pub enum WireFormat {
    /// Plaintext message
    PublicMessage = 1,
    /// Encrypted message
    PrivateMessage = 2,
    /// Welcome message
    Welcome = 3,
    /// Group information
    GroupInfo = 4,
    /// KeyPackage
    KeyPackage = 5,
}

/// ```c
/// // draft-ietf-mls-protocol-17
/// enum {
///     reserved(0),
///     application(1),
///     proposal(2),
///     commit(3),
///     (255)
/// } ContentType;
/// ```
#[derive(
    PartialEq,
    Eq,
    Clone,
    Copy,
    Debug,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
#[repr(u8)]
pub enum ContentType {
    /// Application message
    Application = 1,
    /// Proposal
    Proposal = 2,
    /// Commit
    Commit = 3,
}
