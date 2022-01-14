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
use crate::treesync::*;
use lazy_static::lazy_static;
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
#[derive(
    PartialEq, Clone, Copy, Debug, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
#[repr(u8)]
pub enum WireFormat {
    MlsPlaintext = 1,
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

/// Defines what wire format is acceptable for incoming handshake messages.
/// Note that application messages must always be encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum IncomingWireFormatPolicy {
    /// Handshake messages must always be MlsCiphertext
    AlwaysCiphertext,
    /// Handshake messages must always be MlsPlaintext
    AlwaysPlaintext,
    /// Handshake messages can either be MlsCiphertext or MlsPlaintext
    Mixed,
}

impl IncomingWireFormatPolicy {
    pub(crate) fn is_compatible(&self, wire_format: WireFormat) -> bool {
        match self {
            IncomingWireFormatPolicy::AlwaysCiphertext => wire_format == WireFormat::MlsCiphertext,
            IncomingWireFormatPolicy::AlwaysPlaintext => wire_format == WireFormat::MlsPlaintext,
            IncomingWireFormatPolicy::Mixed => {
                wire_format == WireFormat::MlsCiphertext || wire_format == WireFormat::MlsPlaintext
            }
        }
    }
}

/// Defines what wire format should be used for outgoing handshake messages.
/// Note that application messages must always be encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum OutgoingWireFormatPolicy {
    /// Handshake messages must always be MlsCiphertext
    AlwaysCiphertext,
    /// Handshake messages must always be MlsPlaintext
    AlwaysPlaintext,
}

/// Defines what wire format is desired for outgoing handshake messages.
/// Note that application messages must always be encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireFormatPolicy {
    outgoing: OutgoingWireFormatPolicy,
    incoming: IncomingWireFormatPolicy,
}

impl WireFormatPolicy {
    pub fn new(outgoing: OutgoingWireFormatPolicy, incoming: IncomingWireFormatPolicy) -> Self {
        Self { outgoing, incoming }
    }

    /// Get a reference to the wire format policy's outgoing wire format policy.
    pub fn outgoing(&self) -> OutgoingWireFormatPolicy {
        self.outgoing
    }

    /// Get a reference to the wire format policy's incoming wire format policy.
    pub fn incoming(&self) -> IncomingWireFormatPolicy {
        self.incoming
    }

    /// Set the wire format policy's outgoing wire format policy.
    pub fn set_outgoing(&mut self, outgoing: OutgoingWireFormatPolicy) {
        self.outgoing = outgoing;
    }

    /// Set the wire format policy's incoming wire format policy.
    pub fn set_incoming(&mut self, incoming: IncomingWireFormatPolicy) {
        self.incoming = incoming;
    }
}

impl Default for WireFormatPolicy {
    fn default() -> Self {
        *PURE_CIPHERTEXT_WIRE_FORMAT_POLICY
    }
}

impl From<OutgoingWireFormatPolicy> for WireFormat {
    fn from(outgoing: OutgoingWireFormatPolicy) -> Self {
        match outgoing {
            OutgoingWireFormatPolicy::AlwaysCiphertext => WireFormat::MlsCiphertext,
            OutgoingWireFormatPolicy::AlwaysPlaintext => WireFormat::MlsPlaintext,
        }
    }
}

lazy_static! {
    pub static ref ALL_VALID_WIRE_FORMAT_POLICIES: Vec<WireFormatPolicy> = vec![
        *PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        *PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        *MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
        *MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY,
    ];
}

lazy_static! {
    pub static ref PURE_PLAINTEXT_WIRE_FORMAT_POLICY: WireFormatPolicy = WireFormatPolicy::new(
        OutgoingWireFormatPolicy::AlwaysPlaintext,
        IncomingWireFormatPolicy::AlwaysPlaintext,
    );
}

lazy_static! {
    pub static ref PURE_CIPHERTEXT_WIRE_FORMAT_POLICY: WireFormatPolicy = WireFormatPolicy::new(
        OutgoingWireFormatPolicy::AlwaysCiphertext,
        IncomingWireFormatPolicy::AlwaysCiphertext,
    );
}

lazy_static! {
    pub static ref MIXED_PLAINTEXT_WIRE_FORMAT_POLICY: WireFormatPolicy = WireFormatPolicy::new(
        OutgoingWireFormatPolicy::AlwaysPlaintext,
        IncomingWireFormatPolicy::Mixed,
    );
}

lazy_static! {
    pub static ref MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY: WireFormatPolicy = WireFormatPolicy::new(
        OutgoingWireFormatPolicy::AlwaysCiphertext,
        IncomingWireFormatPolicy::Mixed,
    );
}
