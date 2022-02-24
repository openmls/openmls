//! MLS Message types
//!
//! This module defines two opaque message types that are used by the [`MlsGroup`](crate::group::mls_group::MlsGroup) API.
//! [`MlsMessageIn`] is used for messages between the Delivery Service and the client. It can be instantiated
//! from a byte slice.
//! [`MlsMessageOut`] is returned by various functions of the [`MlsGroup`](crate::group::mls_group::MlsGroup) API.
//! It is to be used between the client and the Delivery Service. It can be serialized to a byte vector.
//!
//! Both messages have the same API. The framing part of the message can be inspected through it. In particular,
//! it is important to look at [`MlsMessageIn::group_id()`] to determine in which
//! [`MlsGroup`](crate::group::mls_group::MlsGroup) it should be processed.

use tls_codec::{Deserialize, Serialize};

use super::*;

use crate::error::LibraryError;

/// Unified message type for MLS messages.
/// /// This is only used internally, externally we use either [`MlsMessageIn`] or
/// [`MlsMessageOut`], depending on the context.
/// Since the memory footprint can differ considerably between [`VerifiableMlsPlaintext`]
/// and [`MlsCiphertext`], we use `Box<T>` for more efficient memory allocation.
#[derive(PartialEq, Debug, Clone)]
pub(crate) enum MlsMessage {
    /// Plaintext message
    Plaintext(Box<VerifiableMlsPlaintext>),

    /// Ciphertext message
    Ciphertext(Box<MlsCiphertext>),
}

impl MlsMessage {
    /// Returns the wire format.
    fn wire_format(&self) -> WireFormat {
        match self {
            MlsMessage::Ciphertext(_) => WireFormat::MlsCiphertext,
            MlsMessage::Plaintext(_) => WireFormat::MlsPlaintext,
        }
    }

    /// Returns the group ID.
    fn group_id(&self) -> &GroupId {
        match self {
            MlsMessage::Ciphertext(m) => m.group_id(),
            MlsMessage::Plaintext(m) => m.group_id(),
        }
    }

    /// Returns the epoch.
    fn epoch(&self) -> GroupEpoch {
        match self {
            MlsMessage::Ciphertext(m) => m.epoch(),
            MlsMessage::Plaintext(m) => m.epoch(),
        }
    }

    /// Returns the content type.
    fn content_type(&self) -> ContentType {
        match self {
            MlsMessage::Ciphertext(m) => m.content_type(),
            MlsMessage::Plaintext(m) => m.content_type(),
        }
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    fn is_handshake_message(&self) -> bool {
        self.content_type().is_handshake_message()
    }

    /// Tries to deserialize from a byte slice. Returns [`MlsMessageError::DecodingError`] on failure.
    fn try_from_bytes(mut bytes: &[u8]) -> Result<Self, MlsMessageError> {
        MlsMessage::tls_deserialize(&mut bytes).map_err(|_| MlsMessageError::UnableToDecode)
    }

    /// Serializes the message to a byte vector. Returns [`MlsMessageError::EncodingError`] on failure.
    fn to_bytes(&self) -> Result<Vec<u8>, MlsMessageError> {
        Ok(self
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?)
    }
}

/// Unified message type for incoming MLS messages.
#[derive(Debug, Clone, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct MlsMessageIn {
    pub(crate) mls_message: MlsMessage,
}

impl MlsMessageIn {
    /// Returns the wire format.
    pub fn wire_format(&self) -> WireFormat {
        self.mls_message.wire_format()
    }

    /// Returns the group ID.
    pub fn group_id(&self) -> &GroupId {
        self.mls_message.group_id()
    }

    /// Returns the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        self.mls_message.epoch()
    }

    /// Returns the content type.
    pub fn content_type(&self) -> ContentType {
        self.mls_message.content_type()
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        self.mls_message.is_handshake_message()
    }

    /// Tries to deserialize from a byte slice. Returns [`MlsMessageError::UnableToDecode`] on failure.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, MlsMessageError> {
        Ok(Self {
            mls_message: MlsMessage::try_from_bytes(bytes)?,
        })
    }

    /// Serializes the message to a byte vector. Returns [`MlsMessageError::LibraryError`] on failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MlsMessageError> {
        self.mls_message.to_bytes()
    }
}

/// Unified message type for outgoing MLS messages.
#[derive(PartialEq, Debug, Clone, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct MlsMessageOut {
    pub(crate) mls_message: MlsMessage,
}

impl From<VerifiableMlsPlaintext> for MlsMessageOut {
    fn from(plaintext: VerifiableMlsPlaintext) -> Self {
        Self {
            mls_message: MlsMessage::Plaintext(Box::new(plaintext)),
        }
    }
}

impl From<MlsPlaintext> for MlsMessageOut {
    fn from(plaintext: MlsPlaintext) -> Self {
        Self {
            mls_message: MlsMessage::Plaintext(Box::new(VerifiableMlsPlaintext::from_plaintext(
                plaintext, None,
            ))),
        }
    }
}

impl From<MlsCiphertext> for MlsMessageOut {
    fn from(ciphertext: MlsCiphertext) -> Self {
        Self {
            mls_message: MlsMessage::Ciphertext(Box::new(ciphertext)),
        }
    }
}

impl MlsMessageOut {
    /// Returns the wire format.
    pub fn wire_format(&self) -> WireFormat {
        self.mls_message.wire_format()
    }

    /// Returns the group ID.
    pub fn group_id(&self) -> &GroupId {
        self.mls_message.group_id()
    }

    /// Returns the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        self.mls_message.epoch()
    }

    /// Returns the content type.
    pub fn content_type(&self) -> ContentType {
        self.mls_message.content_type()
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        self.mls_message.is_handshake_message()
    }

    /// Tries to deserialize from a byte slice. Returns [`MlsMessageError::UnableToDecode`] on failure.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, MlsMessageError> {
        Ok(Self {
            mls_message: MlsMessage::try_from_bytes(bytes)?,
        })
    }

    /// Serializes the message to a byte vector. Returns [`MlsMessageError::LibraryError`] on failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MlsMessageError> {
        self.mls_message.to_bytes()
    }
}

impl From<MlsMessageOut> for MlsMessageIn {
    fn from(message: MlsMessageOut) -> Self {
        MlsMessageIn {
            mls_message: message.mls_message,
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<VerifiableMlsPlaintext> for MlsMessageIn {
    fn from(plaintext: VerifiableMlsPlaintext) -> Self {
        Self {
            mls_message: MlsMessage::Plaintext(Box::new(plaintext)),
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<MlsCiphertext> for MlsMessageIn {
    fn from(ciphertext: MlsCiphertext) -> Self {
        Self {
            mls_message: MlsMessage::Ciphertext(Box::new(ciphertext)),
        }
    }
}
