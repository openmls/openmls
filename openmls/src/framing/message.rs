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

use super::{mls_content::ContentType, *};

use crate::error::LibraryError;

/// Unified message type for MLS messages.
/// /// This is only used internally, externally we use either [`MlsMessageIn`] or
/// [`MlsMessageOut`], depending on the context.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     ProtocolVersion version = mls10;
///
///     // ... continued in [MlsMessageBody] ...
/// } MLSMessage;
/// ```
#[derive(PartialEq, Debug, Clone, TlsSerialize, TlsSize, TlsDeserialize)]
pub(crate) struct MlsMessage {
    pub(crate) body: MlsMessageBody,
}

/// MLSMessage (Body)
///
/// Note: Because [MlsMessageBody] already discriminates between
/// `public_message`, `private_message`, etc., we don't use the
/// `wire_format` field. This prevents inconsistent assignments
/// where `wire_format` contradicts the variant given in `body`.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     // ... continued from [MlsMessage] ...
///
///     WireFormat wire_format;
///     select (MLSMessage.wire_format) {
///         case public_message:
///             PublicMessage plaintext;
///         case private_message:
///             PrivateMessage ciphertext;
///         case mls_welcome:
///             Welcome welcome;
///         case mls_group_info:
///             GroupInfo group_info;
///         case mls_key_package:
///             KeyPackage key_package;
///     }
/// } MLSMessage;
/// ```
#[allow(clippy::large_enum_variant)] // TODO #979: Remove the clippy warning suppresion
#[derive(Debug, PartialEq, Clone, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub(crate) enum MlsMessageBody {
    /// Plaintext message
    #[tls_codec(discriminant = 1)]
    PublicMessage(PublicMessage),

    /// Ciphertext message
    #[tls_codec(discriminant = 2)]
    PrivateMessage(PrivateMessage),
}

impl MlsMessage {
    /// Returns the wire format.
    fn wire_format(&self) -> WireFormat {
        match self.body {
            MlsMessageBody::PrivateMessage(_) => WireFormat::PrivateMessage,
            MlsMessageBody::PublicMessage(_) => WireFormat::PublicMessage,
        }
    }

    /// Returns the group ID.
    fn group_id(&self) -> &GroupId {
        match self.body {
            MlsMessageBody::PrivateMessage(ref m) => m.group_id(),
            MlsMessageBody::PublicMessage(ref m) => m.group_id(),
        }
    }

    /// Returns the epoch.
    fn epoch(&self) -> GroupEpoch {
        match self.body {
            MlsMessageBody::PrivateMessage(ref m) => m.epoch(),
            MlsMessageBody::PublicMessage(ref m) => m.epoch(),
        }
    }

    /// Returns the content type.
    fn content_type(&self) -> ContentType {
        match self.body {
            MlsMessageBody::PrivateMessage(ref m) => m.content_type(),
            MlsMessageBody::PublicMessage(ref m) => m.content_type(),
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

    /// Returns `true` if this is either an external proposal or external commit
    pub fn is_external(&self) -> bool {
        match &self.mls_message.body {
            MlsMessageBody::PublicMessage(p) => {
                matches!(
                    p.sender(),
                    Sender::NewMemberProposal | Sender::NewMemberCommit | Sender::External(_)
                )
            }
            // external message cannot be encrypted
            MlsMessageBody::PrivateMessage(_) => false,
        }
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

    /// Returns an [`PublicMessage`] if the [`MlsMessageIn`] contains one. Otherwise returns `None`.
    #[cfg(test)]
    pub(crate) fn into_plaintext(self) -> Option<PublicMessage> {
        if let MlsMessageBody::PublicMessage(pt) = self.mls_message.body {
            Some(pt)
        } else {
            None
        }
    }

    /// Returns an [`PrivateMessage`] if the [`MlsMessageIn`] contains one. Otherwise returns `None`.
    #[cfg(test)]
    pub(crate) fn into_ciphertext(self) -> Option<PrivateMessage> {
        if let MlsMessageBody::PrivateMessage(ct) = self.mls_message.body {
            Some(ct)
        } else {
            None
        }
    }
}

/// Unified message type for outgoing MLS messages.
#[derive(PartialEq, Debug, Clone, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct MlsMessageOut {
    pub(crate) mls_message: MlsMessage,
}

impl From<PublicMessage> for MlsMessageOut {
    fn from(plaintext: PublicMessage) -> Self {
        let body = MlsMessageBody::PublicMessage(plaintext);

        Self {
            mls_message: MlsMessage { body },
        }
    }
}

impl From<PrivateMessage> for MlsMessageOut {
    fn from(ciphertext: PrivateMessage) -> Self {
        let body = MlsMessageBody::PrivateMessage(ciphertext);

        Self {
            mls_message: MlsMessage { body },
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
impl From<PublicMessage> for MlsMessageIn {
    fn from(plaintext: PublicMessage) -> Self {
        let body = MlsMessageBody::PublicMessage(plaintext);

        Self {
            mls_message: MlsMessage { body },
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<PrivateMessage> for MlsMessageIn {
    fn from(ciphertext: PrivateMessage) -> Self {
        let body = MlsMessageBody::PrivateMessage(ciphertext);

        Self {
            mls_message: MlsMessage { body },
        }
    }
}
