//! MLS Message (Input)
//!
//! This module defines the [`MlsMessageIn`] structs which implements the
//! `MLSMessage` struct as defined by the MLS specification, but is used
//! exclusively as input for the [`MlsGroup`] API. [`MlsMessageOut`] also
//! implements `MLSMessage`, but for outputs.
//!
//! The [`MlsMessageIn`] struct is meant to be deserialized upon receiving it
//! from the DS. After deserialization, its content (either a
//! [`ProtocolMessage`], [`KeyPackage`], [`Welcome`] or [`GroupInfo`]) can be
//! extracted via [`MlsMessageIn::extract()`] for use with the [`MlsGroup`] API.
//!
//! If an [`MlsMessageIn`] contains a [`ProtocolMessage`],
//! [`ProtocolMessage::group_id()`] can be used to determine which group can be
//! used to process the message.

use tls_codec::Deserialize;

use super::{mls_content::ContentType, *};

use crate::{key_packages::KeyPackage, versions::ProtocolVersion};

/// Before use with the [`MlsGroup`] API, the message has to be unpacked via
/// `extract` to yield either a [`Welcome`] message, a [`KeyPackage`], a
/// [`GroupInfo`] or a [`ProtocolMessage`].
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     ProtocolVersion version = mls10;
///
///     // ... continued in [MlsMessageBody] ...
/// } MLSMessage;
/// ```
///
/// The `-In` suffix of this struct is to separate it from the [`MlsMessageOut`]
/// which is commonly returned by functions of the [`MlsGroup`] API.
#[derive(PartialEq, Debug, Clone, TlsSize, TlsDeserialize)]
#[cfg_attr(feature = "test-utils", derive(TlsSerialize))]
pub struct MlsMessageIn {
    pub(crate) version: ProtocolVersion,
    pub(crate) body: MlsMessageInBody,
}

/// MLSMessage (Body)
///
/// Note: Because [`MlsMessageInBody`] already discriminates between
/// `public_message`, `private_message`, etc., we don't use the `wire_format`
/// field. This prevents inconsistent assignments where `wire_format`
/// contradicts the variant given in `body`.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     // ... continued from [MlsMessage] ...
///
///     WireFormat wire_format;
///     select (MLSMessage.wire_format) {
///         case mls_plaintext:
///             PublicMessage plaintext;
///         case mls_ciphertext:
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
#[derive(Debug, PartialEq, Clone, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub(crate) enum MlsMessageInBody {
    /// Plaintext message
    #[tls_codec(discriminant = 1)]
    PublicMessage(PublicMessage),

    /// Ciphertext message
    #[tls_codec(discriminant = 2)]
    PrivateMessage(PrivateMessage),

    /// Welcome message
    #[tls_codec(discriminant = 3)]
    Welcome(Welcome),

    /// Group information
    #[tls_codec(discriminant = 4)]
    GroupInfo(VerifiableGroupInfo),

    /// KeyPackage
    #[tls_codec(discriminant = 5)]
    KeyPackage(KeyPackage),
}

/// Enum containing the possible contents of an [`MlsMessageIn`].
pub enum MlsMessageContent {
    /// Protocl message (handshake or application message)
    ProtocolMessage(ProtocolMessage),

    /// Welcome message
    Welcome(Welcome),

    /// Group information
    GroupInfo(VerifiableGroupInfo),

    /// KeyPackage
    KeyPackage(KeyPackage),
}

impl MlsMessageIn {
    /// Returns the wire format.
    pub fn wire_format(&self) -> WireFormat {
        match self.body {
            MlsMessageInBody::PrivateMessage(_) => WireFormat::PrivateMessage,
            MlsMessageInBody::PublicMessage(_) => WireFormat::PublicMessage,
            MlsMessageInBody::Welcome(_) => WireFormat::Welcome,
            MlsMessageInBody::GroupInfo(_) => WireFormat::GroupInfo,
            MlsMessageInBody::KeyPackage(_) => WireFormat::KeyPackage,
        }
    }

    /// Extract the content of an [`MlsMessageIn`] after deserialization for use
    /// with the [`MlsGroup`] API.
    pub fn extract(self) -> MlsMessageContent {
        match self.body {
            MlsMessageInBody::PublicMessage(m) => MlsMessageContent::ProtocolMessage(m.into()),
            MlsMessageInBody::PrivateMessage(m) => MlsMessageContent::ProtocolMessage(m.into()),
            MlsMessageInBody::Welcome(w) => MlsMessageContent::Welcome(w),
            MlsMessageInBody::GroupInfo(g) => MlsMessageContent::GroupInfo(g),
            MlsMessageInBody::KeyPackage(k) => MlsMessageContent::KeyPackage(k),
        }
    }

    /// Tries to deserialize from a byte slice. Returns [`MlsMessageError::UnableToDecode`] on failure.
    pub fn try_from_bytes(mut bytes: &[u8]) -> Result<Self, MlsMessageError> {
        MlsMessageIn::tls_deserialize(&mut bytes).map_err(|_| MlsMessageError::UnableToDecode)
    }

    #[cfg(test)]
    pub(crate) fn into_plaintext(self) -> Option<PublicMessage> {
        match self.body {
            MlsMessageInBody::PublicMessage(m) => Some(m),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn into_ciphertext(self) -> Option<PrivateMessage> {
        match self.body {
            MlsMessageInBody::PrivateMessage(m) => Some(m),
            _ => None,
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn into_welcome(self) -> Option<Welcome> {
        match self.body {
            MlsMessageInBody::Welcome(w) => Some(w),
            _ => None,
        }
    }
}

/// Struct containing a message for use with `process_message` and an [`MlsGroup`].
#[derive(Debug, Clone)]
pub struct ProtocolMessage {
    pub(crate) body: ProtocolMessageBody,
}

/// Body of a [`ProtocolMessage`].
#[derive(Debug, Clone)]
pub(crate) enum ProtocolMessageBody {
    PrivateMessage(PrivateMessage),
    PublicMessage(PublicMessage),
}

impl From<ProtocolMessageBody> for ProtocolMessage {
    fn from(body: ProtocolMessageBody) -> Self {
        Self { body }
    }
}

impl ProtocolMessage {
    /// Returns the wire format.
    pub fn wire_format(&self) -> WireFormat {
        match self.body {
            ProtocolMessageBody::PrivateMessage(_) => WireFormat::PrivateMessage,
            ProtocolMessageBody::PublicMessage(_) => WireFormat::PublicMessage,
        }
    }

    /// Returns the group ID.
    pub fn group_id(&self) -> &GroupId {
        match self.body {
            ProtocolMessageBody::PrivateMessage(ref m) => m.group_id(),
            ProtocolMessageBody::PublicMessage(ref m) => m.group_id(),
        }
    }

    /// Returns the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        match self.body {
            ProtocolMessageBody::PrivateMessage(ref m) => m.epoch(),
            ProtocolMessageBody::PublicMessage(ref m) => m.epoch(),
        }
    }

    /// Returns the content type.
    pub fn content_type(&self) -> ContentType {
        match self.body {
            ProtocolMessageBody::PrivateMessage(ref m) => m.content_type(),
            ProtocolMessageBody::PublicMessage(ref m) => m.content_type(),
        }
    }

    /// Returns `true` if this is either an external proposal or external commit
    pub fn is_external(&self) -> bool {
        match &self.body {
            ProtocolMessageBody::PublicMessage(p) => {
                matches!(
                    p.sender(),
                    Sender::NewMemberProposal | Sender::NewMemberCommit | Sender::External(_)
                )
            }
            // external message cannot be encrypted
            ProtocolMessageBody::PrivateMessage(_) => false,
        }
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        self.content_type().is_handshake_message()
    }
}

impl From<PrivateMessage> for ProtocolMessage {
    fn from(private_message: PrivateMessage) -> Self {
        Self {
            body: ProtocolMessageBody::PrivateMessage(private_message),
        }
    }
}

impl From<PublicMessage> for ProtocolMessage {
    fn from(public_message: PublicMessage) -> Self {
        Self {
            body: ProtocolMessageBody::PublicMessage(public_message),
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<MlsMessageIn> for ProtocolMessage {
    fn from(msg: MlsMessageIn) -> Self {
        match msg.body {
            MlsMessageInBody::PublicMessage(m) => ProtocolMessageBody::PublicMessage(m).into(),
            MlsMessageInBody::PrivateMessage(m) => ProtocolMessageBody::PrivateMessage(m).into(),
            _ => panic!("Wrong message type"),
        }
    }
}
