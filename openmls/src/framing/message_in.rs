//! MLS Message (Input)
//!
//! This module defines the [`MlsMessageIn`] structs which implements the
//! `MLSMessage` struct as defined by the MLS specification, but is used
//! exclusively as input for the [`MlsGroup`] API. [`MlsMessageOut`] also
//! implements `MLSMessage`, but for outputs.
//!
//! The [`MlsMessageIn`] struct is meant to be deserialized upon receiving it
//! from the DS. After deserialization, its content (either a [`PublicMessage`],
//! [`PrivateMessage`], [`KeyPackageIn`], [`Welcome`] or
//! [`GroupInfo`](crate::messages::group_info::GroupInfo)) can be extracted via
//! [`MlsMessageIn::extract()`] for use with the [`MlsGroup`] API.
//!
//! If an [`MlsMessageIn`] contains a [`PublicMessage`] or [`PrivateMessage`],
//! can be used to determine which group can be used to process the message.

use super::*;
use crate::{
    key_packages::KeyPackageIn, messages::group_info::VerifiableGroupInfo,
    versions::ProtocolVersion,
};

/// Before use with the [`MlsGroup`] API, the message has to be unpacked via
/// `extract` to yield its [`MlsMessageBodyIn`].
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
#[derive(PartialEq, Debug, Clone, TlsSize)]
#[cfg_attr(feature = "test-utils", derive(TlsSerialize))]
pub struct MlsMessageIn {
    pub(crate) version: ProtocolVersion,
    pub(crate) body: MlsMessageBodyIn,
}

/// MLSMessage (Body)
///
/// Note: Because [`MlsMessageBodyIn`] already discriminates between
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
#[derive(Debug, PartialEq, Clone, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
#[cfg_attr(feature = "test-utils", derive(TlsSerialize))]
#[repr(u16)]
pub enum MlsMessageBodyIn {
    /// Plaintext message
    #[tls_codec(discriminant = 1)]
    PublicMessage(PublicMessageIn),

    /// Ciphertext message
    #[tls_codec(discriminant = 2)]
    PrivateMessage(PrivateMessageIn),

    /// Welcome message
    #[tls_codec(discriminant = 3)]
    Welcome(Welcome),

    /// Group information
    #[tls_codec(discriminant = 4)]
    GroupInfo(VerifiableGroupInfo),

    /// KeyPackage
    #[tls_codec(discriminant = 5)]
    KeyPackage(KeyPackageIn),
}

impl MlsMessageIn {
    /// Returns the wire format.
    pub fn wire_format(&self) -> WireFormat {
        match self.body {
            MlsMessageBodyIn::PrivateMessage(_) => WireFormat::PrivateMessage,
            MlsMessageBodyIn::PublicMessage(_) => WireFormat::PublicMessage,
            MlsMessageBodyIn::Welcome(_) => WireFormat::Welcome,
            MlsMessageBodyIn::GroupInfo(_) => WireFormat::GroupInfo,
            MlsMessageBodyIn::KeyPackage(_) => WireFormat::KeyPackage,
        }
    }

    /// Extract the content of an [`MlsMessageIn`] after deserialization for use
    /// with the [`MlsGroup`] API.
    pub fn extract(self) -> MlsMessageBodyIn {
        self.body
    }

    /// Try to convert the message into a [`ProtocolMessage`].
    pub fn try_into_protocol_message(self) -> Result<ProtocolMessage, ProtocolMessageError> {
        self.try_into()
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn into_keypackage(self) -> Option<crate::key_packages::KeyPackage> {
        match self.body {
            MlsMessageBodyIn::KeyPackage(key_package) => {
                debug_assert!(key_package.version_is_supported(self.version));
                Some(key_package.into())
            }
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn into_plaintext(self) -> Option<PublicMessage> {
        match self.body {
            MlsMessageBodyIn::PublicMessage(m) => Some(m.into()),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn into_ciphertext(self) -> Option<PrivateMessageIn> {
        match self.body {
            MlsMessageBodyIn::PrivateMessage(m) => Some(m),
            _ => None,
        }
    }

    /// Convert this message into a [`Welcome`].
    ///
    /// Returns `None` if this message is not a welcome message.
    #[cfg(any(feature = "test-utils", test))]
    pub fn into_welcome(self) -> Option<Welcome> {
        match self.body {
            MlsMessageBodyIn::Welcome(w) => Some(w),
            _ => None,
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn into_protocol_message(self) -> Option<ProtocolMessage> {
        match self.body {
            MlsMessageBodyIn::PublicMessage(m) => Some(m.into()),
            MlsMessageBodyIn::PrivateMessage(m) => Some(m.into()),
            _ => None,
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn into_verifiable_group_info(self) -> Option<VerifiableGroupInfo> {
        match self.body {
            MlsMessageBodyIn::GroupInfo(group_info) => Some(group_info),
            _ => None,
        }
    }
}

/// Enum containing a message for use with `process_message` and an
/// [`MlsGroup`]. Both [`PublicMessage`] and [`PrivateMessage`] implement
/// [`Into<ProtocolMessage>`].
#[derive(Debug, Clone)]
pub enum ProtocolMessage {
    /// A [`ProtocolMessage`] containing a [`PrivateMessage`].
    PrivateMessage(PrivateMessageIn),
    /// A [`ProtocolMessage`] containing a [`PublicMessage`].
    PublicMessage(Box<PublicMessageIn>),
}

impl ProtocolMessage {
    /// Returns the wire format.
    pub fn wire_format(&self) -> WireFormat {
        match self {
            ProtocolMessage::PrivateMessage(_) => WireFormat::PrivateMessage,
            ProtocolMessage::PublicMessage(_) => WireFormat::PublicMessage,
        }
    }

    /// Returns the group ID.
    pub fn group_id(&self) -> &GroupId {
        match self {
            ProtocolMessage::PrivateMessage(ref m) => m.group_id(),
            ProtocolMessage::PublicMessage(ref m) => m.group_id(),
        }
    }

    /// Returns the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        match self {
            ProtocolMessage::PrivateMessage(ref m) => m.epoch(),
            ProtocolMessage::PublicMessage(ref m) => m.epoch(),
        }
    }

    /// Returns the content type.
    pub fn content_type(&self) -> ContentType {
        match self {
            ProtocolMessage::PrivateMessage(ref m) => m.content_type(),
            ProtocolMessage::PublicMessage(ref m) => m.content_type(),
        }
    }

    /// Returns `true` if this is either an external proposal or external commit
    pub fn is_external(&self) -> bool {
        match &self {
            ProtocolMessage::PublicMessage(p) => {
                matches!(
                    p.sender(),
                    Sender::NewMemberProposal | Sender::NewMemberCommit | Sender::External(_)
                )
            }
            // external message cannot be encrypted
            ProtocolMessage::PrivateMessage(_) => false,
        }
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        self.content_type().is_handshake_message()
    }
}

impl From<PrivateMessageIn> for ProtocolMessage {
    fn from(private_message: PrivateMessageIn) -> Self {
        ProtocolMessage::PrivateMessage(private_message)
    }
}

impl From<PublicMessageIn> for ProtocolMessage {
    fn from(public_message: PublicMessageIn) -> Self {
        ProtocolMessage::PublicMessage(Box::new(public_message))
    }
}

impl TryFrom<MlsMessageIn> for ProtocolMessage {
    type Error = ProtocolMessageError;

    fn try_from(msg: MlsMessageIn) -> Result<Self, Self::Error> {
        match msg.body {
            MlsMessageBodyIn::PublicMessage(m) => Ok(m.into()),
            MlsMessageBodyIn::PrivateMessage(m) => Ok(ProtocolMessage::PrivateMessage(m)),
            _ => Err(ProtocolMessageError::WrongWireFormat),
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<PublicMessage> for ProtocolMessage {
    fn from(msg: PublicMessage) -> Self {
        PublicMessageIn::from(msg).into()
    }
}
