//! This module contains the [`FramedContent`] struct and associated helper structs
//! such as [`FramedContentTbs`], as well as their implementations.

use crate::{
    ciphersuite::signable::Signable,
    error::LibraryError,
    group::{GroupEpoch, GroupId},
    messages::{proposals::Proposal, Commit},
    versions::ProtocolVersion,
};

use std::{
    convert::TryFrom,
    io::{Read, Write},
};

use super::{
    mls_auth_content::{AuthenticatedContent, FramedContentAuthData},
    Sender, WireFormat,
};

use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, Size, TlsByteVecU32,
    TlsDeserialize, TlsSerialize, TlsSize, VLBytes,
};

/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     Sender sender;
///     opaque authenticated_data<V>;
///
///     // ... continued in [FramedContentBody] ...
/// } FramedContent;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub(crate) struct FramedContent {
    pub(super) group_id: GroupId,
    pub(super) epoch: GroupEpoch,
    pub(super) sender: Sender,
    pub(super) authenticated_data: VLBytes,

    pub(super) body: FramedContentBody,
}

impl From<AuthenticatedContent> for FramedContent {
    fn from(mls_auth_content: AuthenticatedContent) -> Self {
        mls_auth_content.tbs.content
    }
}

/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     // ... continued from [FramedContent] ...
///
///     ContentType content_type;
///     select (FramedContent.content_type) {
///         case application:
///           opaque application_data<V>;
///         case proposal:
///           Proposal proposal;
///         case commit:
///           Commit commit;
///     }
/// } FramedContent;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[repr(u8)]
pub(crate) enum FramedContentBody {
    #[tls_codec(discriminant = 1)]
    Application(TlsByteVecU32),
    #[tls_codec(discriminant = 2)]
    Proposal(Proposal),
    #[tls_codec(discriminant = 3)]
    Commit(Commit),
}

impl FramedContentBody {
    pub(crate) fn content_type(&self) -> ContentType {
        match self {
            Self::Application(_) => ContentType::Application,
            Self::Proposal(_) => ContentType::Proposal,
            Self::Commit(_) => ContentType::Commit,
        }
    }

    /// Returns the length of the serialized content without the `content_type` field.
    pub(crate) fn serialized_len_without_type(&self) -> usize {
        match self {
            FramedContentBody::Application(a) => a.tls_serialized_len(),
            FramedContentBody::Proposal(p) => p.tls_serialized_len(),
            FramedContentBody::Commit(c) => c.tls_serialized_len(),
        }
    }

    /// Serializes the content without the `content_type` field.
    pub(crate) fn serialize_without_type<W: Write>(
        &self,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        match self {
            FramedContentBody::Application(a) => a.tls_serialize(writer),
            FramedContentBody::Proposal(p) => p.tls_serialize(writer),
            FramedContentBody::Commit(c) => c.tls_serialize(writer),
        }
    }

    pub(super) fn deserialize_without_type<R: Read>(
        bytes: &mut R,
        content_type: ContentType,
    ) -> Result<Self, tls_codec::Error> {
        Ok(match content_type {
            ContentType::Application => {
                FramedContentBody::Application(TlsByteVecU32::tls_deserialize(bytes)?)
            }
            ContentType::Proposal => FramedContentBody::Proposal(Proposal::tls_deserialize(bytes)?),
            ContentType::Commit => FramedContentBody::Commit(Commit::tls_deserialize(bytes)?),
        })
    }
}

#[derive(
    PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
#[repr(u8)]
pub enum ContentType {
    Application = 1,
    Proposal = 2,
    Commit = 3,
}

impl TryFrom<u8> for ContentType {
    type Error = tls_codec::Error;
    fn try_from(value: u8) -> Result<Self, tls_codec::Error> {
        match value {
            1 => Ok(ContentType::Application),
            2 => Ok(ContentType::Proposal),
            3 => Ok(ContentType::Commit),
            _ => Err(tls_codec::Error::DecodingError(format!(
                "{} is not a valid content type",
                value
            ))),
        }
    }
}

impl From<&FramedContentBody> for ContentType {
    fn from(value: &FramedContentBody) -> Self {
        value.content_type()
    }
}

impl ContentType {
    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub(crate) fn is_handshake_message(&self) -> bool {
        self == &ContentType::Proposal || self == &ContentType::Commit
    }
}

/// 7.2 Encoding and Decoding a Plaintext
///
/// ```c
/// // draft-ietf-mls-protocol-17
///
/// struct {
///   FramedContentTBS tbs;
///   FramedContentAuthData auth;
/// } AuthenticatedContentTBM;
/// ```
#[derive(Debug)]
pub(crate) struct AuthenticatedContentTbm<'a> {
    pub(crate) tbs_payload: &'a [u8],
    pub(crate) auth: &'a FramedContentAuthData,
}

impl<'a> AuthenticatedContentTbm<'a> {
    pub(crate) fn new(
        tbs_payload: &'a [u8],
        auth: &'a FramedContentAuthData,
    ) -> Result<Self, LibraryError> {
        Ok(Self { tbs_payload, auth })
    }

    pub(crate) fn into_bytes(self) -> Result<Vec<u8>, tls_codec::Error> {
        let mut buffer = self.tbs_payload.to_vec();
        self.auth.tls_serialize(&mut buffer)?;
        Ok(buffer)
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FramedContentTbs {
    pub(super) version: ProtocolVersion,
    pub(super) wire_format: WireFormat,
    pub(super) content: FramedContent,
    pub(super) serialized_context: Option<Vec<u8>>,
}

impl Signable for FramedContentTbs {
    type SignedOutput = AuthenticatedContent;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        "FramedContentTBS"
    }
}

impl FramedContentTbs {
    /// Create an FramedContentTbs from an existing values.
    /// Note that if you would like to add a serialized context, you
    /// should subsequently call [`with_context`].
    pub(crate) fn new(
        wire_format: WireFormat,
        group_id: GroupId,
        epoch: impl Into<GroupEpoch>,
        sender: Sender,
        authenticated_data: VLBytes,
        body: FramedContentBody,
    ) -> Self {
        let content = FramedContent {
            group_id,
            epoch: epoch.into(),
            sender,
            authenticated_data,
            body,
        };
        FramedContentTbs {
            version: ProtocolVersion::Mls10,
            wire_format,
            content,
            serialized_context: None,
        }
    }

    /// Adds a serialized context to FramedContentTbs.
    /// This consumes the original struct and can be used as a builder function.
    pub(crate) fn with_context(mut self, serialized_context: Vec<u8>) -> Self {
        self.serialized_context = Some(serialized_context);
        self
    }

    /// Get the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.content.epoch
    }

    /// Serialize the [`FramedContentTbs`] without [`ProtocolVersion`]. This is
    /// required for the serialization of [`AuthenticatedContent`].
    pub fn tls_serialize_without_version<W: Write>(
        &self,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        let mut written = self.wire_format.tls_serialize(writer)?;
        written += self.content.tls_serialize(writer)?;
        written += if let Some(serialized_context) = &self.serialized_context {
            // Only members and new members joining via commit should have a context.
            debug_assert!(matches!(
                self.content.sender,
                Sender::Member(_) | Sender::NewMemberCommit
            ));
            writer.write(serialized_context)?
        } else {
            0
        };
        Ok(written)
    }

    /// Compute the length of [`FramedContentTbs`] without [`ProtocolVersion`].
    /// This is required for the serialization of [`AuthenticatedContent`].
    pub fn tls_serialized_len_without_version(&self) -> usize {
        self.wire_format.tls_serialized_len()
            + self.content.tls_serialized_len()
            + if let Some(serialized_context) = &self.serialized_context {
                serialized_context.tls_serialized_len()
            } else {
                0
            }
    }
}

impl Size for FramedContentTbs {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.version.tls_serialized_len() + self.tls_serialized_len_without_version()
    }
}

impl TlsSerializeTrait for FramedContentTbs {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = self.version.tls_serialize(writer)?;
        self.tls_serialize_without_version(writer)
            .map(|l| l + written)
    }
}
