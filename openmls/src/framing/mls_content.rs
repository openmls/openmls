//! This module contains the [`MlsContent`] struct and associated helper structs
//! such as [`MlsContentTbs`], as well as their implementations.

use crate::ciphersuite::signable::Signable;
use crate::group::GroupEpoch;
use crate::group::GroupId;
use crate::messages::proposals::Proposal;
use crate::messages::Commit;

#[cfg(test)]
use super::MlsPlaintext;

use super::Sender;
use super::WireFormat;

use crate::error::LibraryError;

use super::mls_auth_content::MlsContentAuthData;

use std::convert::TryFrom;

use std::io::Read;

use std::io::Write;

use tls_codec::TlsByteVecU32;
use tls_codec::VLBytes;

use super::mls_auth_content::MlsAuthContent;

//use serde::{Deserialize, Serialize};
use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, Size, TlsDeserialize,
    TlsSerialize, TlsSize,
};

/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     Sender sender;
///     opaque authenticated_data<V>;
///
///     // ... continued in [MlsContentBody] ...
/// } MLSContent;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub(crate) struct MlsContent {
    pub(super) group_id: GroupId,
    pub(super) epoch: GroupEpoch,
    pub(super) sender: Sender,
    pub(super) authenticated_data: VLBytes,

    pub(super) body: MlsContentBody,
}

impl From<MlsAuthContent> for MlsContent {
    fn from(mls_auth_content: MlsAuthContent) -> Self {
        mls_auth_content.tbs.content
    }
}

/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     // ... continued from [MlsContent] ...
///
///     ContentType content_type;
///     select (MLSContent.content_type) {
///         case application:
///           opaque application_data<V>;
///         case proposal:
///           Proposal proposal;
///         case commit:
///           Commit commit;
///     }
/// } MLSContent;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[repr(u8)]
pub(crate) enum MlsContentBody {
    #[tls_codec(discriminant = 1)]
    Application(TlsByteVecU32),
    #[tls_codec(discriminant = 2)]
    Proposal(Proposal),
    #[tls_codec(discriminant = 3)]
    Commit(Commit),
}

impl MlsContentBody {
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
            MlsContentBody::Application(a) => a.tls_serialized_len(),
            MlsContentBody::Proposal(p) => p.tls_serialized_len(),
            MlsContentBody::Commit(c) => c.tls_serialized_len(),
        }
    }

    /// Serializes the content without the `content_type` field.
    pub(crate) fn serialize_without_type<W: Write>(
        &self,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        match self {
            MlsContentBody::Application(a) => a.tls_serialize(writer),
            MlsContentBody::Proposal(p) => p.tls_serialize(writer),
            MlsContentBody::Commit(c) => c.tls_serialize(writer),
        }
    }

    pub(super) fn deserialize_without_type<R: Read>(
        bytes: &mut R,
        content_type: ContentType,
    ) -> Result<Self, tls_codec::Error> {
        Ok(match content_type {
            ContentType::Application => {
                MlsContentBody::Application(TlsByteVecU32::tls_deserialize(bytes)?)
            }
            ContentType::Proposal => MlsContentBody::Proposal(Proposal::tls_deserialize(bytes)?),
            ContentType::Commit => MlsContentBody::Commit(Commit::tls_deserialize(bytes)?),
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

impl From<&MlsContentBody> for ContentType {
    fn from(value: &MlsContentBody) -> Self {
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
/// // draft-ietf-mls-protocol-16
///
/// struct {
///   MLSContentTBS tbs;
///   MLSContentAuthData auth;
/// } MLSContentTBM;
/// ```
#[derive(Debug)]
pub(crate) struct MlsContentTbm<'a> {
    pub(crate) tbs_payload: &'a [u8],
    pub(crate) auth: &'a MlsContentAuthData,
}

impl<'a> MlsContentTbm<'a> {
    pub(crate) fn new(
        tbs_payload: &'a [u8],
        auth: &'a MlsContentAuthData,
    ) -> Result<Self, LibraryError> {
        Ok(Self { tbs_payload, auth })
    }

    pub(crate) fn into_bytes(self) -> Result<Vec<u8>, tls_codec::Error> {
        let mut buffer = self.tbs_payload.to_vec();
        self.auth.tls_serialize(&mut buffer)?;
        Ok(buffer)
    }
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct MlsContentTbs {
    pub(super) wire_format: WireFormat,
    pub(super) content: MlsContent,
    pub(super) serialized_context: Option<Vec<u8>>,
}

#[cfg(test)]
impl From<MlsPlaintext> for MlsContentTbs {
    fn from(v: MlsPlaintext) -> Self {
        MlsContentTbs {
            wire_format: WireFormat::MlsPlaintext,
            content: v.content,
            serialized_context: None,
        }
    }
}

impl Signable for MlsContentTbs {
    type SignedOutput = MlsAuthContent;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        "MLSPlaintextTBS"
    }
}

impl MlsContentTbs {
    /// Create an MlsContentTbs from an existing values.
    /// Note that if you would like to add a serialized context, you
    /// should subsequently call [`with_context`].
    pub(crate) fn new(
        wire_format: WireFormat,
        group_id: GroupId,
        epoch: impl Into<GroupEpoch>,
        sender: Sender,
        authenticated_data: VLBytes,
        body: MlsContentBody,
    ) -> Self {
        let content = MlsContent {
            group_id,
            epoch: epoch.into(),
            sender,
            authenticated_data,
            body,
        };
        MlsContentTbs {
            wire_format,
            content,
            serialized_context: None,
        }
    }

    /// Adds a serialized context to MlsContentTbs.
    /// This consumes the original struct and can be used as a builder function.
    pub(crate) fn with_context(mut self, serialized_context: Vec<u8>) -> Self {
        self.serialized_context = Some(serialized_context);
        self
    }

    /// Get the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.content.epoch
    }

    pub(super) fn serialize_plaintext_tbs<'a, W: Write>(
        wire_format: WireFormat,
        content: &MlsContent,
        serialized_context: impl Into<Option<&'a [u8]>>,
        buffer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        let mut written = wire_format.tls_serialize(buffer)?;
        written += content.tls_serialize(buffer)?;
        written += if let Some(serialized_context) = serialized_context.into() {
            // Only members and new members joining via commit should have a context.
            debug_assert!(matches!(
                content.sender,
                Sender::Member(_) | Sender::NewMemberCommit
            ));
            buffer.write(serialized_context)?
        } else {
            0
        };
        Ok(written)
    }
}

impl Size for MlsContentTbs {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.wire_format.tls_serialized_len()
            + self.content.tls_serialized_len()
            + if let Some(serialized_context) = &self.serialized_context {
                serialized_context.tls_serialized_len()
            } else {
                0
            }
    }
}

impl TlsSerializeTrait for MlsContentTbs {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::serialize_plaintext_tbs(
            self.wire_format,
            &self.content,
            self.serialized_context.as_deref(),
            writer,
        )
    }
}
