//! This module contains the [`FramedContent`] struct and associated helper structs
//! such as [`FramedContentTbs`], as well as their implementations.

use crate::{
    ciphersuite::signable::Signable,
    error::LibraryError,
    group::{GroupEpoch, GroupId},
    messages::{proposals::Proposal, Commit},
    versions::ProtocolVersion,
};

use std::io::Write;

use super::{
    mls_auth_content::{AuthenticatedContent, FramedContentAuthData},
    ContentType, Sender, WireFormat,
};

use serde::{Deserialize, Serialize};
use tls_codec::{Serialize as TlsSerializeTrait, Size, TlsSerialize, TlsSize, VLBytes};

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
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub(crate) struct FramedContent {
    pub(super) group_id: GroupId,
    pub(super) epoch: GroupEpoch,
    pub(super) sender: Sender,
    pub(super) authenticated_data: VLBytes,

    pub(super) body: FramedContentBody,
}

impl From<AuthenticatedContent> for FramedContent {
    fn from(mls_auth_content: AuthenticatedContent) -> Self {
        mls_auth_content.content
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
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
pub(crate) enum FramedContentBody {
    #[tls_codec(discriminant = 1)]
    Application(VLBytes),
    #[tls_codec(discriminant = 2)]
    Proposal(Proposal),
    #[tls_codec(discriminant = 3)]
    Commit(Commit),
}

impl FramedContentBody {
    /// Returns the [`ContentType`].
    pub(crate) fn content_type(&self) -> ContentType {
        match self {
            FramedContentBody::Application(_) => ContentType::Application,
            FramedContentBody::Proposal(_) => ContentType::Proposal,
            FramedContentBody::Commit(_) => ContentType::Commit,
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
}

pub(crate) fn framed_content_tbs_serialized_detached<'context>(
    version: ProtocolVersion,
    wire_format: WireFormat,
    content: &impl TlsSerializeTrait,
    sender: &Sender,
    serialized_context: impl Into<Option<&'context [u8]>>,
) -> Result<Vec<u8>, tls_codec::Error> {
    let writer = &mut Vec::new();

    framed_content_tbs_serialized(
        writer,
        version,
        wire_format,
        content,
        sender,
        serialized_context,
    )?;

    Ok(writer.to_vec())
}

pub(crate) fn framed_content_tbs_serialized<'context, W: Write>(
    writer: &mut W,
    version: ProtocolVersion,
    wire_format: WireFormat,
    content: &impl TlsSerializeTrait,
    sender: &Sender,
    serialized_context: impl Into<Option<&'context [u8]>>,
) -> Result<usize, tls_codec::Error> {
    let mut written = version.tls_serialize(writer)?;
    written += wire_format.tls_serialize(writer)?;
    written += content.tls_serialize(writer)?;
    // Context is included if and only if the sender type is Member or
    // NewMemberCommit.
    written += match serialized_context.into() {
        Some(context) if matches!(sender, Sender::Member(_) | Sender::NewMemberCommit) => {
            writer.write_all(context)?;
            context.len()
        }
        _ => 0,
    };

    Ok(written)
}

impl Size for FramedContentTbs {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.version.tls_serialized_len()
            + self.wire_format.tls_serialized_len()
            + self.content.tls_serialized_len()
            + match &self.serialized_context {
                Some(context)
                    if matches!(
                        self.content.sender,
                        Sender::Member(_) | Sender::NewMemberCommit
                    ) =>
                {
                    context.len()
                }
                _ => 0,
            }
    }
}

impl TlsSerializeTrait for FramedContentTbs {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        framed_content_tbs_serialized(
            writer,
            self.version,
            self.wire_format,
            &self.content,
            &self.content.sender,
            self.serialized_context.as_deref(),
        )
    }
}
