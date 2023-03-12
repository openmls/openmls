//! This module contains the [`FramedContentIn`] struct and associated helper structs
//! such as [`FramedContentTbsIn`], as well as their implementations.

use crate::{
    ciphersuite::signable::Signable,
    error::LibraryError,
    group::{GroupEpoch, GroupId},
    messages::{proposals_in::ProposalIn, CommitIn},
    versions::ProtocolVersion,
};

use std::io::{Read, Write};

use super::{
    mls_auth_content_in::{AuthenticatedContentIn, FramedContentAuthDataIn},
    mls_content::FramedContentBody,
    ContentType, Sender, WireFormat,
};

use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, Size, TlsDeserialize,
    TlsSerialize, TlsSize, VLBytes,
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
pub(crate) struct FramedContentIn {
    pub(super) group_id: GroupId,
    pub(super) epoch: GroupEpoch,
    pub(super) sender: Sender,
    pub(super) authenticated_data: VLBytes,

    pub(super) body: FramedContentBodyIn,
}

impl From<AuthenticatedContentIn> for FramedContentIn {
    fn from(mls_auth_content: AuthenticatedContentIn) -> Self {
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
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[repr(u8)]
pub(crate) enum FramedContentBodyIn {
    #[tls_codec(discriminant = 1)]
    Application(VLBytes),
    #[tls_codec(discriminant = 2)]
    Proposal(ProposalIn),
    #[tls_codec(discriminant = 3)]
    Commit(CommitIn),
}

impl FramedContentBodyIn {
    pub(crate) fn content_type(&self) -> ContentType {
        match self {
            Self::Application(_) => ContentType::Application,
            Self::Proposal(_) => ContentType::Proposal,
            Self::Commit(_) => ContentType::Commit,
        }
    }

    pub(super) fn deserialize_without_type<R: Read>(
        bytes: &mut R,
        content_type: ContentType,
    ) -> Result<Self, tls_codec::Error> {
        Ok(match content_type {
            ContentType::Application => {
                FramedContentBodyIn::Application(VLBytes::tls_deserialize(bytes)?)
            }
            ContentType::Proposal => {
                FramedContentBodyIn::Proposal(ProposalIn::tls_deserialize(bytes)?)
            }
            ContentType::Commit => FramedContentBodyIn::Commit(CommitIn::tls_deserialize(bytes)?),
        })
    }
}

impl From<&FramedContentBodyIn> for ContentType {
    fn from(value: &FramedContentBodyIn) -> Self {
        value.content_type()
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
pub(crate) struct AuthenticatedContentTbmIn<'a> {
    pub(crate) tbs_payload: &'a [u8],
    pub(crate) auth: &'a FramedContentAuthDataIn,
}

impl<'a> AuthenticatedContentTbmIn<'a> {
    pub(crate) fn new(
        tbs_payload: &'a [u8],
        auth: &'a FramedContentAuthDataIn,
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
pub(crate) struct FramedContentTbsIn {
    pub(super) version: ProtocolVersion,
    pub(super) wire_format: WireFormat,
    pub(super) content: FramedContentIn,
    pub(super) serialized_context: Option<Vec<u8>>,
}

impl Signable for FramedContentTbsIn {
    type SignedOutput = AuthenticatedContentIn;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        "FramedContentTBS"
    }
}

impl FramedContentTbsIn {
    /// Create an FramedContentTbsIn from an existing values.
    /// Note that if you would like to add a serialized context, you
    /// should subsequently call [`with_context`].
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn new(
        wire_format: WireFormat,
        group_id: GroupId,
        epoch: impl Into<GroupEpoch>,
        sender: Sender,
        authenticated_data: VLBytes,
        body: FramedContentBodyIn,
    ) -> Self {
        let content = FramedContentIn {
            group_id,
            epoch: epoch.into(),
            sender,
            authenticated_data,
            body,
        };
        FramedContentTbsIn {
            version: ProtocolVersion::Mls10,
            wire_format,
            content,
            serialized_context: None,
        }
    }

    /// Helper function to make serialization of [`FramedContentTbsIn`] accessible
    /// to both the [`TlsSerialize`] implementation and the
    /// [`FramedContentTbsIn::new_and_serialize_detached()`] function.
    fn new_and_serialize<'context, W: Write>(
        writer: &mut W,
        version: ProtocolVersion,
        wire_format: WireFormat,
        content: &FramedContentIn,
        serialized_context: impl Into<Option<&'context [u8]>>,
    ) -> Result<usize, tls_codec::Error> {
        let mut written = version.tls_serialize(writer)?;
        written += wire_format.tls_serialize(writer)?;
        written += content.tls_serialize(writer)?;
        // Context is included if and only if the sender type is Member or
        // NewMemberCommit.
        written += match serialized_context.into() {
            Some(context)
                if matches!(content.sender, Sender::Member(_) | Sender::NewMemberCommit) =>
            {
                writer.write(context)?
            }
            _ => 0,
        };

        Ok(written)
    }

    /// Given references to the individual contents of a [`FramedContentTbsIn`],
    /// return its serialization. This function is useful to avoid cloning the
    /// individual contents to create a [`FramedContentTbsIn`] instance just to
    /// serialize it. Note that the context is only serialized if the `sender`
    /// in `content` is [`Sender::Member`] or [`Sender::NewMemberCommit`].
    ///
    /// Returns an [`tls_codec::Error`] if the serialization fails.
    pub(super) fn new_and_serialize_detached<'context>(
        version: ProtocolVersion,
        wire_format: WireFormat,
        content: &FramedContentIn,
        serialized_context: impl Into<Option<&'context [u8]>>,
    ) -> Result<Vec<u8>, tls_codec::Error> {
        let mut writer = Vec::new();
        Self::new_and_serialize(
            &mut writer,
            version,
            wire_format,
            content,
            serialized_context,
        )?;

        Ok(writer)
    }

    /// Adds a serialized context to FramedContentTbs.
    /// This consumes the original struct and can be used as a builder function.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn with_context(mut self, serialized_context: Vec<u8>) -> Self {
        self.serialized_context = Some(serialized_context);
        self
    }
}

impl Size for FramedContentTbsIn {
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

impl TlsSerializeTrait for FramedContentTbsIn {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::new_and_serialize(
            writer,
            self.version,
            self.wire_format,
            &self.content,
            self.serialized_context.as_deref(),
        )
    }
}

// The following two `From` implementations break abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".

// TODO: re-enable #[cfg(any(feature = "test-utils", test))]
impl From<FramedContentBodyIn> for FramedContentBody {
    fn from(body: FramedContentBodyIn) -> Self {
        match body {
            FramedContentBodyIn::Application(application) => {
                FramedContentBody::Application(application)
            }
            FramedContentBodyIn::Proposal(proposal) => FramedContentBody::Proposal(proposal.into()),
            FramedContentBodyIn::Commit(commit) => FramedContentBody::Commit(commit.into()),
        }
    }
}

// TODO #1186: The following is temporary until the refactoring of incoming
// messages is done.

impl From<FramedContentIn> for crate::framing::mls_content::FramedContent {
    fn from(value: FramedContentIn) -> Self {
        Self {
            group_id: value.group_id,
            epoch: value.epoch,
            sender: value.sender,
            authenticated_data: value.authenticated_data,
            body: value.body.into(),
        }
    }
}

impl From<FramedContentBody> for FramedContentBodyIn {
    fn from(body: FramedContentBody) -> Self {
        match body {
            FramedContentBody::Application(application) => {
                FramedContentBodyIn::Application(application)
            }
            FramedContentBody::Proposal(proposal) => FramedContentBodyIn::Proposal(proposal.into()),
            FramedContentBody::Commit(commit) => FramedContentBodyIn::Commit(commit.into()),
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<crate::framing::mls_content::FramedContent> for FramedContentIn {
    fn from(value: crate::framing::mls_content::FramedContent) -> Self {
        Self {
            group_id: value.group_id,
            epoch: value.epoch,
            sender: value.sender,
            authenticated_data: value.authenticated_data,
            body: value.body.into(),
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<FramedContentTbsIn> for crate::framing::mls_content::FramedContentTbs {
    fn from(value: FramedContentTbsIn) -> Self {
        Self {
            version: value.version,
            wire_format: value.wire_format,
            content: value.content.into(),
            serialized_context: value.serialized_context,
        }
    }
}
