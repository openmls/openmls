//! This module contains the [`FramedContentIn`] struct and associated helper structs
//! such as [`FramedContentTbsIn`], as well as their implementations.

use crate::{
    ciphersuite::signable::Signable,
    error::LibraryError,
    framing::SenderContext,
    group::{errors::ValidationError, GroupEpoch, GroupId},
    messages::{proposals_in::ProposalIn, CommitIn},
    versions::ProtocolVersion,
};

use std::io::{Read, Write};

use super::{
    mls_auth_content_in::AuthenticatedContentIn,
    mls_content::{framed_content_tbs_serialized, FramedContent, FramedContentBody},
    ContentType, Sender, WireFormat,
};

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, Size, TlsDeserialize,
    TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes,
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
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub(crate) struct FramedContentIn {
    pub(super) group_id: GroupId,
    pub(super) epoch: GroupEpoch,
    pub(super) sender: Sender,
    pub(super) authenticated_data: VLBytes,
    pub(super) body: FramedContentBodyIn,
}

impl FramedContentIn {
    /// Returns a [`FramedContent`] after successful validation.
    pub(crate) fn validate(
        self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        sender_context: Option<SenderContext>,
        protocol_version: ProtocolVersion,
    ) -> Result<FramedContent, ValidationError> {
        Ok(FramedContent {
            group_id: self.group_id,
            epoch: self.epoch,
            sender: self.sender,
            authenticated_data: self.authenticated_data,
            body: self
                .body
                .validate(ciphersuite, crypto, sender_context, protocol_version)?,
        })
    }
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
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
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
    /// Returns the [`ContentType`].
    pub(crate) fn content_type(&self) -> ContentType {
        match self {
            FramedContentBodyIn::Application(_) => ContentType::Application,
            FramedContentBodyIn::Proposal(_) => ContentType::Proposal,
            FramedContentBodyIn::Commit(_) => ContentType::Commit,
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

    /// Returns a [`FramedContentBody`] after successful validation.
    pub(crate) fn validate(
        self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        sender_context: Option<SenderContext>,
        protocol_version: ProtocolVersion,
    ) -> Result<FramedContentBody, ValidationError> {
        Ok(match self {
            FramedContentBodyIn::Application(bytes) => FramedContentBody::Application(bytes),
            FramedContentBodyIn::Proposal(proposal_in) => FramedContentBody::Proposal(
                proposal_in.validate(crypto, ciphersuite, sender_context, protocol_version)?,
            ),
            FramedContentBodyIn::Commit(commit_in) => {
                let sender_context = sender_context
                    .ok_or(LibraryError::custom("Forgot the commit sender context"))?;
                FramedContentBody::Commit(commit_in.validate(
                    ciphersuite,
                    crypto,
                    sender_context,
                    protocol_version,
                )?)
            }
        })
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

// The following `From` implementation( breaks abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
#[cfg(any(feature = "test-utils", test))]
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

// The following `From` implementation( breaks abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
#[cfg(any(feature = "test-utils", test))]
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

// The following `From` implementation( breaks abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
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
