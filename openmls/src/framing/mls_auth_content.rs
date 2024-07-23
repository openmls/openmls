//! # MLS content authentication
//!
//! This module contains structs and implementation that pertain to content
//! authentication in MLS.

use std::io::{Read, Write};

use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, Size, TlsSerialize, TlsSize,
};

use super::{
    mls_content::{FramedContent, FramedContentBody, FramedContentTbs},
    Commit, ConfirmationTag, ContentType, FramingParameters, GroupContext, GroupEpoch, GroupId,
    Proposal, Sender, Signature, WireFormat,
};
use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::signable::{Signable, SignedStruct},
    error::LibraryError,
    extensions::SenderExtensionIndex,
};

/// 7.1 Content Authentication
///
/// ```c
/// // draft-ietf-mls-protocol-17
///
/// struct {
///    /* SignWithLabel(., "FramedContentTBS", FramedContentTBS) */
///    opaque signature<V>;
///    select (FramedContent.content_type) {
///        case commit:
///            /*
///              MAC(confirmation_key,
///                  GroupContext.confirmed_transcript_hash)
///            */
///            MAC confirmation_tag;
///        case application:
///        case proposal:
///            struct{};
///    };
///} FramedContentAuthData;
/// ```
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FramedContentAuthData {
    pub(super) signature: Signature,
    pub(super) confirmation_tag: Option<ConfirmationTag>,
}

impl FramedContentAuthData {
    pub(crate) fn deserialize<R: Read>(
        bytes: &mut R,
        content_type: ContentType,
    ) -> Result<Self, tls_codec::Error> {
        let signature = Signature::tls_deserialize(bytes)?;
        let confirmation_tag = if matches!(content_type, ContentType::Commit) {
            Some(ConfirmationTag::tls_deserialize(bytes)?)
        } else {
            None
        };
        Ok(Self {
            signature,
            confirmation_tag,
        })
    }
}

/// 6 Message Framing
///
/// ```c
/// // draft-ietf-mls-protocol-17
///
/// struct {
///     WireFormat wire_format;
///     FramedContent content;
///     FramedContentAuthData auth;
/// } AuthenticatedContent;
/// ```
#[derive(PartialEq, Debug, Clone, TlsSerialize, TlsSize)]
pub(crate) struct AuthenticatedContent {
    pub(super) wire_format: WireFormat,
    pub(super) content: FramedContent,
    pub(super) auth: FramedContentAuthData,
}

impl AuthenticatedContent {
    /// Convenience function for creating a [`VerifiableAuthenticatedContent`].
    #[inline]
    fn new_and_sign(
        framing_parameters: FramingParameters,
        sender: Sender,
        body: FramedContentBody,
        context: &GroupContext,
        signer: &impl Signer,
    ) -> Result<Self, LibraryError> {
        let mut content_tbs = FramedContentTbs::new(
            framing_parameters.wire_format(),
            context.group_id().clone(),
            context.epoch(),
            sender.clone(),
            framing_parameters.aad().into(),
            body,
        );

        if matches!(sender, Sender::NewMemberCommit | Sender::Member(_)) {
            let serialized_context = context
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?;
            content_tbs = content_tbs.with_context(serialized_context);
        }

        content_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))
    }

    /// This constructor builds an `AuthenticatedContent` containing an application
    /// message. The sender type is always `SenderType::Member`.
    pub(crate) fn new_application(
        sender_leaf_index: LeafNodeIndex,
        authenticated_data: &[u8],
        application_message: &[u8],
        context: &GroupContext,
        signer: &impl Signer,
    ) -> Result<Self, LibraryError> {
        let framing_parameters =
            FramingParameters::new(authenticated_data, WireFormat::PrivateMessage);
        Self::new_and_sign(
            framing_parameters,
            Sender::Member(sender_leaf_index),
            FramedContentBody::Application(application_message.into()),
            context,
            signer,
        )
    }

    /// This constructor builds an `PublicMessage` containing a Proposal.
    /// The sender type is always `SenderType::Member`.
    pub(crate) fn member_proposal(
        framing_parameters: FramingParameters,
        sender_leaf_index: LeafNodeIndex,
        proposal: Proposal,
        context: &GroupContext,
        signer: &impl Signer,
    ) -> Result<Self, LibraryError> {
        Self::new_and_sign(
            framing_parameters,
            Sender::Member(sender_leaf_index),
            FramedContentBody::Proposal(proposal),
            context,
            signer,
        )
    }

    /// This constructor builds an `PublicMessage` containing an External Proposal.
    pub(crate) fn new_join_proposal(
        proposal: Proposal,
        group_id: GroupId,
        epoch: GroupEpoch,
        signer: &impl Signer,
    ) -> Result<Self, LibraryError> {
        let body = FramedContentBody::Proposal(proposal);

        let content_tbs = FramedContentTbs::new(
            WireFormat::PublicMessage,
            group_id,
            epoch,
            Sender::NewMemberProposal,
            vec![].into(),
            body,
        );

        content_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))
    }

    /// This constructor builds an `PublicMessage` containing an External Proposal.
    pub(crate) fn new_external_proposal(
        proposal: Proposal,
        group_id: GroupId,
        epoch: GroupEpoch,
        signer: &impl Signer,
        sender_index: SenderExtensionIndex,
    ) -> Result<Self, LibraryError> {
        let body = FramedContentBody::Proposal(proposal);

        let content_tbs = FramedContentTbs::new(
            WireFormat::PublicMessage,
            group_id,
            epoch,
            Sender::External(sender_index),
            vec![].into(),
            body,
        );

        content_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))
    }

    /// This constructor builds an `PublicMessage` containing a Commit. If the
    /// given `CommitType` is `Member`, the `SenderType` is `Member` as well. If
    /// it's an `External` commit, the `SenderType` is `NewMemberCommit`. If it is an
    /// `External` commit, the context is not signed along with the rest of the
    /// commit.
    pub(crate) fn commit(
        framing_parameters: FramingParameters,
        sender: Sender,
        commit: Commit,
        context: &GroupContext,
        signer: &impl Signer,
    ) -> Result<Self, LibraryError> {
        Self::new_and_sign(
            framing_parameters,
            sender,
            FramedContentBody::Commit(commit),
            context,
            signer,
        )
    }

    /// Get the signature.
    pub(crate) fn signature(&self) -> &Signature {
        &self.auth.signature
    }

    /// Get the signature.
    pub(crate) fn confirmation_tag(&self) -> Option<&ConfirmationTag> {
        self.auth.confirmation_tag.as_ref()
    }

    /// Set the confirmation tag.
    pub(crate) fn set_confirmation_tag(&mut self, tag: ConfirmationTag) {
        self.auth.confirmation_tag = Some(tag)
    }

    /// Get the content body of the message.
    pub(crate) fn content(&self) -> &FramedContentBody {
        &self.content.body
    }

    /// Get the wire format.
    pub(crate) fn wire_format(&self) -> WireFormat {
        self.wire_format
    }

    pub(crate) fn authenticated_data(&self) -> &[u8] {
        self.content.authenticated_data.as_slice()
    }

    /// Get the group id as [`GroupId`].
    pub(crate) fn group_id(&self) -> &GroupId {
        &self.content.group_id
    }

    /// Get the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.content.epoch
    }

    /// Get the [`Sender`].
    pub fn sender(&self) -> &Sender {
        &self.content.sender
    }

    /// Decompose into body and sender.
    pub(crate) fn into_body_and_sender(self) -> (FramedContentBody, Sender) {
        (self.content.body, self.content.sender)
    }
}

#[cfg(test)]
impl AuthenticatedContent {
    pub(crate) fn new(
        wire_format: WireFormat,
        content: FramedContent,
        auth: FramedContentAuthData,
    ) -> Self {
        Self {
            wire_format,
            content,
            auth,
        }
    }

    pub fn test_signature(&self) -> &Signature {
        &self.auth.signature
    }
}

impl SignedStruct<FramedContentTbs> for AuthenticatedContent {
    fn from_payload(tbs: FramedContentTbs, signature: Signature) -> Self {
        let auth = FramedContentAuthData {
            signature,
            // Tags must always be added after the signature
            confirmation_tag: None,
        };
        Self {
            wire_format: tbs.wire_format,
            content: tbs.content,
            auth,
        }
    }
}

impl Size for FramedContentAuthData {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.signature.tls_serialized_len()
            + if let Some(confirmation_tag) = &self.confirmation_tag {
                confirmation_tag.tls_serialized_len()
            } else {
                0
            }
    }
}

impl TlsSerializeTrait for FramedContentAuthData {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.signature.tls_serialize(writer)?;
        written += if let Some(confirmation_tag) = &self.confirmation_tag {
            confirmation_tag.tls_serialize(writer)?
        } else {
            0
        };
        Ok(written)
    }
}
