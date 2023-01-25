//! # MLS content authentication
//!
//! This module contains structs and implementation that pertain to content
//! authentication in MLS. Besides structs that directly represent structs in
//! the MLS specification, this module also contains
//! [`VerifiableAuthenticatedContent`], a wrapper struct which ensures that the
//! signatures are verified before the content of an MLS [`PrivateMessage`] or
//! [`PublicMessage`] can be accessed by processing functions of OpenMLS.
use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
    error::LibraryError,
    group::errors::ValidationError,
    versions::ProtocolVersion,
};

#[cfg(doc)]
use super::{PrivateMessage, PublicMessage};

use super::{
    mls_content::{ContentType, FramedContent, FramedContentBody, FramedContentTbs},
    AddProposal, Commit, ConfirmationTag, Credential, CredentialBundle, FramingParameters,
    GroupContext, GroupEpoch, GroupId, Proposal, Sender, Signature, WireFormat,
};
use openmls_traits::OpenMlsCryptoProvider;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, Size, TlsSerialize, TlsSize,
};

/// Private module to ensure protection of [`AuthenticatedContent`].
mod private_mod {
    #[derive(Default)]
    pub(crate) struct Seal;
}

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
    pub(super) fn deserialize<R: Read>(
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
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        backend: &impl OpenMlsCryptoProvider,
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
            .sign(backend, credential_bundle.signature_private_key())
            .map_err(|_| LibraryError::custom("Signing failed"))
    }

    /// This constructor builds an `AuthenticatedContent` containing an application
    /// message. The sender type is always `SenderType::Member`.
    pub(crate) fn new_application(
        sender_leaf_index: LeafNodeIndex,
        authenticated_data: &[u8],
        application_message: &[u8],
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, LibraryError> {
        let framing_parameters =
            FramingParameters::new(authenticated_data, WireFormat::PrivateMessage);
        Self::new_and_sign(
            framing_parameters,
            Sender::Member(sender_leaf_index),
            FramedContentBody::Application(application_message.into()),
            credential_bundle,
            context,
            backend,
        )
    }

    /// This constructor builds an `PublicMessage` containing a Proposal.
    /// The sender type is always `SenderType::Member`.
    pub(crate) fn member_proposal(
        framing_parameters: FramingParameters,
        sender_leaf_index: LeafNodeIndex,
        proposal: Proposal,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, LibraryError> {
        Self::new_and_sign(
            framing_parameters,
            Sender::Member(sender_leaf_index),
            FramedContentBody::Proposal(proposal),
            credential_bundle,
            context,
            backend,
        )
    }

    /// This constructor builds an `PublicMessage` containing an External Proposal.
    /// The sender is [Sender::NewMemberProposal].
    // TODO #151/#106: We don't support preconfigured senders yet
    pub(crate) fn new_external_proposal(
        proposal: Proposal,
        credential_bundle: &CredentialBundle,
        group_id: GroupId,
        epoch: GroupEpoch,
        backend: &impl OpenMlsCryptoProvider,
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
            .sign(backend, credential_bundle.signature_private_key())
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
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, LibraryError> {
        Self::new_and_sign(
            framing_parameters,
            sender,
            FramedContentBody::Commit(commit),
            credential_bundle,
            context,
            backend,
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

    #[cfg(test)]
    pub fn test_signature(&self) -> &Signature {
        &self.auth.signature
    }

    #[cfg(test)]
    pub(super) fn unset_confirmation_tag(&mut self) {
        self.auth.confirmation_tag = None;
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<VerifiableAuthenticatedContent> for AuthenticatedContent {
    fn from(v: VerifiableAuthenticatedContent) -> Self {
        AuthenticatedContent {
            wire_format: v.tbs.wire_format,
            content: v.tbs.content,
            auth: v.auth,
        }
    }
}

/// Wrapper struct around [`AuthenticatedContent`] to enforce signature verification
/// before content can be accessed.
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct VerifiableAuthenticatedContent {
    tbs: FramedContentTbs,
    auth: FramedContentAuthData,
}

impl VerifiableAuthenticatedContent {
    /// Create a new [`VerifiableAuthenticatedContent`] from a [`FramedContentTbs`] and
    /// a [`Signature`].
    pub(crate) fn new(
        wire_format: WireFormat,
        content: FramedContent,
        serialized_context: impl Into<Option<Vec<u8>>>,
        auth: FramedContentAuthData,
    ) -> Self {
        let tbs = FramedContentTbs {
            version: ProtocolVersion::default(),
            wire_format,
            content,
            serialized_context: serialized_context.into(),
        };
        Self { tbs, auth }
    }

    /// Get the [`Sender`].
    pub fn sender(&self) -> &Sender {
        &self.tbs.content.sender
    }

    /// Get the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.tbs.content.epoch
    }

    /// Returns the [`Credential`] contained in the [`VerifiableAuthenticatedContent`]
    /// if the `sender_type` is either [`Sender::NewMemberCommit`] or
    /// [`Sender::NewMemberProposal`].
    ///
    /// Returns a [`ValidationError`] if
    /// * the sender type is not one of the above,
    /// * the content type doesn't match the sender type, or
    /// * if it's a NewMemberCommit and the Commit doesn't contain a `path`.
    pub(crate) fn new_member_credential(&self) -> Result<Credential, ValidationError> {
        match self.tbs.content.sender {
            Sender::NewMemberCommit => {
                // only external commits can have a sender type `NewMemberCommit`
                match &self.tbs.content.body {
                    FramedContentBody::Commit(Commit { path, .. }) => path
                        .as_ref()
                        .map(|p| p.leaf_node().credential().clone())
                        .ok_or(ValidationError::NoPath),
                    _ => Err(ValidationError::NotACommit),
                }
            }
            Sender::NewMemberProposal => {
                // only External Add proposals can have a sender type `NewMemberProposal`
                match &self.tbs.content.body {
                    FramedContentBody::Proposal(Proposal::Add(AddProposal { key_package })) => {
                        Ok(key_package.leaf_node().credential().clone())
                    }
                    _ => Err(ValidationError::NotAnExternalAddProposal),
                }
            }
            _ => Err(ValidationError::UnknownMember),
        }
    }

    /// Get the wire format.
    pub(crate) fn wire_format(&self) -> WireFormat {
        self.tbs.wire_format
    }

    /// Get the confirmation tag.
    pub(crate) fn confirmation_tag(&self) -> Option<&ConfirmationTag> {
        self.auth.confirmation_tag.as_ref()
    }

    /// Get the content type
    pub(crate) fn content_type(&self) -> ContentType {
        self.tbs.content.body.content_type()
    }
}

impl Verifiable for VerifiableAuthenticatedContent {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tbs.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.auth.signature
    }

    fn label(&self) -> &str {
        "FramedContentTBS"
    }
}

impl VerifiedStruct<VerifiableAuthenticatedContent> for AuthenticatedContent {
    fn from_verifiable(v: VerifiableAuthenticatedContent, _seal: Self::SealingType) -> Self {
        AuthenticatedContent {
            wire_format: v.tbs.wire_format,
            content: v.tbs.content,
            auth: v.auth,
        }
    }

    type SealingType = private_mod::Seal;
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
