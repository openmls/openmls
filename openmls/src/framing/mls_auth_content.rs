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
    ciphersuite::{
        signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
        SignaturePublicKey,
    },
    error::LibraryError,
    group::errors::ValidationError,
};

#[cfg(doc)]
use super::{PrivateMessage, PublicMessage};

use super::{
    mls_content::{ContentType, FramedContentBody, FramedContentTbs},
    AddProposal, Commit, ConfirmationTag, Credential, FramingParameters, GroupContext, GroupEpoch,
    GroupId, Proposal, Sender, Signature, WireFormat,
};
use openmls_traits::signatures::Signer;
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
///
/// Note that [`AuthenticatedContent`] doesn't correspond exactly to the
/// AuthenticatedContent from the MLS specification, as the [`FramedContentTbs`]
/// contains additional information to ease processing.
///
/// TODO #1051: Serialization is only needed for KAT generation at this point.
/// If we want to serialize a spec-compliant AuthenticatedContent, we have to
/// manually ignore the extra fields in the TBS (i.e. context and later
/// ProtocolVersion).
#[derive(PartialEq, Debug, Clone, TlsSerialize, TlsSize)]
pub(crate) struct AuthenticatedContent {
    pub(super) tbs: FramedContentTbs,
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
        signer: &(impl Signer + ?Sized),
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
        signer: &(impl Signer + ?Sized),
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
        signer: &(impl Signer + ?Sized),
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
    /// The sender is [Sender::NewMemberProposal].
    // TODO #151/#106: We don't support preconfigured senders yet
    pub(crate) fn new_external_proposal(
        proposal: Proposal,
        group_id: GroupId,
        epoch: GroupEpoch,
        signer: &(impl Signer + ?Sized),
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
        signer: &(impl Signer + ?Sized),
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
        &self.tbs.content.body
    }

    /// Get the wire format.
    pub(crate) fn wire_format(&self) -> WireFormat {
        self.tbs.wire_format
    }

    pub(crate) fn authenticated_data(&self) -> &[u8] {
        self.tbs.content.authenticated_data.as_slice()
    }

    /// Get the group id as [`GroupId`].
    pub(crate) fn group_id(&self) -> &GroupId {
        &self.tbs.content.group_id
    }

    /// Get the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.tbs.epoch()
    }

    /// Get the [`Sender`].
    pub fn sender(&self) -> &Sender {
        &self.tbs.content.sender
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
        v.auth_content
    }
}

/// Wrapper struct around [`AuthenticatedContent`] to enforce signature verification
/// before content can be accessed.
#[derive(PartialEq, Debug, Clone, TlsSerialize, TlsSize)]
pub(crate) struct VerifiableAuthenticatedContent {
    auth_content: AuthenticatedContent,
}

impl VerifiableAuthenticatedContent {
    /// Create a new [`VerifiableAuthenticatedContent`] from a [`FramedContentTbs`] and
    /// a [`Signature`].
    pub(crate) fn new(tbs: FramedContentTbs, auth: FramedContentAuthData) -> Self {
        Self {
            auth_content: AuthenticatedContent { tbs, auth },
        }
    }

    /// Get the [`Sender`].
    pub fn sender(&self) -> &Sender {
        &self.auth_content.tbs.content.sender
    }

    /// Get the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.auth_content.tbs.epoch()
    }

    /// Returns the [`Credential`] and the [`SignaturePublicKey`] contained in
    /// the [`VerifiableAuthenticatedContent`] if the `sender_type` is either
    /// [`Sender::NewMemberCommit`] or [`Sender::NewMemberProposal`].
    ///
    /// Returns a [`ValidationError`] if
    /// * the sender type is not one of the above,
    /// * the content type doesn't match the sender type, or
    /// * if it's a NewMemberCommit and the Commit doesn't contain a `path`.
    pub(crate) fn new_member_credential(
        &self,
    ) -> Result<(Credential, SignaturePublicKey), ValidationError> {
        match self.auth_content.tbs.content.sender {
            Sender::NewMemberCommit => {
                // only external commits can have a sender type `NewMemberCommit`
                match &self.auth_content.tbs.content.body {
                    FramedContentBody::Commit(Commit { path, .. }) => path
                        .as_ref()
                        .map(|p| {
                            let credential = p.leaf_node().credential().clone();
                            let pk = p.leaf_node().signature_key().clone();
                            (credential, pk)
                        })
                        .ok_or(ValidationError::NoPath),
                    _ => Err(ValidationError::NotACommit),
                }
            }
            Sender::NewMemberProposal => {
                // only External Add proposals can have a sender type `NewMemberProposal`
                match &self.auth_content.tbs.content.body {
                    FramedContentBody::Proposal(Proposal::Add(AddProposal { key_package })) => {
                        let credential = key_package.leaf_node().credential().clone();
                        let pk = key_package.leaf_node().signature_key().clone();
                        Ok((credential, pk))
                    }
                    _ => Err(ValidationError::NotAnExternalAddProposal),
                }
            }
            _ => Err(ValidationError::UnknownMember),
        }
    }

    /// Get the wire format.
    pub(crate) fn wire_format(&self) -> WireFormat {
        self.auth_content.tbs.wire_format
    }

    /// Get the confirmation tag.
    pub(crate) fn confirmation_tag(&self) -> Option<&ConfirmationTag> {
        self.auth_content.auth.confirmation_tag.as_ref()
    }

    /// Get the content type
    pub(crate) fn content_type(&self) -> ContentType {
        self.auth_content.tbs.content.body.content_type()
    }
}

impl Verifiable for VerifiableAuthenticatedContent {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.auth_content.tbs.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.auth_content.auth.signature
    }

    fn label(&self) -> &str {
        "FramedContentTBS"
    }
}

impl VerifiedStruct<VerifiableAuthenticatedContent> for AuthenticatedContent {
    fn from_verifiable(v: VerifiableAuthenticatedContent, _seal: Self::SealingType) -> Self {
        v.auth_content
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
        Self { tbs, auth }
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
