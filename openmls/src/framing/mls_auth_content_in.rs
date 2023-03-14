//! # MLS content authentication
//!
//! This module contains structs and implementation that pertain to content
//! authentication in MLS. Besides structs that directly represent structs in
//! the MLS specification, this module also contains
//! [`VerifiableAuthenticatedContentIn`], a wrapper struct which ensures that the
//! signatures are verified before the content of an MLS [`PrivateMessageIn`] or
//! [`PublicMessageIn`] can be accessed by processing functions of OpenMLS.

use std::io::{Read, Write};

#[cfg(any(feature = "test-utils", test))]
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, Size};

use super::{mls_auth_content::*, mls_content_in::*, *};
#[cfg(doc)]
use super::{PrivateMessageIn, PublicMessageIn};
#[cfg(any(feature = "test-utils", test))]
use crate::{binary_tree::LeafNodeIndex, ciphersuite::signable::Signable, error::LibraryError};
use crate::{
    ciphersuite::signable::{SignedStruct, Verifiable, VerifiedStruct},
    credentials::CredentialWithKey,
    group::errors::ValidationError,
    messages::proposals_in::ProposalIn,
    versions::ProtocolVersion,
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
pub(crate) struct FramedContentAuthDataIn {
    pub(super) signature: Signature,
    pub(super) confirmation_tag: Option<ConfirmationTag>,
}

impl FramedContentAuthDataIn {
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
#[derive(PartialEq, Debug, Clone, TlsSize)]
pub(crate) struct AuthenticatedContentIn {
    pub(super) wire_format: WireFormat,
    pub(super) content: FramedContentIn,
    pub(super) auth: FramedContentAuthDataIn,
}

#[cfg(any(feature = "test-utils", test))]
impl AuthenticatedContentIn {
    /// Convenience function for creating a [`VerifiableAuthenticatedContent`].
    #[cfg(any(feature = "test-utils", test))]
    fn new_and_sign(
        framing_parameters: FramingParameters,
        sender: Sender,
        body: FramedContentBodyIn,
        context: &GroupContext,
        signer: &impl Signer,
    ) -> Result<Self, LibraryError> {
        let mut content_tbs = FramedContentTbsIn::new(
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

    /// This constructor builds an `PublicMessage` containing a Proposal.
    /// The sender type is always `SenderType::Member`.
    #[cfg(any(feature = "test-utils", test))]
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
            FramedContentBodyIn::Proposal(proposal.into()),
            context,
            signer,
        )
    }

    /// Get the content body of the message.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn content(&self) -> &FramedContentBodyIn {
        &self.content.body
    }
}

/// Note: we can't `derive(tls_codec::Deserialize)` because [`FramedContentAuthData`] cannot
///       implement the usual `tls_codec::Deserialize` as it requires the content type as parameter.
impl tls_codec::Deserialize for AuthenticatedContentIn {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let wire_format = WireFormat::tls_deserialize(bytes)?;
        let content = FramedContentIn::tls_deserialize(bytes)?;
        // Here, content type is requires as parameter for deserialization.
        let auth = FramedContentAuthDataIn::deserialize(bytes, content.body.content_type())?;

        Ok(Self {
            wire_format,
            content,
            auth,
        })
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<VerifiableAuthenticatedContentIn> for AuthenticatedContentIn {
    fn from(v: VerifiableAuthenticatedContentIn) -> Self {
        AuthenticatedContentIn {
            wire_format: v.tbs.wire_format,
            content: v.tbs.content,
            auth: v.auth,
        }
    }
}

/// Wrapper struct around [`AuthenticatedContent`] to enforce signature verification
/// before content can be accessed.
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct VerifiableAuthenticatedContentIn {
    tbs: FramedContentTbsIn,
    auth: FramedContentAuthDataIn,
}

impl VerifiableAuthenticatedContentIn {
    /// Create a new [`VerifiableAuthenticatedContentIn`] from a [`FramedContentTbsIn`] and
    /// a [`Signature`].
    pub(crate) fn new(
        wire_format: WireFormat,
        content: FramedContentIn,
        serialized_context: impl Into<Option<Vec<u8>>>,
        auth: FramedContentAuthDataIn,
    ) -> Self {
        let tbs = FramedContentTbsIn {
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

    /// Returns the [`Credential`] and the [`SignaturePublicKey`] contained in
    /// the [`VerifiableAuthenticatedContent`] if the `sender_type` is either
    /// [`Sender::NewMemberCommit`] or [`Sender::NewMemberProposal`].
    ///
    /// Returns a [`ValidationError`] if
    /// * the sender type is not one of the above,
    /// * the content type doesn't match the sender type, or
    /// * if it's a NewMemberCommit and the Commit doesn't contain a `path`.
    pub(crate) fn new_member_credential(&self) -> Result<CredentialWithKey, ValidationError> {
        match self.tbs.content.sender {
            Sender::NewMemberCommit => {
                // only external commits can have a sender type `NewMemberCommit`
                match &self.tbs.content.body {
                    FramedContentBodyIn::Commit(commit) => commit
                        .unverified_credential()
                        .ok_or(ValidationError::NoPath),
                    _ => Err(ValidationError::NotACommit),
                }
            }
            Sender::NewMemberProposal => {
                // only External Add proposals can have a sender type `NewMemberProposal`
                match &self.tbs.content.body {
                    FramedContentBodyIn::Proposal(ProposalIn::Add(add_proposal)) => {
                        Ok(add_proposal.unverified_credential())
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

impl Verifiable for VerifiableAuthenticatedContentIn {
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

impl VerifiedStruct<VerifiableAuthenticatedContentIn> for AuthenticatedContentIn {
    fn from_verifiable(v: VerifiableAuthenticatedContentIn, _seal: Self::SealingType) -> Self {
        AuthenticatedContentIn {
            wire_format: v.tbs.wire_format,
            content: v.tbs.content,
            auth: v.auth,
        }
    }

    type SealingType = private_mod::Seal;
}

impl SignedStruct<FramedContentTbsIn> for AuthenticatedContentIn {
    fn from_payload(tbs: FramedContentTbsIn, signature: Signature) -> Self {
        let auth = FramedContentAuthDataIn {
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

impl Size for FramedContentAuthDataIn {
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

impl TlsSerializeTrait for FramedContentAuthDataIn {
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

// The following two `From` implementations break abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
// TODO #1186: Re-enable #[cfg(any(feature = "test-utils", test))]
impl From<AuthenticatedContentIn> for AuthenticatedContent {
    fn from(v: AuthenticatedContentIn) -> Self {
        AuthenticatedContent {
            wire_format: v.wire_format,
            content: v.content.into(),
            auth: v.auth.into(),
        }
    }
}

// TODO #1186: The following is temporary until the refactoring of incoming
// messages is done.

impl From<FramedContentAuthDataIn> for crate::framing::mls_auth_content::FramedContentAuthData {
    fn from(v: FramedContentAuthDataIn) -> Self {
        Self {
            signature: v.signature,
            confirmation_tag: v.confirmation_tag,
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<crate::framing::mls_auth_content::FramedContentAuthData> for FramedContentAuthDataIn {
    fn from(v: crate::framing::mls_auth_content::FramedContentAuthData) -> Self {
        Self {
            signature: v.signature,
            confirmation_tag: v.confirmation_tag,
        }
    }
}
