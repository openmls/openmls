//! # MLS content authentication
//!
//! This module contains structs and implementation that pertain to content
//! authentication in MLS. Besides structs that directly represent structs in
//! the MLS specification, this module also contains
//! [`VerifiableAuthenticatedContentIn`], a wrapper struct which ensures that the
//! signatures are verified before the content of an MLS [`PrivateMessageIn`] or
//! [`PublicMessageIn`] can be accessed by processing functions of OpenMLS.

use std::io::Read;

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use tls_codec::Serialize as TlsSerializeTrait;

use super::{mls_auth_content::*, mls_content_in::*, *};
use crate::{
    ciphersuite::signable::{SignedStruct, Verifiable, VerifiedStruct},
    credentials::CredentialWithKey,
    group::errors::ValidationError,
    messages::proposals_in::ProposalIn,
    versions::ProtocolVersion,
};

#[cfg(doc)]
use super::{PrivateMessageIn, PublicMessageIn};

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
    pub(super) auth: FramedContentAuthData,
}

impl AuthenticatedContentIn {
    /// Returns a [`AuthenticatedContent`] after successful validation.
    pub(crate) fn validate(
        self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        sender_context: Option<SenderContext>,
        protocol_version: ProtocolVersion,
    ) -> Result<AuthenticatedContent, ValidationError> {
        Ok(AuthenticatedContent {
            wire_format: self.wire_format,
            content: self.content.validate(
                ciphersuite,
                crypto,
                sender_context,
                protocol_version,
            )?,
            auth: self.auth,
        })
    }
}

#[cfg(any(feature = "test-utils", test))]
impl AuthenticatedContentIn {
    /// Get the content body of the message.
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
        let auth = FramedContentAuthData::deserialize(bytes, content.body.content_type())?;

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
    auth: FramedContentAuthData,
}

impl VerifiableAuthenticatedContentIn {
    /// Create a new [`VerifiableAuthenticatedContentIn`] from a [`FramedContentTbsIn`] and
    /// a [`Signature`].
    pub(crate) fn new(
        wire_format: WireFormat,
        content: FramedContentIn,
        serialized_context: impl Into<Option<Vec<u8>>>,
        auth: FramedContentAuthData,
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
    type VerifiedStruct = AuthenticatedContentIn;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tbs.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.auth.signature
    }

    fn label(&self) -> &str {
        "FramedContentTBS"
    }

    fn verify(
        self,
        crypto: &impl OpenMlsCrypto,
        pk: &OpenMlsSignaturePublicKey,
    ) -> Result<Self::VerifiedStruct, signable::SignatureError> {
        // https://validation.openmls.tech/#valn1302
        // https://validation.openmls.tech/#valn1304
        self.verify_no_out(crypto, pk)?;
        Ok(AuthenticatedContentIn {
            wire_format: self.tbs.wire_format,
            content: self.tbs.content,
            auth: self.auth,
        })
    }
}

impl VerifiedStruct for AuthenticatedContentIn {}

impl SignedStruct<FramedContentTbsIn> for AuthenticatedContentIn {
    fn from_payload(tbs: FramedContentTbsIn, signature: Signature) -> Self {
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

// The following `From` implementation( breaks abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
#[cfg(any(feature = "test-utils", test))]
impl From<AuthenticatedContentIn> for AuthenticatedContent {
    fn from(v: AuthenticatedContentIn) -> Self {
        AuthenticatedContent {
            wire_format: v.wire_format,
            content: v.content.into(),
            auth: v.auth,
        }
    }
}

impl From<AuthenticatedContent> for AuthenticatedContentIn {
    fn from(v: AuthenticatedContent) -> Self {
        AuthenticatedContentIn {
            wire_format: v.wire_format,
            content: v.content.into(),
            auth: v.auth,
        }
    }
}
