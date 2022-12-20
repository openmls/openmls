use crate::{
    ciphersuite::signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
    error::LibraryError,
    group::errors::ValidationError,
};

use super::mls_content::{ContentType, MlsContentBody, MlsContentTbs};

use super::*;
use openmls_traits::OpenMlsCryptoProvider;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, Size, TlsSerialize, TlsSize,
};

/// Private module to ensure protection of [`MlsAuthContent`].
mod private_mod {
    #[derive(Default)]
    pub(crate) struct Seal;
}

/// 7.1 Content Authentication
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///    /* SignWithLabel(., "MLSContentTBS", MLSContentTBS) */
///    opaque signature<V>;
///    select (MLSContent.content_type) {
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
///} MLSContentAuthData;
/// ```
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MlsContentAuthData {
    pub(super) signature: Signature,
    pub(super) confirmation_tag: Option<ConfirmationTag>,
}

impl MlsContentAuthData {
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
/// // draft-ietf-mls-protocol-16
///
/// struct {
///     WireFormat wire_format;
///     MLSContent content;
///     MLSContentAuthData auth;
/// } MLSAuthenticatedContent;
/// ```
///
/// Note that [`MlsAuthContent`] doesn't correspond exactly to the
/// MLSAuthenticatedContent from the MLS specification, as the [`MlsContentTbs`]
/// contains additional information to ease processing.
///
/// TODO #1051: Serialization is only needed for KAT generation at this point.
/// If we want to serialize a spec-compliant MLSAuthenticatedContent, we have to
/// manually ignore the extra fields in the TBS (i.e. context and later
/// ProtocolVersion).
#[derive(PartialEq, Debug, Clone, TlsSerialize, TlsSize)]
pub(crate) struct MlsAuthContent {
    pub(super) tbs: MlsContentTbs,
    pub(super) auth: MlsContentAuthData,
}

impl MlsAuthContent {
    /// Convenience function for creating a [`VerifiableMlsAuthContent`].
    #[inline]
    fn new_and_sign(
        framing_parameters: FramingParameters,
        sender: Sender,
        body: MlsContentBody,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, LibraryError> {
        let mut content_tbs = MlsContentTbs::new(
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

        content_tbs.sign(backend, credential_bundle)
    }

    /// This constructor builds an `MlsAuthContent` containing an application
    /// message. The sender type is always `SenderType::Member`.
    pub(crate) fn new_application(
        sender_leaf_index: u32,
        authenticated_data: &[u8],
        application_message: &[u8],
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, LibraryError> {
        let framing_parameters =
            FramingParameters::new(authenticated_data, WireFormat::MlsCiphertext);
        Self::new_and_sign(
            framing_parameters,
            Sender::Member(sender_leaf_index),
            MlsContentBody::Application(application_message.into()),
            credential_bundle,
            context,
            backend,
        )
    }

    /// This constructor builds an `MlsPlaintext` containing a Proposal.
    /// The sender type is always `SenderType::Member`.
    pub(crate) fn member_proposal(
        framing_parameters: FramingParameters,
        sender_leaf_index: u32,
        proposal: Proposal,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, LibraryError> {
        Self::new_and_sign(
            framing_parameters,
            Sender::Member(sender_leaf_index),
            MlsContentBody::Proposal(proposal),
            credential_bundle,
            context,
            backend,
        )
    }

    /// This constructor builds an `MlsPlaintext` containing an External Proposal.
    /// The sender is [Sender::NewMemberProposal].
    // TODO #151/#106: We don't support preconfigured senders yet
    pub(crate) fn new_external_proposal(
        proposal: Proposal,
        credential_bundle: &CredentialBundle,
        group_id: GroupId,
        epoch: GroupEpoch,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, LibraryError> {
        let body = MlsContentBody::Proposal(proposal);

        let content_tbs = MlsContentTbs::new(
            WireFormat::MlsPlaintext,
            group_id,
            epoch,
            Sender::NewMemberProposal,
            vec![].into(),
            body,
        );

        content_tbs.sign(backend, credential_bundle)
    }

    /// This constructor builds an `MlsPlaintext` containing a Commit. If the
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
            MlsContentBody::Commit(commit),
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
    pub(crate) fn content(&self) -> &MlsContentBody {
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
impl From<VerifiableMlsAuthContent> for MlsAuthContent {
    fn from(v: VerifiableMlsAuthContent) -> Self {
        v.auth_content
    }
}

/// Wrapper struct around [`MlsAuthContent`] to enforce signature verification
/// before content can be accessed.
///
/// TODO #979: Currently, the abstraction boundary between
/// VerifiableMlsAuthContent and its content is not properly enforced.
#[derive(PartialEq, Debug, Clone, TlsSerialize, TlsSize)]
pub(crate) struct VerifiableMlsAuthContent {
    pub(super) auth_content: MlsAuthContent,
}

impl VerifiableMlsAuthContent {
    /// Create a new [`VerifiableMlsAuthContent`] from a [`MlsContentTbs`] and
    /// a [`Signature`].
    pub(crate) fn new(tbs: MlsContentTbs, auth: MlsContentAuthData) -> Self {
        Self {
            auth_content: MlsAuthContent { tbs, auth },
        }
    }

    /// Create a [`VerifiableMlsAuthContent`] from an [`MlsPlaintext`] and the
    /// serialized context.
    pub(crate) fn from_plaintext(
        mls_plaintext: MlsPlaintext,
        serialized_context: impl Into<Option<Vec<u8>>>,
    ) -> Self {
        let tbs = MlsContentTbs {
            wire_format: WireFormat::MlsPlaintext,
            content: mls_plaintext.content,
            serialized_context: serialized_context.into(),
        };

        Self::new(tbs, mls_plaintext.auth)
    }

    /// Get the [`Sender`].
    pub fn sender(&self) -> &Sender {
        &self.auth_content.tbs.content.sender
    }

    /// Set the serialized context before verifying the signature.
    pub(crate) fn set_context(&mut self, serialized_context: Vec<u8>) {
        self.auth_content.tbs.serialized_context = Some(serialized_context);
    }

    /// Set the serialized context before verifying the signature.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn has_context(&self) -> bool {
        self.auth_content.tbs.serialized_context.is_some()
    }

    /// Get the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.auth_content.tbs.epoch()
    }

    /// Returns the [`Credential`] contained in the [`VerifiableMlsAuthContent`]
    /// if the `sender_type` is either [`Sender::NewMemberCommit`] or
    /// [`Sender::NewMemberProposal`].
    ///
    /// Returns a [`ValidationError`] if
    /// * the sender type is not one of the above,
    /// * the content type doesn't match the sender type, or
    /// * if it's a NewMemberCommit and the Commit doesn't contain a `path`.
    pub(crate) fn new_member_credential(&self) -> Result<Credential, ValidationError> {
        match self.auth_content.tbs.content.sender {
            Sender::NewMemberCommit => {
                // only external commits can have a sender type `NewMemberCommit`
                match &self.auth_content.tbs.content.body {
                    MlsContentBody::Commit(Commit { path, .. }) => path
                        .as_ref()
                        .map(|p| p.leaf_node().credential().clone())
                        .ok_or(ValidationError::NoPath),
                    _ => Err(ValidationError::NotACommit),
                }
            }
            Sender::NewMemberProposal => {
                // only External Add proposals can have a sender type `NewMemberProposal`
                match &self.auth_content.tbs.content.body {
                    MlsContentBody::Proposal(Proposal::Add(AddProposal { key_package })) => {
                        Ok(key_package.credential().clone())
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

impl Verifiable for VerifiableMlsAuthContent {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.auth_content.tbs.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.auth_content.auth.signature
    }

    fn label(&self) -> &str {
        "MLSPlaintextTBS"
    }
}

impl VerifiedStruct<VerifiableMlsAuthContent> for MlsAuthContent {
    fn from_verifiable(v: VerifiableMlsAuthContent, _seal: Self::SealingType) -> Self {
        v.auth_content
    }

    type SealingType = private_mod::Seal;
}

impl SignedStruct<MlsContentTbs> for MlsAuthContent {
    fn from_payload(tbs: MlsContentTbs, signature: Signature) -> Self {
        let auth = MlsContentAuthData {
            signature,
            // Tags must always be added after the signature
            confirmation_tag: None,
        };
        Self { tbs, auth }
    }
}

impl Size for MlsContentAuthData {
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

impl TlsSerializeTrait for MlsContentAuthData {
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
