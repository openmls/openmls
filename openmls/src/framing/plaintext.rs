//! # MlsPlaintext
//!
//! An MlsPlaintext is a framing structure for MLS messages. It can contain
//! Proposals, Commits and application messages.

use crate::{
    ciphersuite::signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
    error::LibraryError,
    group::errors::ValidationError,
};

use super::*;
use openmls_traits::OpenMlsCryptoProvider;
use std::{
    convert::TryFrom,
    io::{Read, Write},
};
use tls_codec::{Deserialize, Serialize, TlsByteVecU32, TlsDeserialize, TlsSerialize, TlsSize};

/// `MLSPlaintext` is a framing structure for MLS messages. It can contain
/// Proposals, Commits and application messages.
///
/// 9. Message framing
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///     MLSContent content;
///     MLSContentAuthData auth;
///     optional<MAC> membership_tag;
/// } MLSPlaintext;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub(crate) struct MlsPlaintext {
    pub(super) content: MlsContent,
    pub(super) auth: MlsContentAuthData,
    pub(super) membership_tag: Option<MembershipTag>,
}

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
    pub(crate) fn serialize_without_type<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
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

// TODO #979: This pierces the abstraction boundary and should be removed.
impl From<MlsPlaintext> for MlsContentBody {
    fn from(plaintext: MlsPlaintext) -> Self {
        plaintext.content.body
    }
}

#[cfg(test)]
impl MlsPlaintext {
    pub fn set_confirmation_tag(&mut self, confirmation_tag: Option<ConfirmationTag>) {
        self.auth.confirmation_tag = confirmation_tag;
    }

    pub fn unset_membership_tag(&mut self) {
        self.membership_tag = None;
    }

    pub fn set_content(&mut self, content: MlsContentBody) {
        self.content.body = content;
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.content.epoch = epoch.into();
    }

    pub fn content(&self) -> &MlsContentBody {
        &self.content.body
    }

    pub fn confirmation_tag(&self) -> Option<&ConfirmationTag> {
        self.auth.confirmation_tag.as_ref()
    }

    pub(crate) fn invalidate_signature(&mut self) {
        let mut modified_signature = self.auth.signature.as_slice().to_vec();
        modified_signature[0] ^= 0xFF;
        self.auth.signature.modify(&modified_signature);
    }

    /// Set the sender.
    pub(crate) fn set_sender(&mut self, sender: Sender) {
        self.content.sender = sender;
    }

    /// Set the group id.
    pub(crate) fn set_group_id(&mut self, group_id: GroupId) {
        self.content.group_id = group_id;
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub(crate) fn is_handshake_message(&self) -> bool {
        self.content_type().is_handshake_message()
    }

    // TODO: #727 - Remove if not needed.
    // #[cfg(test)]
    // pub(super) fn set_signature(&mut self, signature: Signature) {
    //     self.signature = signature;
    // }

    // #[cfg(test)]
    // pub(super) fn set_membership_tag_test(&mut self, tag: MembershipTag) {
    //     self.membership_tag = Some(tag);
    // }
}

impl From<VerifiableMlsAuthContent> for MlsPlaintext {
    fn from(v: VerifiableMlsAuthContent) -> Self {
        v.auth_content.into()
    }
}

impl From<MlsAuthContent> for MlsPlaintext {
    fn from(v: MlsAuthContent) -> Self {
        Self {
            content: v.tbs.content,
            auth: v.auth,
            membership_tag: None,
        }
    }
}

impl MlsPlaintext {
    /// Build an [`MlsPlaintext`].
    pub(crate) fn new(
        content: MlsContent,
        auth: MlsContentAuthData,
        membership_tag: Option<MembershipTag>,
    ) -> Self {
        Self {
            content,
            auth,
            membership_tag,
        }
    }

    /// Returns a reference to the `content` field.
    pub(crate) fn content_type(&self) -> ContentType {
        self.content.body.content_type()
    }

    /// Get the sender of this message.
    pub(crate) fn sender(&self) -> &Sender {
        &self.content.sender
    }

    /// Adds a membership tag to this `MlsPlaintext`. The membership_tag is
    /// produced using the the membership secret.
    ///
    /// This should be used after signing messages from group members.
    pub(crate) fn set_membership_tag(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        serialized_context: &[u8],
        membership_key: &MembershipKey,
    ) -> Result<(), LibraryError> {
        let tbs_payload = self
            .encode_tbs(serialized_context)
            .map_err(LibraryError::missing_bound_check)?;
        let tbm_payload = MlsContentTbm::new(&tbs_payload, &self.auth)?;
        let membership_tag = membership_key.tag(backend, tbm_payload)?;

        self.membership_tag = Some(membership_tag);
        Ok(())
    }

    /// Verify the membership tag of an `UnverifiedMlsPlaintext` sent from a
    /// group member. Returns `Ok(())` if successful or `VerificationError`
    /// otherwise. Note, that the context must have been set before calling this
    /// function.
    // TODO #133: Include this in the validation
    pub(crate) fn verify_membership(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        membership_key: &MembershipKey,
        serialized_context: &[u8],
    ) -> Result<(), ValidationError> {
        log::debug!("Verifying membership tag.");
        log_crypto!(trace, "  Membership key: {:x?}", membership_key);
        log_crypto!(trace, "  Serialized context: {:x?}", serialized_context);
        let tbs_payload = self
            .encode_tbs(serialized_context)
            .map_err(LibraryError::missing_bound_check)?;
        let tbm_payload = MlsContentTbm::new(&tbs_payload, &self.auth)?;
        let expected_membership_tag = &membership_key.tag(backend, tbm_payload)?;

        // Verify the membership tag
        if let Some(membership_tag) = &self.membership_tag {
            // TODO #133: make this a constant-time comparison
            if membership_tag != expected_membership_tag {
                return Err(ValidationError::InvalidMembershipTag);
            }
        } else {
            return Err(ValidationError::MissingMembershipTag);
        }
        Ok(())
    }

    /// Get the group epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.content.epoch
    }

    /// Get the [`GroupId`].
    pub(crate) fn group_id(&self) -> &GroupId {
        &self.content.group_id
    }

    fn encode_tbs<'a>(
        &self,
        serialized_context: impl Into<Option<&'a [u8]>>,
    ) -> Result<Vec<u8>, tls_codec::Error> {
        let mut out = Vec::new();
        codec::serialize_plaintext_tbs(
            WireFormat::MlsPlaintext,
            &self.content,
            serialized_context,
            &mut out,
        )?;
        Ok(out)
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn set_membership_tag_test(&mut self, membership_tag: MembershipTag) {
        self.membership_tag = Some(membership_tag);
    }

    // TODO: #727 - Remove if not needed.
    // #[cfg(test)]
    // pub(crate) fn invalidate_signature(&mut self) {
    //     let mut modified_signature = self.signature().as_slice().to_vec();
    //     modified_signature[0] ^= 0xFF;
    //     self.signature.modify(&modified_signature);
    // }
}

// === Helper structs ===

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
    tbs_payload: &'a [u8],
    auth: &'a MlsContentAuthData,
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

/// Wrapper around a `Mac` used for type safety.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub(crate) struct MembershipTag(pub(crate) Mac);

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

impl From<MlsAuthContent> for MlsContent {
    fn from(mls_auth_content: MlsAuthContent) -> Self {
        mls_auth_content.tbs.content
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
    #[cfg(any(feature = "test-utils", test))]
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

    /// Get the content of the message.
    pub(crate) fn content(&self) -> &MlsContentBody {
        &self.auth_content.tbs.content.body
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

mod private_mod {
    #[derive(Default)]
    pub(crate) struct Seal;
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

/// 9.2 Transcript Hashes
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///    WireFormat wire_format;
///    MLSContent content; /* with content_type == commit */
///    opaque signature<V>;
///} ConfirmedTranscriptHashInput;
/// ```
#[derive(TlsSerialize, TlsSize)]
pub(crate) struct ConfirmedTranscriptHashInput<'a> {
    pub(super) wire_format: WireFormat,
    pub(super) mls_content: &'a MlsContent,
    pub(super) signature: &'a Signature,
}

impl<'a> ConfirmedTranscriptHashInput<'a> {
    pub(crate) fn try_from(mls_content: &'a MlsAuthContent) -> Result<Self, &'static str> {
        if !matches!(mls_content.content().content_type(), ContentType::Commit) {
            return Err("MlsPlaintext needs to contain a Commit.");
        }
        Ok(ConfirmedTranscriptHashInput {
            wire_format: mls_content.wire_format(),
            mls_content: &mls_content.tbs.content,
            signature: mls_content.signature(),
        })
    }
}

#[derive(TlsSerialize, TlsSize)]
pub(crate) struct InterimTranscriptHashInput<'a> {
    pub(crate) confirmation_tag: &'a ConfirmationTag,
}

impl<'a> TryFrom<&'a MlsPlaintext> for InterimTranscriptHashInput<'a> {
    type Error = &'static str;

    fn try_from(mls_plaintext: &'a MlsPlaintext) -> Result<Self, Self::Error> {
        match mls_plaintext.auth.confirmation_tag.as_ref() {
            Some(confirmation_tag) => Ok(InterimTranscriptHashInput { confirmation_tag }),
            None => Err("MLSPlaintext needs to contain a confirmation tag."),
        }
    }
}

impl<'a> From<&'a ConfirmationTag> for InterimTranscriptHashInput<'a> {
    fn from(confirmation_tag: &'a ConfirmationTag) -> Self {
        InterimTranscriptHashInput { confirmation_tag }
    }
}
