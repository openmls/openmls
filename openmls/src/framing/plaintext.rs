//! # MlsPlaintext
//!
//! An MlsPlaintext is a framing structure for MLS messages. It can contain
//! Proposals, Commits and application messages.

use crate::{
    ciphersuite::{
        hash_ref::KeyPackageRef,
        signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
    },
    error::LibraryError,
    group::errors::ValidationError,
};

use super::*;
use openmls_traits::OpenMlsCryptoProvider;
use std::convert::TryFrom;
use tls_codec::{Serialize, TlsByteVecU32, TlsDeserialize, TlsSerialize, TlsSize};

/// `MLSPlaintext` is a framing structure for MLS messages. It can contain
/// Proposals, Commits and application messages.
///
/// 9. Message framing
///
/// ```c
/// struct {
///     MLSContent content;
///     MLSContentAuthData auth;
///
///     // ... continued in [MlsPlaintextBody] ...
/// } MLSPlaintext;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub(crate) struct MlsPlaintext {
    content: MlsContent,
    auth: MlsContentAuthData,
    body: MlsPlaintextBody,
}

/// ```c
/// struct {
///     // ... continued from [MlsPlaintext] ...
///
///     select (MLSPlaintext.content.sender.sender_type) {
///         case member:
///             MAC membership_tag;
///         case external:
///         case new_member_commit:
///         case new_member_proposal:
///             struct{};
///     }
/// } MLSPlaintext;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
enum MlsPlaintextBody {
    Member { membership_tag: MembershipTag },
    External,
    NewMemberCommit,
    NewMemberProposal,
}

/// ```c
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     Sender sender;
///     opaque authenticated_data<V>;
///
///     // ... continued in [MlsContentBody] ...
/// } MLSContent;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
struct MlsContent {
    group_id: GroupId,
    epoch: GroupEpoch,
    sender: Sender,
    authenticated_data: TlsByteVecU32,

    body: MlsContentBody,
}

/// ```c
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
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub(crate) enum MlsContentBody {
    Application(TlsByteVecU32),
    Proposal(Proposal),
    Commit(Commit),
}

/// ```c
/// struct {
///     // SignWithLabel(., "MLSContentTBS", MLSContentTBS)
///     opaque signature<V>;
///
///     // ... continued in [MlsContentAuthDataBody] ...
/// } MLSContentAuthData;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
struct MlsContentAuthData {
    signature: Signature,
    body: MlsContentAuthDataBody,
}

/// ```c
/// struct {
///     // ... continued in [MlsContentAuthDataBody] ...
///
///     select (MLSContent.content_type) {
///         case commit:
///             // MAC(confirmation_key, GroupContext.confirmed_transcript_hash)
///             MAC confirmation_tag;
///         case application:
///         case proposal:
///             struct{};
///     }
/// } MLSContentAuthData;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
enum MlsContentAuthDataBody {
    Commit { confirmation_tag: ConfirmationTag },
    Application,
    Proposal,
}

pub(crate) struct Payload {
    pub(crate) payload: MlsContentBody,
    pub(crate) content_type: ContentType,
}

// This block only has pub(super) getters.
impl MlsPlaintext {
    pub(super) fn signature(&self) -> &Signature {
        &self.auth.signature
    }

    #[cfg(test)]
    pub(super) fn unset_confirmation_tag(&mut self) {
        unimplemented!();
    }

    #[cfg(test)]
    pub(super) fn set_content(&mut self, content: MlsContentBody) {
        self.content.body = content;
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

impl MlsPlaintext {
    /// Convenience function for creating an `MlsPlaintext`.
    #[inline]
    fn new(
        framing_parameters: FramingParameters,
        sender: Sender,
        payload: Payload,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, LibraryError> {
        let mut mls_plaintext = MlsPlaintextTbs::new(
            context.group_id().clone(),
            context.epoch(),
            sender.clone(),
            framing_parameters.aad().into(),
            payload,
        );

        if let Sender::Member(_) = sender {
            let serialized_context = context
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?;
            mls_plaintext = mls_plaintext.with_context(serialized_context);
        }

        mls_plaintext.sign(backend, credential_bundle)
    }

    /// Create message with membership tag
    #[inline]
    fn new_with_membership_tag(
        framing_parameters: FramingParameters,
        sender_reference: &KeyPackageRef,
        payload: Payload,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        membership_key: &MembershipKey,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, LibraryError> {
        let sender = Sender::build_member(sender_reference);
        let mut mls_plaintext = Self::new(
            framing_parameters,
            sender,
            payload,
            credential_bundle,
            context,
            backend,
        )?;
        mls_plaintext.set_membership_tag(
            backend,
            &context
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?,
            membership_key,
        )?;
        Ok(mls_plaintext)
    }

    /// This constructor builds an `MlsPlaintext` containing a Proposal.
    /// The sender type is always `SenderType::Member`.
    pub(crate) fn member_proposal(
        framing_parameters: FramingParameters,
        sender_reference: &KeyPackageRef,
        proposal: Proposal,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        membership_key: &MembershipKey,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, LibraryError> {
        Self::new_with_membership_tag(
            framing_parameters,
            sender_reference,
            Payload {
                payload: MlsContentBody::Proposal(proposal),
                content_type: ContentType::Proposal,
            },
            credential_bundle,
            context,
            membership_key,
            backend,
        )
    }

    /// This constructor builds an `MlsPlaintext` containing a Commit. If the
    /// given `CommitType` is `Member`, the `SenderType` is `Member` as well. If
    /// it's an `External` commit, the `SenderType` is `NewMember`. If it is an
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
        Self::new(
            framing_parameters,
            sender,
            Payload {
                payload: MlsContentBody::Commit(commit),
                content_type: ContentType::Commit,
            },
            credential_bundle,
            context,
            backend,
        )
    }

    /// This constructor builds an `MlsPlaintext` containing an application
    /// message. The sender type is always `SenderType::Member`.
    pub(crate) fn new_application(
        sender_reference: &KeyPackageRef,
        authenticated_data: &[u8],
        application_message: &[u8],
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        membership_key: &MembershipKey,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, LibraryError> {
        let framing_parameters =
            FramingParameters::new(authenticated_data, WireFormat::MlsCiphertext);
        Self::new_with_membership_tag(
            framing_parameters,
            sender_reference,
            Payload {
                payload: MlsContentBody::Application(application_message.into()),
                content_type: ContentType::Application,
            },
            credential_bundle,
            context,
            membership_key,
            backend,
        )
    }

    /// Returns a reference to the `content` field.
    pub(crate) fn content(&self) -> &MlsContentBody {
        &self.content.body
    }

    /// Get the content type of this message.
    pub(crate) fn content_type(&self) -> ContentType {
        match self.content.body {
            MlsContentBody::Application(_) => ContentType::Application,
            MlsContentBody::Proposal(_) => ContentType::Proposal,
            MlsContentBody::Commit(_) => ContentType::Commit,
        }
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
        let tbs_payload =
            encode_tbs(self, serialized_context).map_err(LibraryError::missing_bound_check)?;

        let confirmation_tag = self.confirmation_tag().cloned();
        let tbm_payload = MlsPlaintextTbmPayload::new(
            &tbs_payload,
            &self.auth.signature,
            confirmation_tag.as_ref(),
        )?;

        match &mut self.body {
            MlsPlaintextBody::Member { membership_tag } => {
                *membership_tag = membership_key.tag(backend, tbm_payload)?;
            }
            MlsPlaintextBody::External => unimplemented!(),
            MlsPlaintextBody::NewMemberCommit => unimplemented!(),
            MlsPlaintextBody::NewMemberProposal => unimplemented!(),
        }

        Ok(())
    }

    /// Remove the membership tag for testing.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn remove_membership_tag(&mut self) {
        unimplemented!()
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    #[cfg(test)]
    pub(crate) fn is_handshake_message(&self) -> bool {
        self.content_type().is_handshake_message()
    }

    /// Get the group epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.content.epoch
    }

    /// Set the confirmation tag.
    pub(crate) fn set_confirmation_tag(&mut self, tag: ConfirmationTag) {
        match self.auth.body {
            MlsContentAuthDataBody::Commit {
                ref mut confirmation_tag,
            } => {
                *confirmation_tag = tag;
            }
            MlsContentAuthDataBody::Application => unimplemented!(),
            MlsContentAuthDataBody::Proposal => unimplemented!(),
        }
    }

    pub(crate) fn confirmation_tag(&self) -> Option<&ConfirmationTag> {
        match self.auth.body {
            MlsContentAuthDataBody::Commit {
                ref confirmation_tag,
            } => Some(confirmation_tag),
            MlsContentAuthDataBody::Application => None,
            MlsContentAuthDataBody::Proposal => None,
        }
    }

    pub(crate) fn membership_tag(&self) -> Option<&MembershipTag> {
        match self.body {
            MlsPlaintextBody::Member { ref membership_tag } => Some(membership_tag),
            MlsPlaintextBody::External => None,
            MlsPlaintextBody::NewMemberCommit => None,
            MlsPlaintextBody::NewMemberProposal => None,
        }
    }

    /// The authenticated data of this MlsPlaintext as byte slice.
    pub(crate) fn authenticated_data(&self) -> &[u8] {
        self.content.authenticated_data.as_slice()
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
        match value {
            MlsContentBody::Application(_) => ContentType::Application,
            MlsContentBody::Proposal(_) => ContentType::Proposal,
            MlsContentBody::Commit(_) => ContentType::Commit,
        }
    }
}

impl ContentType {
    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub(crate) fn is_handshake_message(&self) -> bool {
        self == &ContentType::Proposal || self == &ContentType::Commit
    }
}

impl From<MlsPlaintext> for MlsContentBody {
    fn from(plaintext: MlsPlaintext) -> Self {
        plaintext.content.body
    }
}

/// 9.1 Content Authentication
///
/// ```c
/// struct {
///   MLSPlaintextTBS tbs;
///   opaque signature<0..2^16-1>;
///   optional<MAC> confirmation_tag;
/// } MLSPlaintextTBM;
/// ```
#[derive(Debug)]
pub(crate) struct MlsPlaintextTbmPayload<'a> {
    tbs_payload: &'a [u8],
    signature: &'a Signature,
    confirmation_tag: Option<&'a ConfirmationTag>,
}

impl<'a> MlsPlaintextTbmPayload<'a> {
    pub(crate) fn new(
        tbs_payload: &'a [u8],
        signature: &'a Signature,
        confirmation_tag: Option<&'a ConfirmationTag>,
    ) -> Result<Self, LibraryError> {
        Ok(Self {
            tbs_payload,
            signature,
            confirmation_tag,
        })
    }

    pub(crate) fn into_bytes(self) -> Result<Vec<u8>, tls_codec::Error> {
        let mut buffer = self.tbs_payload.to_vec();
        self.signature.tls_serialize(&mut buffer)?;
        self.confirmation_tag.tls_serialize(&mut buffer)?;
        Ok(buffer)
    }
}

/// Wrapper around a `Mac` used for type safety.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub(crate) struct MembershipTag(pub(crate) Mac);

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct MlsPlaintextTbs {
    pub(super) serialized_context: Option<Vec<u8>>,
    pub(super) group_id: GroupId,
    pub(super) epoch: GroupEpoch,
    pub(super) sender: Sender,
    pub(super) authenticated_data: TlsByteVecU32,
    pub(super) content_type: ContentType,
    pub(super) payload: MlsContentBody,
}

fn encode_tbs<'a>(
    plaintext: &MlsPlaintext,
    serialized_context: impl Into<Option<&'a [u8]>>,
) -> Result<Vec<u8>, tls_codec::Error> {
    let mut out = Vec::new();

    let content_type = match plaintext.content.body {
        MlsContentBody::Application(_) => ContentType::Application,
        MlsContentBody::Proposal(_) => ContentType::Proposal,
        MlsContentBody::Commit(_) => ContentType::Commit,
    };

    codec::serialize_plaintext_tbs(
        serialized_context,
        &plaintext.content.group_id,
        &plaintext.content.epoch,
        &plaintext.content.sender,
        &plaintext.content.authenticated_data,
        &content_type,
        &plaintext.content.body,
        &mut out,
    )?;
    Ok(out)
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct VerifiableMlsPlaintext {
    pub(super) tbs: MlsPlaintextTbs,
    pub(super) signature: Signature,
    pub(super) confirmation_tag: Option<ConfirmationTag>,
    pub(super) membership_tag: Option<MembershipTag>,
}

impl VerifiableMlsPlaintext {
    /// Create a new [`VerifiableMlsPlaintext`] from a [`MlsPlaintextTbs`] and
    /// a [`Signature`].
    pub(crate) fn new(
        tbs: MlsPlaintextTbs,
        signature: Signature,
        confirmation_tag: impl Into<Option<ConfirmationTag>>,
        membership_tag: impl Into<Option<MembershipTag>>,
    ) -> Self {
        Self {
            tbs,
            signature,
            confirmation_tag: confirmation_tag.into(),
            membership_tag: membership_tag.into(),
        }
    }

    /// Create a [`VerifiableMlsPlaintext`] from an [`MlsPlaintext`] and the
    /// serialized context.
    pub(crate) fn from_plaintext(
        mls_plaintext: MlsPlaintext,
        serialized_context: impl Into<Option<Vec<u8>>>,
    ) -> Self {
        let signature = mls_plaintext.auth.signature.clone();
        let membership_tag = mls_plaintext.membership_tag().cloned();
        let confirmation_tag = mls_plaintext.confirmation_tag().cloned();

        match serialized_context.into() {
            Some(context) => Self {
                tbs: MlsPlaintextTbs::from_plaintext(mls_plaintext).with_context(context),
                signature,
                confirmation_tag,
                membership_tag,
            },
            None => Self {
                tbs: MlsPlaintextTbs::from_plaintext(mls_plaintext),
                signature,
                confirmation_tag,
                membership_tag,
            },
        }
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
    ) -> Result<(), ValidationError> {
        log::debug!("Verifying membership tag.");
        log_crypto!(trace, "  Membership key: {:x?}", membership_key);
        log_crypto!(trace, "  Serialized context: {:x?}", serialized_context);
        let tbs_payload = self
            .tbs
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        let tbm_payload =
            MlsPlaintextTbmPayload::new(&tbs_payload, &self.signature, self.confirmation_tag())?;
        let expected_membership_tag = &membership_key.tag(backend, tbm_payload)?;

        // Verify the membership tag
        if let Some(membership_tag) = self.membership_tag() {
            // TODO #133: make this a constant-time comparison
            if membership_tag != expected_membership_tag {
                return Err(ValidationError::InvalidMembershipTag);
            }
        } else {
            return Err(ValidationError::MissingMembershipTag);
        }
        Ok(())
    }

    /// Get the [`Sender`].
    pub fn sender(&self) -> &Sender {
        &self.tbs.sender
    }

    /// Set the sender.
    #[cfg(test)]
    pub(crate) fn set_sender(&mut self, sender: Sender) {
        self.tbs.sender = sender;
    }

    /// Get the group id as [`GroupId`].
    pub(crate) fn group_id(&self) -> &GroupId {
        &self.tbs.group_id
    }

    /// Set the group id.
    #[cfg(test)]
    pub(crate) fn set_group_id(&mut self, group_id: GroupId) {
        self.tbs.group_id = group_id;
    }

    /// Set the serialized context before verifying the signature.
    pub(crate) fn set_context(&mut self, serialized_context: Vec<u8>) {
        self.tbs.serialized_context = Some(serialized_context);
    }

    /// Set the serialized context before verifying the signature.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn has_context(&self) -> bool {
        self.tbs.serialized_context.is_some()
    }

    /// Get the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.tbs.epoch()
    }

    /// Set the epoch.
    #[cfg(test)]
    pub(crate) fn set_epoch(&mut self, epoch: u64) {
        self.tbs.epoch = epoch.into();
    }

    /// Get the underlying MlsPlaintext data of the tbs object.
    #[cfg(test)]
    pub(crate) fn payload(&self) -> &MlsPlaintextTbs {
        &self.tbs
    }

    /// Get the content of the message.
    pub(crate) fn content(&self) -> &MlsContentBody {
        &self.tbs.payload
    }

    /// Get the membership tag.
    pub(crate) fn membership_tag(&self) -> &Option<MembershipTag> {
        &self.membership_tag
    }

    /// Set the membership tag.
    #[cfg(test)]
    pub(crate) fn set_membership_tag(&mut self, tag: MembershipTag) {
        self.membership_tag = Some(tag);
    }

    /// Unset the membership tag.
    #[cfg(test)]
    pub(crate) fn unset_membership_tag(&mut self) {
        self.membership_tag = None;
    }

    /// Get the confirmation tag.
    pub(crate) fn confirmation_tag(&self) -> Option<&ConfirmationTag> {
        self.confirmation_tag.as_ref()
    }

    /// Set the confirmation tag.
    #[cfg(test)]
    pub(crate) fn set_confirmation_tag(&mut self, confirmation_tag: Option<ConfirmationTag>) {
        self.confirmation_tag = confirmation_tag;
    }

    /// Get the content type
    pub(crate) fn content_type(&self) -> ContentType {
        self.tbs.content_type
    }

    /// Set the content type.
    #[cfg(test)]
    pub(crate) fn set_content_type(&mut self, content_type: ContentType) {
        self.tbs.content_type = content_type;
    }

    /// Set the content.
    #[cfg(test)]
    pub(crate) fn set_content(&mut self, content: MlsContentBody) {
        self.tbs.payload = content;
    }

    /// Get the signature.
    #[cfg(test)]
    pub(crate) fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Set the signature.
    #[cfg(test)]
    pub(crate) fn set_signature(&mut self, signature: Signature) {
        self.signature = signature;
    }

    #[cfg(test)]
    pub(crate) fn invalidate_signature(&mut self) {
        let mut modified_signature = self.signature().as_slice().to_vec();
        modified_signature[0] ^= 0xFF;
        self.signature.modify(&modified_signature);
    }
}

impl Signable for MlsPlaintextTbs {
    type SignedOutput = MlsPlaintext;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }
}

impl MlsPlaintextTbs {
    /// Create an MlsPlaintextTbs from an existing values.
    /// Note that if you would like to add a serialized context, you
    /// should subsequently call [`with_context`].
    pub(crate) fn new(
        group_id: GroupId,
        epoch: impl Into<GroupEpoch>,
        sender: Sender,
        authenticated_data: TlsByteVecU32,
        payload: Payload,
    ) -> Self {
        MlsPlaintextTbs {
            serialized_context: None,
            group_id,
            epoch: epoch.into(),
            sender,
            authenticated_data,
            content_type: payload.content_type,
            payload: payload.payload,
        }
    }
    /// Adds a serialized context to MlsPlaintextTbs.
    /// This consumes the original struct and can be used as a builder function.
    pub(crate) fn with_context(mut self, serialized_context: Vec<u8>) -> Self {
        self.serialized_context = Some(serialized_context);
        self
    }

    /// Create a new signable MlsPlaintext from an existing MlsPlaintext.
    /// This consumes the existing plaintext.
    /// To get the `MlsPlaintext` back use `sign`.
    fn from_plaintext(mls_plaintext: MlsPlaintext) -> Self {
        let content_type = mls_plaintext.content_type();

        MlsPlaintextTbs {
            serialized_context: None,
            group_id: mls_plaintext.content.group_id,
            epoch: mls_plaintext.content.epoch,
            sender: mls_plaintext.content.sender,
            authenticated_data: mls_plaintext.content.authenticated_data,
            content_type: content_type,
            payload: mls_plaintext.content.body,
        }
    }

    /// Get the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.epoch
    }
}

impl Verifiable for VerifiableMlsPlaintext {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tbs.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

mod private_mod {
    #[derive(Default)]
    pub(crate) struct Seal;
}

impl VerifiedStruct<VerifiableMlsPlaintext> for MlsPlaintext {
    fn from_verifiable(v: VerifiableMlsPlaintext, _seal: Self::SealingType) -> Self {
        let content = {
            let body = v.tbs.payload;

            MlsContent {
                group_id: v.tbs.group_id,
                epoch: v.tbs.epoch,
                sender: v.tbs.sender,
                authenticated_data: v.tbs.authenticated_data,

                body,
            }
        };

        let auth = {
            let body = match v.confirmation_tag {
                Some(confirmation_tag) => MlsContentAuthDataBody::Commit { confirmation_tag },
                None => {
                    unimplemented!()
                }
            };

            MlsContentAuthData {
                signature: v.signature,
                body,
            }
        };

        let body = match v.membership_tag {
            Some(membership_tag) => MlsPlaintextBody::Member { membership_tag },
            None => {
                unimplemented!()
            }
        };

        Self {
            content,
            auth,
            body,
        }
    }

    type SealingType = private_mod::Seal;
}

impl SignedStruct<MlsPlaintextTbs> for MlsPlaintext {
    fn from_payload(tbs: MlsPlaintextTbs, signature: Signature) -> Self {
        let content = {
            let body = tbs.payload;

            MlsContent {
                group_id: tbs.group_id,
                epoch: tbs.epoch,
                sender: tbs.sender,
                authenticated_data: tbs.authenticated_data,

                body,
            }
        };

        let auth = {
            // TODO: This is wrong? What does no confirmation_tag mean?
            let body = MlsContentAuthDataBody::Proposal;

            MlsContentAuthData { signature, body }
        };

        // TODO: This is wrong? What does no confirmation_tag mean?
        let body = MlsPlaintextBody::NewMemberProposal;

        Self {
            content,
            auth,
            body,
        }
    }
}

#[derive(TlsSerialize, TlsSize)]
pub(crate) struct MlsPlaintextCommitContent<'a> {
    pub(super) group_id: &'a GroupId,
    pub(super) epoch: GroupEpoch,
    pub(super) sender: &'a Sender,
    pub(super) authenticated_data: &'a TlsByteVecU32,
    pub(super) content_type: ContentType,
    pub(super) commit: &'a Commit,
    pub(super) signature: &'a Signature,
}

impl<'a> TryFrom<&'a MlsPlaintext> for MlsPlaintextCommitContent<'a> {
    type Error = &'static str;

    fn try_from(mls_plaintext: &'a MlsPlaintext) -> Result<Self, Self::Error> {
        let commit = match &mls_plaintext.content.body {
            MlsContentBody::Commit(commit) => commit,
            _ => return Err("MlsPlaintext needs to contain a Commit."),
        };
        Ok(MlsPlaintextCommitContent {
            group_id: &mls_plaintext.content.group_id,
            epoch: mls_plaintext.content.epoch,
            sender: &mls_plaintext.content.sender,
            authenticated_data: &mls_plaintext.content.authenticated_data,
            content_type: mls_plaintext.content_type(),
            commit,
            signature: &mls_plaintext.auth.signature,
        })
    }
}

#[derive(TlsSerialize, TlsSize)]
pub(crate) struct MlsPlaintextCommitAuthData<'a> {
    pub(crate) confirmation_tag: Option<&'a ConfirmationTag>,
}

impl<'a> TryFrom<&'a MlsPlaintext> for MlsPlaintextCommitAuthData<'a> {
    type Error = &'static str;

    fn try_from(mls_plaintext: &'a MlsPlaintext) -> Result<Self, Self::Error> {
        match mls_plaintext.confirmation_tag() {
            Some(confirmation_tag) => Ok(MlsPlaintextCommitAuthData {
                confirmation_tag: Some(confirmation_tag),
            }),
            None => Err("MLSPlaintext needs to contain a confirmation tag."),
        }
    }
}

impl<'a> From<&'a ConfirmationTag> for MlsPlaintextCommitAuthData<'a> {
    fn from(confirmation_tag: &'a ConfirmationTag) -> Self {
        MlsPlaintextCommitAuthData {
            confirmation_tag: Some(confirmation_tag),
        }
    }
}
