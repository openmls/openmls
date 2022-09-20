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
///     opaque group_id<0..255>;
///     uint64 epoch;
///     Sender sender;
///     opaque authenticated_data<0..2^32-1>;
///
///     ContentType content_type;
///     select (MLSPlaintext.content_type) {
///         case application:
///             opaque application_data<0..2^32-1>;
///
///         case proposal:
///             Proposal proposal;
///
///         case commit:
///             Commit commit;
///     }
///
///     opaque signature<0..2^16-1>;
///     optional<MAC> confirmation_tag;
///     optional<MAC> membership_tag;
/// } MLSPlaintext;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub(crate) struct MlsPlaintext {
    wire_format: WireFormat,
    group_id: GroupId,
    epoch: GroupEpoch,
    sender: Sender,
    authenticated_data: TlsByteVecU32,
    content_type: ContentType,
    content: MlsPlaintextContentType,
    signature: Signature,
    confirmation_tag: Option<ConfirmationTag>,
    membership_tag: Option<MembershipTag>,
}

pub(crate) struct Payload {
    pub(crate) payload: MlsPlaintextContentType,
    pub(crate) content_type: ContentType,
}

// This block only has pub(super) getters.
impl MlsPlaintext {
    pub(super) fn signature(&self) -> &Signature {
        &self.signature
    }

    pub(super) fn wire_format(&self) -> WireFormat {
        self.wire_format
    }

    #[cfg(test)]
    pub(super) fn unset_confirmation_tag(&mut self) {
        self.confirmation_tag = None;
    }

    #[cfg(test)]
    pub(super) fn set_content(&mut self, content: MlsPlaintextContentType) {
        self.content = content;
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

    #[cfg(test)]
    pub(super) fn set_wire_format(&mut self, wire_format: WireFormat) {
        self.wire_format = wire_format;
    }
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
            framing_parameters.wire_format(),
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
                payload: MlsPlaintextContentType::Proposal(proposal),
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
                payload: MlsPlaintextContentType::Commit(commit),
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
                payload: MlsPlaintextContentType::Application(application_message.into()),
                content_type: ContentType::Application,
            },
            credential_bundle,
            context,
            membership_key,
            backend,
        )
    }

    /// Returns a reference to the `content` field.
    pub(crate) fn content(&self) -> &MlsPlaintextContentType {
        &self.content
    }

    /// Get the content type of this message.
    pub(crate) fn content_type(&self) -> ContentType {
        self.content_type
    }

    /// Get the sender of this message.
    pub(crate) fn sender(&self) -> &Sender {
        &self.sender
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
        let tbm_payload =
            MlsPlaintextTbmPayload::new(&tbs_payload, &self.signature, &self.confirmation_tag)?;
        let membership_tag = membership_key.tag(backend, tbm_payload)?;

        self.membership_tag = Some(membership_tag);
        Ok(())
    }

    /// Remove the membership tag for testing.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn remove_membership_tag(&mut self) {
        self.membership_tag = None;
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    #[cfg(test)]
    pub(crate) fn is_handshake_message(&self) -> bool {
        self.content_type.is_handshake_message()
    }

    /// Get the group epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Set the confirmation tag.
    pub(crate) fn set_confirmation_tag(&mut self, tag: ConfirmationTag) {
        self.confirmation_tag = Some(tag)
    }

    pub(crate) fn confirmation_tag(&self) -> Option<&ConfirmationTag> {
        self.confirmation_tag.as_ref()
    }

    /// The the authenticated data of this MlsPlaintext as byte slice.
    pub(crate) fn authenticated_data(&self) -> &[u8] {
        self.authenticated_data.as_slice()
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

impl From<&MlsPlaintextContentType> for ContentType {
    fn from(value: &MlsPlaintextContentType) -> Self {
        match value {
            MlsPlaintextContentType::Application(_) => ContentType::Application,
            MlsPlaintextContentType::Proposal(_) => ContentType::Proposal,
            MlsPlaintextContentType::Commit(_) => ContentType::Commit,
        }
    }
}

impl ContentType {
    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub(crate) fn is_handshake_message(&self) -> bool {
        self == &ContentType::Proposal || self == &ContentType::Commit
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub(crate) enum MlsPlaintextContentType {
    Application(TlsByteVecU32),
    Proposal(Proposal),
    Commit(Commit),
}

impl From<MlsPlaintext> for MlsPlaintextContentType {
    fn from(plaintext: MlsPlaintext) -> Self {
        plaintext.content
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
    confirmation_tag: &'a Option<ConfirmationTag>,
}

impl<'a> MlsPlaintextTbmPayload<'a> {
    pub(crate) fn new(
        tbs_payload: &'a [u8],
        signature: &'a Signature,
        confirmation_tag: &'a Option<ConfirmationTag>,
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
    pub(super) wire_format: WireFormat,
    pub(super) group_id: GroupId,
    pub(super) epoch: GroupEpoch,
    pub(super) sender: Sender,
    pub(super) authenticated_data: TlsByteVecU32,
    pub(super) content_type: ContentType,
    pub(super) payload: MlsPlaintextContentType,
}

fn encode_tbs<'a>(
    plaintext: &MlsPlaintext,
    serialized_context: impl Into<Option<&'a [u8]>>,
) -> Result<Vec<u8>, tls_codec::Error> {
    let mut out = Vec::new();
    codec::serialize_plaintext_tbs(
        serialized_context,
        plaintext.wire_format,
        &plaintext.group_id,
        &plaintext.epoch,
        &plaintext.sender,
        &plaintext.authenticated_data,
        &plaintext.content_type,
        &plaintext.content,
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
        let signature = mls_plaintext.signature.clone();
        let membership_tag = mls_plaintext.membership_tag.clone();
        let confirmation_tag = mls_plaintext.confirmation_tag.clone();

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
            MlsPlaintextTbmPayload::new(&tbs_payload, &self.signature, &self.confirmation_tag)?;
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
    pub(crate) fn content(&self) -> &MlsPlaintextContentType {
        &self.tbs.payload
    }

    /// Get the wire format.
    pub(crate) fn wire_format(&self) -> WireFormat {
        self.tbs.wire_format
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
    pub(crate) fn set_content(&mut self, content: MlsPlaintextContentType) {
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
        wire_format: WireFormat,
        group_id: GroupId,
        epoch: impl Into<GroupEpoch>,
        sender: Sender,
        authenticated_data: TlsByteVecU32,
        payload: Payload,
    ) -> Self {
        MlsPlaintextTbs {
            serialized_context: None,
            wire_format,
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
        MlsPlaintextTbs {
            wire_format: mls_plaintext.wire_format,
            serialized_context: None,
            group_id: mls_plaintext.group_id,
            epoch: mls_plaintext.epoch,
            sender: mls_plaintext.sender,
            authenticated_data: mls_plaintext.authenticated_data,
            content_type: mls_plaintext.content_type,
            payload: mls_plaintext.content,
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
        Self {
            wire_format: v.tbs.wire_format,
            group_id: v.tbs.group_id,
            epoch: v.tbs.epoch,
            sender: v.tbs.sender,
            authenticated_data: v.tbs.authenticated_data,
            content_type: v.tbs.content_type,
            content: v.tbs.payload,
            signature: v.signature,
            confirmation_tag: v.confirmation_tag,
            membership_tag: v.membership_tag,
        }
    }

    type SealingType = private_mod::Seal;
}

impl SignedStruct<MlsPlaintextTbs> for MlsPlaintext {
    fn from_payload(tbs: MlsPlaintextTbs, signature: Signature) -> Self {
        Self {
            wire_format: tbs.wire_format,
            group_id: tbs.group_id,
            epoch: tbs.epoch,
            sender: tbs.sender,
            authenticated_data: tbs.authenticated_data,
            content_type: tbs.content_type,
            content: tbs.payload,
            signature,
            // Tags must always be added after the signature
            confirmation_tag: None,
            membership_tag: None,
        }
    }
}

#[derive(TlsSerialize, TlsSize)]
pub(crate) struct MlsPlaintextCommitContent<'a> {
    pub(super) wire_format: WireFormat,
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
        let commit = match &mls_plaintext.content {
            MlsPlaintextContentType::Commit(commit) => commit,
            _ => return Err("MlsPlaintext needs to contain a Commit."),
        };
        Ok(MlsPlaintextCommitContent {
            wire_format: mls_plaintext.wire_format,
            group_id: &mls_plaintext.group_id,
            epoch: mls_plaintext.epoch,
            sender: &mls_plaintext.sender,
            authenticated_data: &mls_plaintext.authenticated_data,
            content_type: mls_plaintext.content_type,
            commit,
            signature: &mls_plaintext.signature,
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
        match mls_plaintext.confirmation_tag.as_ref() {
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
