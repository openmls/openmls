//! # PublicMessage
//!
//! A PublicMessage is a framing structure for MLS messages. It can contain
//! Proposals, Commits and application messages.

use crate::{error::LibraryError, group::errors::ValidationError};

use super::{
    mls_auth_content::{
        AuthenticatedContent, FramedContentAuthData, VerifiableAuthenticatedContent,
    },
    mls_content::{AuthenticatedContentTbm, ContentType, FramedContent, FramedContentTbs},
    *,
};

use openmls_traits::OpenMlsCryptoProvider;
use std::{
    convert::TryFrom,
    io::{Read, Write},
};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, TlsDeserialize,
    TlsSerialize, TlsSize,
};

/// Wrapper around a `Mac` used for type safety.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub(crate) struct MembershipTag(pub(crate) Mac);

/// `PublicMessage` is a framing structure for MLS messages. It can contain
/// Proposals, Commits and application messages.
///
/// 9. Message framing
///
/// ```c
/// // draft-ietf-mls-protocol-17
///
/// struct {
///     FramedContent content;
///     FramedContentAuthData auth;
///     optional<MAC> membership_tag;
/// } PublicMessage;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub(crate) struct PublicMessage {
    content: FramedContentTbs,
    auth: FramedContentAuthData,
    membership_tag: Option<MembershipTag>,
}

#[cfg(test)]
impl PublicMessage {
    pub fn set_confirmation_tag(&mut self, confirmation_tag: Option<ConfirmationTag>) {
        self.auth.confirmation_tag = confirmation_tag;
    }

    pub fn unset_membership_tag(&mut self) {
        self.membership_tag = None;
    }

    pub fn set_content(&mut self, content: FramedContentBody) {
        self.content.content.body = content;
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.content.content.epoch = epoch.into();
    }

    pub fn content(&self) -> &FramedContentBody {
        &self.content.content.body
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
        self.content.content.sender = sender;
    }

    /// Set the group id.
    pub(crate) fn set_group_id(&mut self, group_id: GroupId) {
        self.content.content.group_id = group_id;
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub(crate) fn is_handshake_message(&self) -> bool {
        self.content_type().is_handshake_message()
    }

    /// Strips the internal context.
    pub(crate) fn test_set_context(&mut self, serialized_context: impl Into<Option<Vec<u8>>>) {
        self.content.serialized_context = serialized_context.into()
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

impl From<AuthenticatedContent> for PublicMessage {
    fn from(v: AuthenticatedContent) -> Self {
        Self {
            content: v.tbs,
            auth: v.auth,
            membership_tag: None,
        }
    }
}

impl From<PublicMessage> for VerifiableAuthenticatedContent {
    fn from(pm: PublicMessage) -> Self {
        Self::new(pm.content, pm.auth)
    }
}

impl PublicMessage {
    /// Build an [`PublicMessage`].
    pub(crate) fn new(
        content: FramedContentTbs,
        auth: FramedContentAuthData,
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
        self.content.content.body.content_type()
    }

    /// Get the sender of this message.
    pub(crate) fn sender(&self) -> &Sender {
        &self.content.content.sender
    }

    #[cfg(test)]
    pub(crate) fn set_membership_tag_with_context(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        serialized_context: &[u8],
        membership_key: &MembershipKey,
    ) -> Result<(), LibraryError> {
        self.set_context(serialized_context);
        self.set_membership_tag(backend, membership_key)
    }

    /// Adds a membership tag to this `PublicMessage`. The membership_tag is
    /// produced using the the membership secret.
    ///
    /// This should be used after signing messages from group members.
    pub(crate) fn set_membership_tag(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        membership_key: &MembershipKey,
    ) -> Result<(), LibraryError> {
        let tbs_payload = self
            .content
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        let tbm_payload = AuthenticatedContentTbm::new(&tbs_payload, &self.auth)?;
        let membership_tag = membership_key.tag(backend, tbm_payload)?;

        self.membership_tag = Some(membership_tag);
        Ok(())
    }

    /// Verify the membership tag of a [`PublicMessage`] sent from a group
    /// member. Returns `Ok(())` if successful or [`ValidationError`] otherwise.
    /// Note, that the context must have been set before calling this function.
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
            .content
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        let tbm_payload = AuthenticatedContentTbm::new(&tbs_payload, &self.auth)?;
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
        self.content.content.epoch
    }

    /// Get the [`GroupId`].
    pub(crate) fn group_id(&self) -> &GroupId {
        &self.content.content.group_id
    }

    /// Set the context for later verification. This should only be done for
    /// messages with [`Sender::Member`] and [`Sender::NewMemberCommit`].
    pub(super) fn set_context(&mut self, context: &[u8]) {
        let serialized_context =
            if matches!(self.sender(), Sender::NewMemberCommit | Sender::Member(_)) {
                Some(context.to_vec())
            } else {
                None
            };
        self.content.serialized_context = serialized_context
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

#[cfg(test)]
impl From<PublicMessage> for FramedContentTbs {
    fn from(v: PublicMessage) -> Self {
        v.content
    }
}

// === Helper structs ===

/// 9.2 Transcript Hashes
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///    WireFormat wire_format;
///    FramedContent content; /* with content_type == commit */
///    opaque signature<V>;
///} ConfirmedTranscriptHashInput;
/// ```
#[derive(TlsSerialize, TlsSize)]
pub(crate) struct ConfirmedTranscriptHashInput<'a> {
    pub(super) wire_format: WireFormat,
    pub(super) mls_content: &'a FramedContent,
    pub(super) signature: &'a Signature,
}

impl<'a> ConfirmedTranscriptHashInput<'a> {
    pub(crate) fn try_from(mls_content: &'a AuthenticatedContent) -> Result<Self, &'static str> {
        if !matches!(mls_content.content().content_type(), ContentType::Commit) {
            return Err("PublicMessage needs to contain a Commit.");
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

impl<'a> TryFrom<&'a PublicMessage> for InterimTranscriptHashInput<'a> {
    type Error = &'static str;

    fn try_from(public_message: &'a PublicMessage) -> Result<Self, Self::Error> {
        match public_message.auth.confirmation_tag.as_ref() {
            Some(confirmation_tag) => Ok(InterimTranscriptHashInput { confirmation_tag }),
            None => Err("PublicMessage needs to contain a confirmation tag."),
        }
    }
}

impl<'a> From<&'a ConfirmationTag> for InterimTranscriptHashInput<'a> {
    fn from(confirmation_tag: &'a ConfirmationTag) -> Self {
        InterimTranscriptHashInput { confirmation_tag }
    }
}

impl TlsDeserializeTrait for PublicMessage {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let content: FramedContent = FramedContent::tls_deserialize(bytes)?;
        let auth = FramedContentAuthData::deserialize(bytes, content.body.content_type())?;
        let membership_tag = if content.sender.is_member() {
            Some(MembershipTag::tls_deserialize(bytes)?)
        } else {
            None
        };
        let tbs = FramedContentTbs::new(
            WireFormat::PublicMessage,
            content.group_id,
            content.epoch,
            content.sender,
            content.authenticated_data,
            content.body,
        );

        Ok(PublicMessage::new(tbs, auth, membership_tag))
    }
}

impl Size for PublicMessage {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.content.content.tls_serialized_len()
            + self.auth.tls_serialized_len()
            + if let Some(membership_tag) = &self.membership_tag {
                membership_tag.tls_serialized_len()
            } else {
                0
            }
    }
}

impl TlsSerializeTrait for PublicMessage {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        // Serialize the content, not the TBS.
        let mut written = self.content.content.tls_serialize(writer)?;
        written += self.auth.tls_serialize(writer)?;
        written += if let Some(membership_tag) = &self.membership_tag {
            membership_tag.tls_serialize(writer)?
        } else {
            0
        };
        Ok(written)
    }
}
