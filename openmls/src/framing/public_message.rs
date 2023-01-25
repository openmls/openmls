//! # PublicMessage
//!
//! A PublicMessage is a framing structure for MLS messages. It can contain
//! Proposals, Commits and application messages.

use crate::{error::LibraryError, group::errors::ValidationError, versions::ProtocolVersion};

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

/// [`PublicMessage`] is a framing structure for MLS messages. It can contain
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
pub struct PublicMessage {
    content: FramedContent,
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

    pub(crate) fn set_content(&mut self, content: FramedContentBody) {
        self.content.body = content;
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.content.epoch = epoch.into();
    }

    pub(crate) fn content(&self) -> &FramedContentBody {
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

impl From<AuthenticatedContent> for PublicMessage {
    fn from(v: AuthenticatedContent) -> Self {
        Self {
            content: v.content,
            auth: v.auth,
            membership_tag: None,
        }
    }
}

impl PublicMessage {
    /// Build an [`PublicMessage`].
    pub(crate) fn new(
        content: FramedContent,
        auth: FramedContentAuthData,
        membership_tag: Option<MembershipTag>,
    ) -> Self {
        Self {
            content,
            auth,
            membership_tag,
        }
    }

    /// Returns the [`ContentType`] of the message.
    pub(crate) fn content_type(&self) -> ContentType {
        self.content.body.content_type()
    }

    /// Get the sender of this message.
    pub(crate) fn sender(&self) -> &Sender {
        &self.content.sender
    }

    /// Adds a membership tag to this `PublicMessage`. The membership_tag is
    /// produced using the the membership secret.
    ///
    /// This should be used after signing messages from group members.
    pub(crate) fn set_membership_tag(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        membership_key: &MembershipKey,
        serialized_context: &[u8],
    ) -> Result<(), LibraryError> {
        let tbs_payload = FramedContentTbs::new_and_serialize_detached(
            ProtocolVersion::default(),
            WireFormat::PublicMessage,
            &self.content,
            Some(serialized_context),
        )
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
        serialized_context: &[u8],
    ) -> Result<(), ValidationError> {
        log::debug!("Verifying membership tag.");
        log_crypto!(trace, "  Membership key: {:x?}", membership_key);
        log_crypto!(trace, "  Serialized context: {:x?}", serialized_context);
        let tbs_payload = FramedContentTbs::new_and_serialize_detached(
            ProtocolVersion::default(),
            WireFormat::PublicMessage,
            &self.content,
            Some(serialized_context),
        )
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
        self.content.epoch
    }

    /// Get the [`GroupId`].
    pub(crate) fn group_id(&self) -> &GroupId {
        &self.content.group_id
    }

    /// Turn this [`PublicMessage`] into a [`VerifiableAuthenticatedContent`].
    pub(crate) fn into_verifiable_content(
        self,
        serialized_context: impl Into<Option<Vec<u8>>>,
    ) -> VerifiableAuthenticatedContent {
        VerifiableAuthenticatedContent::new(
            WireFormat::PublicMessage,
            self.content,
            serialized_context,
            self.auth,
        )
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn set_membership_tag_test(&mut self, membership_tag: MembershipTag) {
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
        FramedContentTbs {
            version: ProtocolVersion::default(),
            wire_format: WireFormat::PublicMessage,
            content: v.content,
            serialized_context: None,
        }
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
            mls_content: &mls_content.content,
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

        Ok(PublicMessage::new(content, auth, membership_tag))
    }
}

impl Size for PublicMessage {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.content.tls_serialized_len()
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
        let mut written = self.content.tls_serialize(writer)?;
        written += self.auth.tls_serialize(writer)?;
        written += if let Some(membership_tag) = &self.membership_tag {
            membership_tag.tls_serialize(writer)?
        } else {
            0
        };
        Ok(written)
    }
}
