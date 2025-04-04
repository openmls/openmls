//! # PublicMessageIn
//!
//! A PublicMessageIn is a framing structure for MLS messages. It can contain
//! Proposals, Commits and application messages.

use crate::{error::LibraryError, group::errors::ValidationError, versions::ProtocolVersion};

use super::{
    mls_auth_content::FramedContentAuthData,
    mls_auth_content_in::{AuthenticatedContentIn, VerifiableAuthenticatedContentIn},
    mls_content::{framed_content_tbs_serialized_detached, AuthenticatedContentTbm},
    mls_content_in::FramedContentIn,
    *,
};

use openmls_traits::types::Ciphersuite;
use std::io::{Read, Write};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

/// [`PublicMessageIn`] is a framing structure for MLS messages. It can contain
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
pub struct PublicMessageIn {
    pub(crate) content: FramedContentIn,
    pub(crate) auth: FramedContentAuthData,
    pub(crate) membership_tag: Option<MembershipTag>,
}

#[cfg(any(test, feature = "test-utils"))]
impl PublicMessageIn {
    pub(crate) fn content(&self) -> &crate::framing::mls_content_in::FramedContentBodyIn {
        &self.content.body
    }
}

#[cfg(test)]
impl PublicMessageIn {
    pub fn set_confirmation_tag(&mut self, confirmation_tag: Option<ConfirmationTag>) {
        self.auth.confirmation_tag = confirmation_tag;
    }

    pub fn unset_membership_tag(&mut self) {
        self.membership_tag = None;
    }

    pub(crate) fn set_content(&mut self, content: FramedContentBodyIn) {
        self.content.body = content;
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.content.epoch = epoch.into();
    }

    /// Set the sender.
    pub(crate) fn set_sender(&mut self, sender: Sender) {
        self.content.sender = sender;
    }
}

impl From<AuthenticatedContentIn> for PublicMessageIn {
    fn from(v: AuthenticatedContentIn) -> Self {
        Self {
            content: v.content,
            auth: v.auth,
            membership_tag: None,
        }
    }
}

impl PublicMessageIn {
    /// Build an [`PublicMessageIn`].
    pub(crate) fn new(
        content: FramedContentIn,
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
    pub fn content_type(&self) -> ContentType {
        self.content.body.content_type()
    }

    /// Get the sender of this message.
    pub fn sender(&self) -> &Sender {
        &self.content.sender
    }

    #[cfg(test)]
    pub(crate) fn set_membership_tag(
        &mut self,
        provider: &impl openmls_traits::OpenMlsProvider,
        ciphersuite: Ciphersuite,
        membership_key: &MembershipKey,
        serialized_context: &[u8],
    ) -> Result<(), LibraryError> {
        let tbs_payload = framed_content_tbs_serialized_detached(
            ProtocolVersion::default(),
            WireFormat::PublicMessage,
            &self.content,
            &self.content.sender,
            serialized_context,
        )
        .map_err(LibraryError::missing_bound_check)?;
        let tbm_payload = AuthenticatedContentTbm::new(&tbs_payload, &self.auth)?;
        let membership_tag =
            membership_key.tag_message(provider.crypto(), ciphersuite, tbm_payload)?;

        self.membership_tag = Some(membership_tag);
        Ok(())
    }

    /// Verify the membership tag of a [`PublicMessage`] sent from a group
    /// member. Returns `Ok(())` if successful or [`ValidationError`] otherwise.
    /// Note, that the context must have been set before calling this function.
    // TODO #133: Include this in the validation
    pub(crate) fn verify_membership(
        &self,
        crypto: &impl openmls_traits::crypto::OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        membership_key: &MembershipKey,
        serialized_context: &[u8],
    ) -> Result<(), ValidationError> {
        log::debug!("Verifying membership tag.");
        log_crypto!(trace, "  Membership key: {:x?}", membership_key);
        log_crypto!(trace, "  Serialized context: {:x?}", serialized_context);
        let tbs_payload = framed_content_tbs_serialized_detached(
            ProtocolVersion::default(),
            WireFormat::PublicMessage,
            &self.content,
            &self.content.sender,
            serialized_context,
        )
        .map_err(LibraryError::missing_bound_check)?;
        let tbm_payload = AuthenticatedContentTbm::new(&tbs_payload, &self.auth)?;
        let expected_membership_tag =
            &membership_key.tag_message(crypto, ciphersuite, tbm_payload)?;

        // Verify the membership tag
        // https://validation.openmls.tech/#valn1302
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
    pub fn epoch(&self) -> GroupEpoch {
        self.content.epoch
    }

    /// Get the [`GroupId`].
    pub fn group_id(&self) -> &GroupId {
        &self.content.group_id
    }

    /// Turn this [`PublicMessageIn`] into a [`VerifiableAuthenticatedContent`].
    pub(crate) fn into_verifiable_content(
        self,
        serialized_context: impl Into<Option<Vec<u8>>>,
    ) -> VerifiableAuthenticatedContentIn {
        VerifiableAuthenticatedContentIn::new(
            WireFormat::PublicMessage,
            self.content,
            serialized_context,
            self.auth,
        )
    }

    /// Get the [`MembershipTag`].
    pub(crate) fn membership_tag(&self) -> Option<&MembershipTag> {
        self.membership_tag.as_ref()
    }

    /// Get the [`ConfirmationTag`].
    pub fn confirmation_tag(&self) -> Option<&ConfirmationTag> {
        self.auth.confirmation_tag.as_ref()
    }
}

#[cfg(test)]
impl From<PublicMessageIn> for FramedContentTbsIn {
    fn from(v: PublicMessageIn) -> Self {
        FramedContentTbsIn {
            version: ProtocolVersion::default(),
            wire_format: WireFormat::PublicMessage,
            content: v.content,
            serialized_context: None,
        }
    }
}

impl<'a> TryFrom<&'a PublicMessageIn> for InterimTranscriptHashInput<'a> {
    type Error = &'static str;

    fn try_from(public_message: &'a PublicMessageIn) -> Result<Self, Self::Error> {
        match public_message.auth.confirmation_tag.as_ref() {
            Some(confirmation_tag) => Ok(InterimTranscriptHashInput { confirmation_tag }),
            None => Err("PublicMessage needs to contain a confirmation tag."),
        }
    }
}

impl TlsDeserializeTrait for PublicMessageIn {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        let content = FramedContentIn::tls_deserialize(bytes)?;
        let auth = FramedContentAuthData::deserialize(bytes, content.body.content_type())?;
        let membership_tag = if content.sender.is_member() {
            Some(MembershipTag::tls_deserialize(bytes)?)
        } else {
            None
        };

        Ok(PublicMessageIn::new(content, auth, membership_tag))
    }
}

impl DeserializeBytes for PublicMessageIn {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let message = PublicMessageIn::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[message.tls_serialized_len()..];
        Ok((message, remainder))
    }
}

impl Size for PublicMessageIn {
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

impl TlsSerializeTrait for PublicMessageIn {
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

// The following `From` implementation( breaks abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
#[cfg(any(feature = "test-utils", test))]
impl From<PublicMessageIn> for PublicMessage {
    fn from(v: PublicMessageIn) -> Self {
        PublicMessage {
            content: v.content.into(),
            auth: v.auth,
            membership_tag: v.membership_tag,
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<PublicMessage> for PublicMessageIn {
    fn from(v: PublicMessage) -> Self {
        PublicMessageIn {
            content: v.content.into(),
            auth: v.auth,
            membership_tag: v.membership_tag,
        }
    }
}
