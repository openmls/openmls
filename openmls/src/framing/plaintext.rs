//! # MlsPlaintext
//!
//! An MlsPlaintext is a framing structure for MLS messages. It can contain
//! Proposals, Commits and application messages.

use crate::{error::LibraryError, group::errors::ValidationError};

use super::{
    mls_auth_content::{MlsAuthContent, MlsContentAuthData, VerifiableMlsAuthContent},
    mls_content::{ContentType, MlsContent, MlsContentTbm, MlsContentTbs},
};

//#[cfg(test)]
//use super::mls_auth_content::MlsContentBody;

use super::*;
use openmls_traits::OpenMlsCryptoProvider;
use std::convert::TryFrom;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// Wrapper around a `Mac` used for type safety.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub(crate) struct MembershipTag(pub(crate) Mac);

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

#[cfg(test)]
impl MlsPlaintext {
    pub fn set_confirmation_tag(&mut self, confirmation_tag: Option<ConfirmationTag>) {
        self.auth.confirmation_tag = confirmation_tag;
    }

    pub fn unset_membership_tag(&mut self) {
        self.membership_tag = None;
    }

    pub fn set_content(&mut self, content: mls_content::MlsContentBody) {
        self.content.body = content;
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.content.epoch = epoch.into();
    }

    pub fn content(&self) -> &mls_content::MlsContentBody {
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
        MlsContentTbs::serialize_plaintext_tbs(
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
