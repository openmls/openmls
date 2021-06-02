use crate::ciphersuite::signable::{Signable, Verifiable};

use super::*;
use std::convert::TryFrom;

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
/// opaque signature<0..2^16-1>;
/// optional<MAC> confirmation_tag;
/// optional<MAC> membership_tag;
/// ```
/// } MLSPlaintext;
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct MlsPlaintext {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) sender: Sender,
    pub(crate) authenticated_data: Vec<u8>,
    pub(crate) content_type: ContentType,
    pub(crate) content: MlsPlaintextContentType,
    pub(crate) signature: Signature,
    pub(crate) confirmation_tag: Option<ConfirmationTag>,
    pub(crate) membership_tag: Option<MembershipTag>,
}

impl MlsPlaintext {
    /// This constructor builds a new `MlsPlaintext` from the parameters
    /// provided. It is only used internally.
    pub(crate) fn new_from_member(
        sender_index: LeafIndex,
        authenticated_data: &[u8],
        content: MlsPlaintextContentType,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
    ) -> Result<Self, MlsPlaintextError> {
        let sender = Sender::member(sender_index);

        let mut mls_plaintext = MlsPlaintext {
            group_id: context.group_id().clone(),
            epoch: context.epoch(),
            sender,
            authenticated_data: authenticated_data.to_vec(),
            content_type: ContentType::from(&content),
            content,
            signature: Signature::new_empty(),
            confirmation_tag: None,
            membership_tag: None,
        };

        let serialized_context = context.serialized();
        mls_plaintext.sign_from_member(credential_bundle, serialized_context)?;
        Ok(mls_plaintext)
    }

    /// This constructor builds an `MlsPlaintext` containing a Proposal.
    /// The sender type is always `SenderType::Member`.
    pub fn new_from_proposal_member(
        sender_index: LeafIndex,
        authenticated_data: &[u8],
        proposal: Proposal,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        membership_key: &MembershipKey,
    ) -> Result<Self, MlsPlaintextError> {
        let content = MlsPlaintextContentType::Proposal(proposal);
        let mut mls_plaintext = Self::new_from_member(
            sender_index,
            authenticated_data,
            content,
            credential_bundle,
            context,
        )?;
        mls_plaintext.add_membership_tag(context.serialized(), membership_key)?;
        Ok(mls_plaintext)
    }

    /// This constructor builds an `MlsPlaintext` containing an application
    /// message. The sender type is always `SenderType::Member`.
    pub fn new_from_application(
        sender_index: LeafIndex,
        authenticated_data: &[u8],
        application_message: &[u8],
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        membership_key: &MembershipKey,
    ) -> Result<Self, MlsPlaintextError> {
        let content = MlsPlaintextContentType::Application(application_message.to_vec());
        let mut mls_plaintext = Self::new_from_member(
            sender_index,
            authenticated_data,
            content,
            credential_bundle,
            context,
        )?;
        mls_plaintext.add_membership_tag(context.serialized(), membership_key)?;
        Ok(mls_plaintext)
    }

    /// Returns a reference to the `content` field.
    pub fn content(&self) -> &MlsPlaintextContentType {
        &self.content
    }

    /// Get the sender leaf index of this message.
    pub fn sender(&self) -> LeafIndex {
        self.sender.to_leaf_index()
    }

    /// Sign this `MlsPlaintext`. This populates the
    /// `signature` field. The signature is produced from
    /// the private key contained in the credential bundle.
    ///
    /// This should be used when signing messages from external parties.
    pub fn sign_from_external(
        &mut self,
        credential_bundle: &CredentialBundle,
    ) -> Result<(), MlsPlaintextError> {
        let tbs_payload = MlsPlaintextTbsPayload::new_from_mls_plaintext(&self, None);
        self.signature = tbs_payload.sign(credential_bundle)?;
        Ok(())
    }

    /// Sign this `MlsPlaintext` and add a membership tag. This populates the
    /// `signature` and `membership_tag` fields. The signature is produced from
    /// the private key contained in the credential bundle, and the
    /// membership_tag is produced using the the membership secret.
    ///
    /// This should be used to sign messages from group members.
    pub fn sign_from_member(
        &mut self,
        credential_bundle: &CredentialBundle,
        serialized_context: &[u8],
    ) -> Result<(), MlsPlaintextError> {
        let tbs_payload = MlsPlaintextTbs::new_from(&self, Some(serialized_context));
        self.signature = tbs_payload.sign(credential_bundle)?;
        Ok(())
    }

    /// Adds a membership tag to this `MlsPlaintext`. The membership_tag is
    /// produced using the the membership secret.
    ///
    /// This should be used after signing messages from group members.
    pub fn add_membership_tag(
        &mut self,
        serialized_context: &[u8],
        membership_key: &MembershipKey,
    ) -> Result<(), MlsPlaintextError> {
        let tbs_payload = MlsPlaintextTbs::new_from(&self, Some(serialized_context));

        let tbm_payload =
            MlsPlaintextTbmPayload::new(&tbs_payload, &self.signature, &self.confirmation_tag)?;
        let membership_tag = membership_key.tag(tbm_payload)?;

        self.membership_tag = Some(membership_tag);
        Ok(())
    }

    /// Verify the signature of an `MlsPlaintext` sent from an external party.
    /// Returns `Ok(())` if successful or `VerificationError` otherwise.
    pub fn verify_signature(
        &self,
        serialized_context: &[u8],
        credential: &Credential,
    ) -> Result<(), VerificationError> {
        let tbs_payload = MlsPlaintextTbs::new_from(&self, Some(serialized_context));
        tbs_payload.verify(credential).map_err(|e| e.into())
    }

    /// Verify the membership tag of an `MlsPlaintext` sent from member.
    /// Returns `Ok(())` if successful or `VerificationError` otherwise.
    // TODO #133: Include this in the validation
    pub fn verify_membership_tag(
        &self,
        ciphersuite: &'static Ciphersuite,
        serialized_context: &[u8],
        membership_key: &MembershipKey,
    ) -> Result<(), MlsPlaintextError> {
        log::debug!("Verifying membership tag {}.", ciphersuite);
        log_crypto!(trace, "  Membership key: {:x?}", membership_key);
        log_crypto!(trace, "  Serialized context: {:x?}", serialized_context);
        let tbs_payload = MlsPlaintextTbs::new_from(&self, Some(serialized_context));
        let tbm_payload =
            MlsPlaintextTbmPayload::new(&tbs_payload, &self.signature, &self.confirmation_tag)?;
        let expected_membership_tag = &membership_key.tag(tbm_payload)?;

        // Verify the membership tag
        if let Some(membership_tag) = &self.membership_tag {
            if membership_tag != expected_membership_tag {
                Err(VerificationError::InvalidMembershipTag.into())
            } else {
                Ok(())
            }
        } else {
            Err(VerificationError::MissingMembershipTag.into())
        }
    }

    /// Verify the signature and the membership tag of an `MlsPlaintext` sent
    /// from a group member. Returns `Ok(())` if successful or
    /// `VerificationError` otherwise.
    // TODO #133: Include this in the validation
    pub fn verify_from_member(
        &self,
        serialized_context: &[u8],
        credential: &Credential,
        membership_key: &MembershipKey,
    ) -> Result<(), MlsPlaintextError> {
        // Verify the signature first
        let tbs_payload = MlsPlaintextTbs::new_from(&self, Some(serialized_context));
        let signature_result = tbs_payload.verify(credential);

        let tbm_payload =
            MlsPlaintextTbmPayload::new(&tbs_payload, &self.signature, &self.confirmation_tag)?;
        let expected_membership_tag = &membership_key.tag(tbm_payload)?;

        // Verify the membership tag
        if let Some(membership_tag) = &self.membership_tag {
            // TODO #133: make this a constant-time comparison
            if membership_tag != expected_membership_tag {
                Err(VerificationError::InvalidMembershipTag.into())
            } else {
                // If the tags are equal we just return the signature result
                signature_result.map_err(|e| e.into())
            }
        } else {
            Err(VerificationError::MissingMembershipTag.into())
        }
    }

    /// Tries to extract an application messages from an `MlsPlaintext`. Returns
    /// `MlsPlaintextError::NotAnApplicationMessage` if the `MlsPlaintext`
    /// contained something other than an application message.
    pub fn as_application_message(&self) -> Result<&[u8], MlsPlaintextError> {
        match &self.content {
            MlsPlaintextContentType::Application(message) => Ok(message),
            _ => Err(MlsPlaintextError::NotAnApplicationMessage),
        }
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        self.content_type.is_handshake_message()
    }

    /// Returns `true` if this is a proposal message and `false` otherwise.
    pub(crate) fn is_proposal(&self) -> bool {
        self.content_type.is_proposal()
    }

    /// Get the group ID.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Get the group ID.
    pub fn epoch(&self) -> &GroupEpoch {
        &self.epoch
    }
}

// === Helper structs ===

#[derive(PartialEq, Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentType {
    Application = 1,
    Proposal = 2,
    Commit = 3,
}

impl TryFrom<u8> for ContentType {
    type Error = CodecError;
    fn try_from(value: u8) -> Result<Self, CodecError> {
        match value {
            1 => Ok(ContentType::Application),
            2 => Ok(ContentType::Proposal),
            3 => Ok(ContentType::Commit),
            _ => Err(CodecError::DecodingError),
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
    pub(crate) fn is_handshake_message(&self) -> bool {
        self == &ContentType::Proposal || self == &ContentType::Commit
    }
    pub(crate) fn is_proposal(&self) -> bool {
        self == &ContentType::Proposal
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum MlsPlaintextContentType {
    Application(Vec<u8>),
    Proposal(Proposal),
    Commit(Commit),
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
    tbs_payload: Vec<u8>,
    pub(crate) signature: &'a Signature,
    pub(crate) confirmation_tag: &'a Option<ConfirmationTag>,
}

impl<'a> MlsPlaintextTbmPayload<'a> {
    pub(crate) fn new(
        tbs_payload: &MlsPlaintextTbs,
        signature: &'a Signature,
        confirmation_tag: &'a Option<ConfirmationTag>,
    ) -> Result<Self, MlsPlaintextError> {
        Ok(Self {
            tbs_payload: tbs_payload.encode_detached()?,
            signature,
            confirmation_tag,
        })
    }
    pub(crate) fn into_bytes(self) -> Result<Vec<u8>, CodecError> {
        let mut buffer = self.tbs_payload;
        buffer.extend(self.signature.encode_detached()?.iter());
        buffer.extend(self.confirmation_tag.encode_detached()?.iter());
        Ok(buffer)
    }
}

/// Wrapper around a `Mac` used for type safety.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct MembershipTag(pub(crate) Mac);

#[derive(Debug)]
pub struct MlsPlaintextTbs<'a> {
    pub(crate) serialized_context_option: Option<&'a [u8]>,
    pub(crate) group_id: &'a GroupId,
    pub(crate) epoch: &'a GroupEpoch,
    pub(crate) sender: &'a Sender,
    pub(crate) authenticated_data: &'a [u8],
    pub(crate) content_type: &'a ContentType,
    pub(crate) payload: &'a MlsPlaintextContentType,
    // We store the signature here as well in order to implement Verifiable.
    signature: &'a Signature,
}

impl<'a> Signable for MlsPlaintextTbs<'a> {
    type SignedOutput = Signature;

    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        self.encode_detached()
    }
}

impl<'a> MlsPlaintextTbs<'a> {
    pub fn new_from(
        mls_plaintext: &'a MlsPlaintext,
        serialized_context_option: Option<&'a [u8]>,
    ) -> Self {
        MlsPlaintextTbs {
            serialized_context_option,
            group_id: &mls_plaintext.group_id,
            epoch: &mls_plaintext.epoch,
            sender: &mls_plaintext.sender,
            authenticated_data: &mls_plaintext.authenticated_data,
            content_type: &mls_plaintext.content_type,
            payload: &mls_plaintext.content,
            signature: &mls_plaintext.signature,
        }
    }
}

// Usually Verifiable and Signable shouldn't be implemented on the same struct.
// In this case however we don't have the serialized context in the MlsPlaintext
// (the object that should actually implement Verifiable).
impl<'a> Verifiable for MlsPlaintextTbs<'a> {
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        self.encode_detached()
    }

    fn signature(&self) -> &Signature {
        self.signature
    }
}

pub(crate) struct MlsPlaintextTbsPayload {
    payload: Vec<u8>,
}

impl<'a> MlsPlaintextTbsPayload {
    pub(crate) fn new_from_mls_plaintext(
        mls_plaintext: &MlsPlaintext,
        serialized_context_option: Option<&'a [u8]>,
    ) -> Self {
        let tbs = MlsPlaintextTbs::new_from(mls_plaintext, serialized_context_option);
        Self {
            payload: tbs.encode_detached().unwrap(),
        }
    }
}

impl Signable for MlsPlaintextTbsPayload {
    type SignedOutput = Signature;

    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.payload.clone())
    }
}

pub(crate) struct MlsPlaintextCommitContent<'a> {
    pub(crate) group_id: &'a GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) sender: &'a Sender,
    pub(crate) authenticated_data: &'a [u8],
    pub(crate) content_type: ContentType,
    pub(crate) commit: &'a Commit,
    pub(crate) signature: &'a Signature,
}

impl<'a> TryFrom<&'a MlsPlaintext> for MlsPlaintextCommitContent<'a> {
    type Error = &'static str;

    fn try_from(mls_plaintext: &'a MlsPlaintext) -> Result<Self, Self::Error> {
        let commit = match &mls_plaintext.content {
            MlsPlaintextContentType::Commit(commit) => commit,
            _ => return Err("MlsPlaintext needs to contain a Commit."),
        };
        Ok(MlsPlaintextCommitContent {
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
