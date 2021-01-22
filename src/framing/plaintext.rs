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
pub struct MLSPlaintext {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) sender: Sender,
    pub(crate) authenticated_data: Vec<u8>,
    pub(crate) content_type: ContentType,
    pub(crate) content: MLSPlaintextContentType,
    pub(crate) signature: Signature,
    pub(crate) confirmation_tag: Option<ConfirmationTag>,
    pub(crate) membership_tag: Option<MembershipTag>,
}

impl MLSPlaintext {
    /// This constructor builds a new `MLSPlaintext` from the parameters
    /// provided. It is only used internally.
    pub(crate) fn new_from_member(
        sender_index: LeafIndex,
        authenticated_data: &[u8],
        content: MLSPlaintextContentType,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
    ) -> Result<Self, CodecError> {
        let sender = Sender::member(sender_index);

        let mut mls_plaintext = MLSPlaintext {
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

    /// This constructor builds an `MLSPlaintext` containing a Proposal.
    /// The sender type is always `SenderType::Member`.
    pub fn new_from_proposal_member(
        ciphersuite: &Ciphersuite,
        sender_index: LeafIndex,
        authenticated_data: &[u8],
        proposal: Proposal,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        membership_key: &MembershipKey,
    ) -> Result<Self, CodecError> {
        let content = MLSPlaintextContentType::Proposal(proposal);
        let mut mls_plaintext = Self::new_from_member(
            sender_index,
            authenticated_data,
            content,
            credential_bundle,
            context,
        )?;
        mls_plaintext.add_membership_tag(ciphersuite, context.serialized(), membership_key)?;
        Ok(mls_plaintext)
    }

    /// This constructor builds an `MLSPlaintext` containing an application
    /// message. The sender type is always `SenderType::Member`.
    pub fn new_from_application(
        ciphersuite: &Ciphersuite,
        sender_index: LeafIndex,
        authenticated_data: &[u8],
        application_message: &[u8],
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        membership_key: &MembershipKey,
    ) -> Result<Self, CodecError> {
        let content = MLSPlaintextContentType::Application(application_message.to_vec());
        let mut mls_plaintext = Self::new_from_member(
            sender_index,
            authenticated_data,
            content,
            credential_bundle,
            context,
        )?;
        mls_plaintext.add_membership_tag(ciphersuite, context.serialized(), membership_key)?;
        Ok(mls_plaintext)
    }

    /// Returns a reference to the `content` field.
    pub fn content(&self) -> &MLSPlaintextContentType {
        &self.content
    }

    /// Get the sender leaf index of this message.
    pub fn sender(&self) -> LeafIndex {
        self.sender.to_leaf_index()
    }

    /// Sign this `MLSPlaintext`. This populates the
    /// `signature` field. The signature is produced from
    /// the private key conatined in the credential bundle.
    ///
    /// This should be used when signing messages from external parties.
    pub fn sign_from_external(&mut self, credential_bundle: &CredentialBundle) {
        let tbs_payload = MLSPlaintextTBSPayload::new_from_mls_plaintext(&self, None);
        self.signature = tbs_payload.sign(credential_bundle);
    }

    /// Sign this `MLSPlaintext` and add a membership tag. This populates the
    /// `signature` and `membership_tag` fields. The signature is produced from
    /// the private key conatined in the credential bundle, and the
    /// membership_tag is produced using the the membership secret.
    ///
    /// This should be used to sign messages from group members.
    pub fn sign_from_member(
        &mut self,
        credential_bundle: &CredentialBundle,
        serialized_context: &[u8],
    ) -> Result<(), CodecError> {
        let tbs_payload = MLSPlaintextTBS::new_from(&self, Some(serialized_context));
        self.signature = tbs_payload.sign(credential_bundle)?;
        Ok(())
    }

    /// Adds a membership tag to this `MLSPlaintext`. The membership_tag is
    /// produced using the the membership secret.
    ///
    /// This should be used after signing messages from group members.
    pub fn add_membership_tag(
        &mut self,
        ciphersuite: &Ciphersuite,
        serialized_context: &[u8],
        membership_key: &MembershipKey,
    ) -> Result<(), CodecError> {
        let tbs_payload = MLSPlaintextTBS::new_from(&self, Some(serialized_context));

        let tbm_payload =
            MLSPlaintextTBMPayload::new(&tbs_payload, &self.signature, &self.confirmation_tag)?;
        let membership_tag = MembershipTag::new(ciphersuite, membership_key, tbm_payload)?;

        self.membership_tag = Some(membership_tag);
        Ok(())
    }

    /// Verify the signature of an `MLSPlaintext` sent from an external party.
    /// Returns `Ok(())` if successful or `VerificationError` otherwise.
    pub fn verify_signature(
        &self,
        serialized_context: &[u8],
        credential: &Credential,
    ) -> Result<(), VerificationError> {
        let tbs_payload = MLSPlaintextTBS::new_from(&self, Some(serialized_context));
        tbs_payload.verify(credential, &self.signature)
    }

    /// Verify the membership tag of an `MLSPlaintext` sent from member.
    /// Returns `Ok(())` if successful or `VerificationError` otherwise.
    // TODO #133: Include this in the validation
    pub fn verify_membership_tag(
        &self,
        ciphersuite: &Ciphersuite,
        serialized_context: &[u8],
        membership_key: &MembershipKey,
    ) -> Result<(), VerificationError> {
        let tbs_payload = MLSPlaintextTBS::new_from(&self, Some(serialized_context));
        let tbm_payload =
            MLSPlaintextTBMPayload::new(&tbs_payload, &self.signature, &self.confirmation_tag)
                .map_err(VerificationError::CodecError)?;
        let expected_membership_tag =
            &MembershipTag::new(ciphersuite, membership_key, tbm_payload)?;

        // Verify the membership tag
        if let Some(membership_tag) = &self.membership_tag {
            if membership_tag != expected_membership_tag {
                Err(VerificationError::InvalidMembershipTag)
            } else {
                Ok(())
            }
        } else {
            Err(VerificationError::MissingMembershipTag)
        }
    }

    /// Verify the signature and the membership tag of an `MLSPlaintext` sent
    /// from a group member. Returns `Ok(())` if successful or
    /// `VerificationError` otherwise.
    // TODO #133: Include this in the validation
    pub fn verify_from_member(
        &self,
        ciphersuite: &Ciphersuite,
        serialized_context: &[u8],
        credential: &Credential,
        membership_key: &MembershipKey,
    ) -> Result<(), VerificationError> {
        // Verify the signature first
        let tbs_payload = MLSPlaintextTBS::new_from(&self, Some(serialized_context));
        let signature_result = tbs_payload.verify(credential, &self.signature);

        let tbm_payload =
            MLSPlaintextTBMPayload::new(&tbs_payload, &self.signature, &self.confirmation_tag)
                .map_err(VerificationError::CodecError)?;
        let expected_membership_tag =
            &MembershipTag::new(ciphersuite, membership_key, tbm_payload)?;

        // Verify the membership tag
        if let Some(membership_tag) = &self.membership_tag {
            // TODO #133: make this a constant-time comparison
            if membership_tag != expected_membership_tag {
                Err(VerificationError::InvalidMembershipTag)
            } else {
                // If the tags are equal we just return the signature result
                signature_result
            }
        } else {
            Err(VerificationError::MissingMembershipTag)
        }
    }

    /// Tries to extract an application messages from an `MLSPlaintext`. Returns
    /// `MLSPlaintextError::NotAnApplicationMessage` if the `MLSPlaintext`
    /// contained something other than an application message.
    pub fn as_application_message(&self) -> Result<&[u8], MLSPlaintextError> {
        match &self.content {
            MLSPlaintextContentType::Application(message) => Ok(message),
            _ => Err(MLSPlaintextError::NotAnApplicationMessage),
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

impl From<&MLSPlaintextContentType> for ContentType {
    fn from(value: &MLSPlaintextContentType) -> Self {
        match value {
            MLSPlaintextContentType::Application(_) => ContentType::Application,
            MLSPlaintextContentType::Proposal(_) => ContentType::Proposal,
            MLSPlaintextContentType::Commit(_) => ContentType::Commit,
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
pub enum MLSPlaintextContentType {
    Application(Vec<u8>),
    Proposal(Proposal),
    Commit(Commit),
}

impl MLSPlaintextContentType {
    pub(crate) fn to_proposal(&self) -> &Proposal {
        match self {
            MLSPlaintextContentType::Proposal(proposal) => proposal,
            _ => panic!("Library error. Expected Proposal in MLSPlaintextContentType"),
        }
    }
}

/// 9.2 Message framing
///
/// struct {
///     opaque mac_value<0..255>;
/// } MAC;
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub(crate) struct Mac {
    pub(crate) mac_value: Vec<u8>,
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
pub(crate) struct MLSPlaintextTBMPayload<'a> {
    tbs_payload: Vec<u8>,
    pub(crate) signature: &'a Signature,
    pub(crate) confirmation_tag: &'a Option<ConfirmationTag>,
}

impl<'a> MLSPlaintextTBMPayload<'a> {
    pub(crate) fn new(
        tbs_payload: &MLSPlaintextTBS,
        signature: &'a Signature,
        confirmation_tag: &'a Option<ConfirmationTag>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            tbs_payload: tbs_payload.encode_detached()?,
            signature,
            confirmation_tag,
        })
    }
    fn into_bytes(self) -> Result<Vec<u8>, CodecError> {
        let mut buffer = self.tbs_payload;
        buffer.extend(self.signature.encode_detached()?.iter());
        buffer.extend(self.confirmation_tag.encode_detached()?.iter());
        Ok(buffer)
    }
}

impl From<Vec<u8>> for Mac {
    fn from(mac_value: Vec<u8>) -> Self {
        Self { mac_value }
    }
}

impl From<Mac> for Vec<u8> {
    fn from(mac: Mac) -> Self {
        mac.mac_value
    }
}

/// Wrapper around a `Mac` used for type safety.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct MembershipTag(pub(crate) Mac);

impl MembershipTag {
    /// Create a new membership tag.
    ///
    /// 9.1 Content Authentication
    ///
    /// ```text
    /// membership_tag = MAC(membership_key, MLSPlaintextTBM);
    /// ```
    pub(crate) fn new(
        ciphersuite: &Ciphersuite,
        membership_key: &MembershipKey,
        tbm_payload: MLSPlaintextTBMPayload,
    ) -> Result<Self, CodecError> {
        Ok(MembershipTag(
            ciphersuite
                .mac(
                    membership_key.secret(),
                    &Secret::from(tbm_payload.into_bytes()?),
                )
                .into(),
        ))
    }
}

#[derive(Debug)]
pub struct MLSPlaintextTBS<'a> {
    pub(crate) serialized_context_option: Option<&'a [u8]>,
    pub(crate) group_id: &'a GroupId,
    pub(crate) epoch: &'a GroupEpoch,
    pub(crate) sender: &'a Sender,
    pub(crate) authenticated_data: &'a [u8],
    pub(crate) content_type: &'a ContentType,
    pub(crate) payload: &'a MLSPlaintextContentType,
}

impl<'a> MLSPlaintextTBS<'a> {
    pub fn new_from(
        mls_plaintext: &'a MLSPlaintext,
        serialized_context_option: Option<&'a [u8]>,
    ) -> Self {
        MLSPlaintextTBS {
            serialized_context_option,
            group_id: &mls_plaintext.group_id,
            epoch: &mls_plaintext.epoch,
            sender: &mls_plaintext.sender,
            authenticated_data: &mls_plaintext.authenticated_data,
            content_type: &mls_plaintext.content_type,
            payload: &mls_plaintext.content,
        }
    }
    pub(crate) fn sign(
        &self,
        credential_bundle: &CredentialBundle,
    ) -> Result<Signature, CodecError> {
        let bytes = self.encode_detached()?;
        // Unwrapping here is safe, because signatures would only fail due to a bad
        // implementation of the crypto primitive
        Ok(credential_bundle.sign(&bytes).unwrap())
    }
    pub(crate) fn verify(
        &self,
        credential: &Credential,
        signature: &Signature,
    ) -> Result<(), VerificationError> {
        let bytes = self.encode_detached()?;
        if credential.verify(&bytes, &signature) {
            Ok(())
        } else {
            Err(VerificationError::InvalidSignature)
        }
    }
}

pub(crate) struct MLSPlaintextTBSPayload {
    payload: Vec<u8>,
}

impl<'a> MLSPlaintextTBSPayload {
    pub(crate) fn new_from_mls_plaintext(
        mls_plaintext: &MLSPlaintext,
        serialized_context_option: Option<&'a [u8]>,
    ) -> Self {
        let tbs = MLSPlaintextTBS::new_from(mls_plaintext, serialized_context_option);
        Self {
            payload: tbs.encode_detached().unwrap(),
        }
    }
    pub(crate) fn sign(&self, credential_bundle: &CredentialBundle) -> Signature {
        credential_bundle.sign(&self.payload).unwrap()
    }
}

pub(crate) struct MLSPlaintextCommitContent<'a> {
    pub(crate) group_id: &'a GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) sender: &'a Sender,
    pub(crate) content_type: ContentType,
    pub(crate) commit: &'a Commit,
    pub(crate) signature: &'a Signature,
}

impl<'a> TryFrom<&'a MLSPlaintext> for MLSPlaintextCommitContent<'a> {
    type Error = &'static str;

    fn try_from(mls_plaintext: &'a MLSPlaintext) -> Result<Self, Self::Error> {
        let commit = match &mls_plaintext.content {
            MLSPlaintextContentType::Commit(commit) => commit,
            _ => return Err("MLSPlaintext needs to contain a Commit."),
        };
        Ok(MLSPlaintextCommitContent {
            group_id: &mls_plaintext.group_id,
            epoch: mls_plaintext.epoch,
            sender: &mls_plaintext.sender,
            content_type: mls_plaintext.content_type,
            commit,
            signature: &mls_plaintext.signature,
        })
    }
}

pub(crate) struct MLSPlaintextCommitAuthData<'a> {
    pub(crate) confirmation_tag: &'a ConfirmationTag,
}

impl<'a> TryFrom<&'a MLSPlaintext> for MLSPlaintextCommitAuthData<'a> {
    type Error = &'static str;

    fn try_from(mls_plaintext: &'a MLSPlaintext) -> Result<Self, Self::Error> {
        let confirmation_tag = match &mls_plaintext.confirmation_tag {
            Some(confirmation_tag) => confirmation_tag,
            None => return Err("MLSPlaintext needs to contain a confirmation tag."),
        };
        Ok(MLSPlaintextCommitAuthData { confirmation_tag })
    }
}

impl<'a> From<&'a ConfirmationTag> for MLSPlaintextCommitAuthData<'a> {
    fn from(confirmation_tag: &'a ConfirmationTag) -> Self {
        MLSPlaintextCommitAuthData { confirmation_tag }
    }
}
