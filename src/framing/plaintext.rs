use super::*;
use std::convert::TryFrom;

/// `MLSPlaintext` is a framing structure for MLS messages. It can contain
/// Proposals, Commits and application messages.
///
/// 9. Message framing
///
/// ```c
/// struct {
/// opaque group_id<0..255>;
/// uint64 epoch;
/// Sender sender;
/// opaque authenticated_data<0..2^32-1>;
///
/// ContentType content_type;
/// select (MLSPlaintext.content_type) {
///     case application:
///       opaque application_data<0..2^32-1>;
///
///     case proposal:
///       Proposal proposal;
///
///     case commit:
///       Commit commit;
/// }
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
    /// provided. It is ony used internally.
    fn new_from_member(
        ciphersuite: &Ciphersuite,
        sender_index: LeafIndex,
        authenticated_data: &[u8],
        content: MLSPlaintextContentType,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        membership_key: &Secret,
    ) -> Self {
        let sender = Sender::member(sender_index);

        let mut mls_plaintext = MLSPlaintext {
            group_id: context.group_id.clone(),
            epoch: context.epoch,
            sender,
            authenticated_data: authenticated_data.to_vec(),
            content_type: ContentType::from(&content),
            content,
            signature: Signature::new_empty(),
            confirmation_tag: None,
            membership_tag: None,
        };

        let serialized_context = context.encode_detached().unwrap();
        mls_plaintext.sign_and_mac(
            ciphersuite,
            credential_bundle,
            serialized_context,
            membership_key,
        );
        mls_plaintext
    }

    /// This contructor builds an `MLSPlaintext` containing a Proposal.
    /// The sender type is always `SenderType::Member`.
    pub fn new_from_proposal_member(
        ciphersuite: &Ciphersuite,
        sender_index: LeafIndex,
        authenticated_data: &[u8],
        proposal: Proposal,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        membership_key: &Secret,
    ) -> Self {
        let content = MLSPlaintextContentType::Proposal(proposal);
        Self::new_from_member(
            ciphersuite,
            sender_index,
            authenticated_data,
            content,
            credential_bundle,
            context,
            membership_key,
        )
    }

    /// This contructor builds an `MLSPlaintext` containing an application
    /// message. The sender type is always `SenderType::Member`.
    pub fn new_from_application(
        ciphersuite: &Ciphersuite,
        sender_index: LeafIndex,
        authenticated_data: &[u8],
        application_message: Vec<u8>,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
        membership_key: &Secret,
    ) -> Self {
        let content = MLSPlaintextContentType::Application(application_message);
        Self::new_from_member(
            ciphersuite,
            sender_index,
            authenticated_data,
            content,
            credential_bundle,
            context,
            membership_key,
        )
    }

    /// Returns a reference to the `content` field
    pub fn content(&self) -> &MLSPlaintextContentType {
        &self.content
    }

    /// Get the sender leaf index of this message.
    pub fn sender(&self) -> LeafIndex {
        self.sender.to_leaf_index()
    }

    /// Sign this `MLSPlaintext` without using a group context
    pub fn sign(&mut self, credential_bundle: &CredentialBundle) {
        let tbs_payload = MLSPlaintextTBSPayload::new_from_mls_plaintext(&self, None);
        self.signature = tbs_payload.sign(credential_bundle);
    }

    /// Sign this `MLSPlaintext` and add a membership tag
    pub fn sign_and_mac(
        &mut self,
        ciphersuite: &Ciphersuite,
        credential_bundle: &CredentialBundle,
        serialized_context: Vec<u8>,
        membership_key: &Secret,
    ) {
        let tbs_payload =
            MLSPlaintextTBSPayload::new_from_mls_plaintext(&self, Some(serialized_context));
        self.signature = tbs_payload.sign(credential_bundle);
        let tbm_payload = MLSPlaintextTBMPayload::new(tbs_payload, &self);
        self.membership_tag = Some(MembershipTag::new(ciphersuite, membership_key, tbm_payload));
    }

    /// Verify the signature of the `MLSPlaintext`.
    pub fn verify_signature(
        &self,
        serialized_context_option: Option<Vec<u8>>,
        credential: &Credential,
    ) -> bool {
        let signature_input = MLSPlaintextTBS::new_from(&self, serialized_context_option);
        signature_input.verify(credential, &self.signature)
    }

    /// Verify the membership tag of the `MLSPlaintext`. Returns `true` if the
    /// verification is successful and `false` otherwise.
    pub fn verify_membership_tag(
        &self,
        ciphersuite: &Ciphersuite,
        serialized_context: Vec<u8>,
        membership_key: &Secret,
    ) -> bool {
        let tbs_payload =
            MLSPlaintextTBSPayload::new_from_mls_plaintext(&self, Some(serialized_context));
        let tbm_payload = MLSPlaintextTBMPayload::new(tbs_payload, &self);
        let expected_membership_tag = &MembershipTag::new(ciphersuite, membership_key, tbm_payload);

        if let Some(membership_tag) = &self.membership_tag {
            membership_tag == expected_membership_tag
        } else {
            false
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
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ContentType::Application),
            2 => Ok(ContentType::Proposal),
            3 => Ok(ContentType::Commit),
            _ => Err("Unknown content type for MLSPlaintext."),
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
/// opaque mac_value<0..255>;
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
pub(crate) struct MLSPlaintextTBMPayload<'a> {
    tbs_payload: MLSPlaintextTBSPayload,
    pub(crate) signature: &'a Signature,
    pub(crate) confirmation_tag: &'a Option<ConfirmationTag>,
}

impl<'a> MLSPlaintextTBMPayload<'a> {
    pub(crate) fn new(
        tbs_payload: MLSPlaintextTBSPayload,
        mls_plaintext: &'a MLSPlaintext,
    ) -> Self {
        Self {
            tbs_payload,
            signature: &mls_plaintext.signature,
            confirmation_tag: &mls_plaintext.confirmation_tag,
        }
    }
    fn into_bytes(self) -> Vec<u8> {
        let mut buffer = self.tbs_payload.payload;
        buffer.extend(self.signature.encode_detached().unwrap().iter());
        buffer.extend(self.confirmation_tag.encode_detached().unwrap().iter());
        buffer
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
        membership_key: &Secret,
        mls_plaintext_tbm_payload: MLSPlaintextTBMPayload,
    ) -> Self {
        MembershipTag(
            ciphersuite
                .mac(
                    membership_key,
                    &Secret::from(mls_plaintext_tbm_payload.into_bytes()),
                )
                .into(),
        )
    }
}

pub struct MLSPlaintextTBS<'a> {
    pub(crate) serialized_context_option: Option<Vec<u8>>,
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
        serialized_context_option: Option<Vec<u8>>,
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
    #[cfg(test)]
    pub(crate) fn sign(&self, credential_bundle: &CredentialBundle) -> Signature {
        let bytes = self.encode_detached().unwrap();
        credential_bundle.sign(&bytes).unwrap()
    }
    pub fn verify(&self, credential: &Credential, signature: &Signature) -> bool {
        let bytes = self.encode_detached().unwrap();
        credential.verify(&bytes, &signature)
    }
}

pub(crate) struct MLSPlaintextTBSPayload {
    payload: Vec<u8>,
}

impl MLSPlaintextTBSPayload {
    pub(crate) fn new_from_mls_plaintext(
        mls_plaintext: &MLSPlaintext,
        serialized_context_option: Option<Vec<u8>>,
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
