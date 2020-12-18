use super::*;

/// 9. Message framing
///
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
/// } MLSPlaintext;
///
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
    pub fn new(
        sender: LeafIndex,
        authenticated_data: &[u8],
        content: MLSPlaintextContentType,
        credential_bundle: &CredentialBundle,
        context: &GroupContext,
    ) -> Self {
        let sender = Sender {
            sender_type: SenderType::Member,
            sender,
        };
        let mut mls_plaintext = MLSPlaintext {
            group_id: context.group_id.clone(),
            epoch: context.epoch,
            sender,
            authenticated_data: authenticated_data.to_vec(),
            content_type: ContentType::from(&content),
            content,
            signature: Signature::new_empty(),
        };
        let serialized_context = context.encode_detached().unwrap();
        mls_plaintext.sign(credential_bundle, Some(serialized_context));
        mls_plaintext
    }

    /// Returns a reference to the `content` field
    pub fn content(&self) -> &MLSPlaintextContentType {
        &self.content
    }

    /// Get the sender leaf index of this message.
    pub fn sender(&self) -> LeafIndex {
        self.sender.to_leaf_index()
    }

    /// Sign this `MLSPlaintext`.
    pub fn sign(
        &mut self,
        credential_bundle: &CredentialBundle,
        serialized_context_option: Option<Vec<u8>>,
    ) {
        let signature_input = MLSPlaintextTBS::new_from(&self, serialized_context_option);
        self.signature = signature_input.sign(credential_bundle);
    }
    pub fn verify(
        &self,
        serialized_context_option: Option<Vec<u8>>,
        credential: &Credential,
    ) -> bool {
        let signature_input = MLSPlaintextTBS::new_from(&self, serialized_context_option);
        signature_input.verify(credential, &self.signature)
    }
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

    /// Get the group ID.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Get the group ID.
    pub fn epoch(&self) -> &GroupEpoch {
        &self.epoch
    }
}

#[derive(PartialEq, Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentType {
    Invalid = 0,
    Application = 1,
    Proposal = 2,
    Commit = 3,
    Default = 255,
}

impl From<u8> for ContentType {
    fn from(value: u8) -> Self {
        match value {
            0 => ContentType::Invalid,
            1 => ContentType::Application,
            2 => ContentType::Proposal,
            3 => ContentType::Commit,
            _ => ContentType::Default,
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
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum MLSPlaintextContentType {
    Application(Vec<u8>),
    Proposal(Proposal),
    Commit((Commit, ConfirmationTag)),
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
///
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub(crate) struct Mac {
    pub(crate) mac_value: Vec<u8>,
}

/// 9.1 Content Authentication
///
/// struct {
///   MLSPlaintextTBS tbs;
///   opaque signature<0..2^16-1>;
///   optional<MAC> confirmation_tag;
/// } MLSPlaintextTBM;
pub(crate) struct MLSPlaintextTBM {
    pub(crate) tbs: MLSPlaintextTBS,
    pub(crate) signature: Signature,
    pub(crate) confirmation_tag: Option<ConfirmationTag>,
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
    pub fn new(
        ciphersuite: &Ciphersuite,
        membership_key: &Secret,
        mls_plaintext_tbm: MLSPlaintextTBM,
    ) -> Self {
        MembershipTag(
            ciphersuite
                .mac(
                    membership_key,
                    &Secret::from(mls_plaintext_tbm.encode_detached().unwrap()),
                )
                .into(),
        )
    }

    /*
    /// Get a copy of the raw byte vector.
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    */
}

pub(crate) struct MLSPlaintextTBS {
    pub(crate) serialized_context_option: Option<Vec<u8>>,
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) sender: LeafIndex,
    pub(crate) authenticated_data: Vec<u8>,
    pub(crate) content_type: ContentType,
    pub(crate) payload: MLSPlaintextContentType,
}

impl MLSPlaintextTBS {
    pub fn new_from(
        mls_plaintext: &MLSPlaintext,
        serialized_context_option: Option<Vec<u8>>,
    ) -> Self {
        MLSPlaintextTBS {
            serialized_context_option,
            group_id: mls_plaintext.group_id.clone(),
            epoch: mls_plaintext.epoch,
            sender: mls_plaintext.sender.sender,
            authenticated_data: mls_plaintext.authenticated_data.clone(),
            content_type: mls_plaintext.content_type,
            payload: mls_plaintext.content.clone(),
        }
    }
    pub fn sign(&self, credential_bundle: &CredentialBundle) -> Signature {
        let bytes = self.encode_detached().unwrap();
        credential_bundle.sign(&bytes).unwrap()
    }
    pub fn verify(&self, credential: &Credential, signature: &Signature) -> bool {
        let bytes = self.encode_detached().unwrap();
        credential.verify(&bytes, &signature)
    }
}

pub(crate) struct MLSPlaintextCommitContent {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) sender: Sender,
    pub(crate) content_type: ContentType,
    pub(crate) commit: Commit,
}

impl MLSPlaintextCommitContent {
    pub(crate) fn new(group_context: &GroupContext, sender: LeafIndex, commit: Commit) -> Self {
        MLSPlaintextCommitContent {
            group_id: group_context.group_id.clone(),
            epoch: group_context.epoch,
            sender: Sender::member(sender),
            content_type: ContentType::Commit,
            commit,
        }
    }
    pub(crate) fn serialize(&self) -> Vec<u8> {
        self.encode_detached().unwrap()
    }
}

impl From<&MLSPlaintext> for MLSPlaintextCommitContent {
    fn from(mls_plaintext: &MLSPlaintext) -> Self {
        let commit = match &mls_plaintext.content {
            MLSPlaintextContentType::Commit((commit, _confirmation_tag)) => commit,
            _ => panic!("MLSPlaintext needs to contain a Commit"),
        };
        MLSPlaintextCommitContent {
            group_id: mls_plaintext.group_id.clone(),
            epoch: mls_plaintext.epoch,
            sender: mls_plaintext.sender,
            content_type: mls_plaintext.content_type,
            commit: commit.clone(),
        }
    }
}

pub(crate) struct MLSPlaintextCommitAuthData {
    pub(crate) confirmation_tag: Vec<u8>,
}

impl MLSPlaintextCommitAuthData {
    pub(crate) fn serialize(&self) -> Vec<u8> {
        self.encode_detached().unwrap()
    }
}

impl From<&MLSPlaintext> for MLSPlaintextCommitAuthData {
    fn from(mls_plaintext: &MLSPlaintext) -> Self {
        let confirmation_tag = match &mls_plaintext.content {
            MLSPlaintextContentType::Commit((_commit, confirmation_tag)) => confirmation_tag,
            _ => panic!("MLSPlaintext needs to contain a Commit"),
        };
        MLSPlaintextCommitAuthData {
            confirmation_tag: confirmation_tag.0.mac_value.clone(),
        }
    }
}

impl From<&ConfirmationTag> for MLSPlaintextCommitAuthData {
    fn from(confirmation_tag: &ConfirmationTag) -> Self {
        MLSPlaintextCommitAuthData {
            confirmation_tag: confirmation_tag.0.mac_value.clone(),
        }
    }
}
