use crate::ciphersuite::*;
use crate::codec::*;
use crate::creds::*;
use crate::group::*;
use crate::messages::{proposals::*, *};
use crate::schedule::*;
use crate::tree::{index::*, secret_tree::*};

use std::convert::TryFrom;

pub mod errors;
pub mod sender;
pub(crate) use errors::*;
use sender::*;

#[cfg(test)]
mod test_framing;

#[derive(Debug, PartialEq, Clone)]
pub struct MLSPlaintext {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) sender: Sender,
    pub(crate) authenticated_data: Vec<u8>,
    pub(crate) content_type: ContentType,
    pub content: MLSPlaintextContentType,
    pub(crate) signature: Signature,
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
    // XXX: Only used in tests right now.
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = Cursor::new(bytes);
        let group_id = GroupId::decode(&mut cursor).unwrap();
        let epoch = GroupEpoch::decode(&mut cursor).unwrap();
        let sender = Sender::decode(&mut cursor).unwrap();
        let authenticated_data = decode_vec(VecSize::VecU32, &mut cursor).unwrap();
        let content_type = ContentType::decode(&mut cursor).unwrap();
        let content = MLSPlaintextContentType::decode(&mut cursor).unwrap();
        let signature = Signature::decode(&mut cursor).unwrap();

        Ok(MLSPlaintext {
            group_id,
            epoch,
            sender,
            authenticated_data,
            content_type,
            content,
            signature,
        })
    }
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
}

impl Codec for MLSPlaintext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.sender.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        self.content_type.encode(buffer)?;
        self.content.encode(buffer)?;
        self.signature.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let sender = Sender::decode(cursor)?;
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let content = MLSPlaintextContentType::decode(cursor)?;
        let signature = Signature::decode(cursor)?;

        Ok(MLSPlaintext {
            group_id,
            epoch,
            sender,
            authenticated_data,
            content_type,
            content,
            signature,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct MLSCiphertext {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>,
    pub encrypted_sender_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl MLSCiphertext {
    // pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
    //     let mut cursor = Cursor::new(bytes);
    //     let group_id = GroupId::decode(&mut cursor)?;
    //     let epoch = GroupEpoch::decode(&mut cursor)?;
    //     let content_type = ContentType::decode(&mut cursor)?;
    //     let authenticated_data = decode_vec(VecSize::VecU32, &mut cursor)?;
    //     let sender_data_nonce = decode_vec(VecSize::VecU8, &mut cursor)?;
    //     let encrypted_sender_data = decode_vec(VecSize::VecU8, &mut cursor)?;
    //     let ciphertext = decode_vec(VecSize::VecU32, &mut cursor)?;
    //     Ok(MLSCiphertext {
    //         group_id,
    //         epoch,
    //         content_type,
    //         authenticated_data,
    //         sender_data_nonce,
    //         encrypted_sender_data,
    //         ciphertext,
    //     })
    // }
    pub fn as_slice(&self) -> Vec<u8> {
        self.encode_detached().unwrap()
    }

    pub fn new_from_plaintext(
        mls_plaintext: &MLSPlaintext,
        mls_group: &MlsGroup,
        generation: u32,
        ratchet_key: AeadKey,
        mut ratchet_nonce: AeadNonce,
    ) -> MLSCiphertext {
        let ciphersuite = mls_group.ciphersuite();
        let context = mls_group.context();
        let epoch_secrets = mls_group.epoch_secrets();
        let mls_ciphertext_content_aad = MLSCiphertextContentAAD {
            group_id: context.group_id.clone(),
            epoch: context.epoch,
            content_type: mls_plaintext.content_type,
            authenticated_data: mls_plaintext.authenticated_data.to_vec(),
        };
        let mls_ciphertext_content_aad_bytes =
            mls_ciphertext_content_aad.encode_detached().unwrap(); // TODO: error handling;

        // Sample reuse guard uniformly at random.
        let reuse_guard: ReuseGuard = ReuseGuard::from_random();
        // Prepare the nonce by xoring with the reuse guard.
        ratchet_nonce.xor_with_reuse_guard(&reuse_guard);
        let ciphertext = ratchet_key
            .aead_seal(
                &Self::encode_padded_ciphertext_content_detached(mls_plaintext).unwrap(),
                &mls_ciphertext_content_aad_bytes,
                &ratchet_nonce,
            )
            .unwrap();
        // Derive key from the key schedule using the ciphertext.
        let sender_data_key = AeadKey::from_sender_data_secret(
            ciphersuite,
            &ciphertext,
            epoch_secrets.sender_data_secret(),
        );
        // Derive initial nonce from the key schedule using the ciphertext.
        let sender_data_nonce = AeadNonce::from_sender_data_secret(
            ciphersuite,
            &ciphertext,
            epoch_secrets.sender_data_secret(),
        );
        // Compute sender data nonce by xoring reuse guard and key schedule
        // nonce as per spec.
        let mls_ciphertext_sender_data_aad = MLSCiphertextSenderDataAAD::new(
            context.group_id.clone(),
            context.epoch,
            mls_plaintext.content_type,
        );
        let mls_ciphertext_sender_data_aad_bytes =
            mls_ciphertext_sender_data_aad.encode_detached().unwrap(); // TODO: error handling
        let sender_data = MLSSenderData::new(mls_plaintext.sender.sender, generation, reuse_guard);
        let encrypted_sender_data = sender_data_key
            .aead_seal(
                &sender_data.encode_detached().unwrap(),
                &mls_ciphertext_sender_data_aad_bytes,
                &sender_data_nonce,
            )
            .unwrap();
        MLSCiphertext {
            group_id: context.group_id.clone(),
            epoch: context.epoch,
            content_type: mls_plaintext.content_type,
            authenticated_data: mls_plaintext.authenticated_data.to_vec(),
            encrypted_sender_data,
            ciphertext,
        }
    }

    pub(crate) fn to_plaintext(
        &self,
        ciphersuite: &Ciphersuite,
        roster: &[&Credential],
        epoch_secrets: &EpochSecrets,
        secret_tree: &mut SecretTree,
        context: &GroupContext,
    ) -> Result<MLSPlaintext, MLSCiphertextError> {
        // Derive key from the key schedule using the ciphertext.
        let sender_data_key = AeadKey::from_sender_data_secret(
            ciphersuite,
            &self.ciphertext,
            epoch_secrets.sender_data_secret(),
        );
        // Derive initial nonce from the key schedule using the ciphertext.
        let sender_data_nonce = AeadNonce::from_sender_data_secret(
            ciphersuite,
            &self.ciphertext,
            epoch_secrets.sender_data_secret(),
        );
        let mls_ciphertext_sender_data_aad =
            MLSCiphertextSenderDataAAD::new(self.group_id.clone(), self.epoch, self.content_type);
        let mls_ciphertext_sender_data_aad_bytes =
            mls_ciphertext_sender_data_aad.encode_detached().unwrap();
        let sender_data_bytes = &sender_data_key
            .aead_open(
                &self.encrypted_sender_data,
                &mls_ciphertext_sender_data_aad_bytes,
                &sender_data_nonce,
            )
            .unwrap();
        let sender_data = MLSSenderData::from_bytes(&sender_data_bytes).unwrap();
        let secret_type = match SecretType::try_from(&self.content_type) {
            Ok(secret_type) => secret_type,
            Err(_) => return Err(MLSCiphertextError::InvalidContentType),
        };
        let (ratchet_key, mut ratchet_nonce) = match secret_tree.get_secret_for_decryption(
            ciphersuite,
            sender_data.sender,
            secret_type,
            sender_data.generation,
        ) {
            Ok(ratchet_secrets) => ratchet_secrets,
            Err(_) => return Err(MLSCiphertextError::GenerationOutOfBound),
        };
        ratchet_nonce.xor_with_reuse_guard(&sender_data.reuse_guard);
        let mls_ciphertext_content_aad = MLSCiphertextContentAAD {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            content_type: self.content_type,
            authenticated_data: self.authenticated_data.clone(),
        };
        let mls_ciphertext_content_aad_bytes =
            mls_ciphertext_content_aad.encode_detached().unwrap();
        let mls_ciphertext_content_bytes = ratchet_key
            .aead_open(
                &self.ciphertext,
                &mls_ciphertext_content_aad_bytes,
                &ratchet_nonce,
            )
            .unwrap();
        let mls_ciphertext_content =
            MLSCiphertextContent::from_bytes(&mls_ciphertext_content_bytes).unwrap();
        let sender = Sender {
            sender_type: SenderType::Member,
            sender: sender_data.sender,
        };
        let mls_plaintext = MLSPlaintext {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            sender,
            authenticated_data: self.authenticated_data.clone(),
            content_type: self.content_type,
            content: mls_ciphertext_content.content,
            signature: mls_ciphertext_content.signature,
        };
        let credential = roster.get(sender_data.sender.as_usize()).unwrap();
        let serialized_context = context.encode_detached().unwrap();
        assert!(mls_plaintext.verify(Some(serialized_context), credential));
        Ok(mls_plaintext)
    }

    fn encode_padded_ciphertext_content_detached(
        mls_plaintext: &MLSPlaintext,
    ) -> Result<Vec<u8>, CodecError> {
        let mut buffer = vec![];
        mls_plaintext.content.encode(&mut buffer)?;
        mls_plaintext.signature.encode(&mut buffer)?;
        let padding_offset = buffer.len() + 2 + TAG_BYTES;
        // TODO: The PADDING SIZE should be retrieved from the config.
        const PADDING_SIZE: usize = 10;
        let mut padding_length = PADDING_SIZE - (padding_offset % PADDING_SIZE);
        if PADDING_SIZE == padding_length {
            padding_length = 0;
        }
        let padding_block = vec![0u8; padding_length];
        encode_vec(VecSize::VecU16, &mut buffer, &padding_block)?;
        Ok(buffer)
    }
}

impl Codec for MLSCiphertext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.content_type.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        encode_vec(VecSize::VecU8, buffer, &self.encrypted_sender_data)?;
        encode_vec(VecSize::VecU32, buffer, &self.ciphertext)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        let encrypted_sender_data = decode_vec(VecSize::VecU8, cursor)?;
        let ciphertext = decode_vec(VecSize::VecU32, cursor)?;
        Ok(MLSCiphertext {
            group_id,
            epoch,
            content_type,
            authenticated_data,
            encrypted_sender_data,
            ciphertext,
        })
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
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

impl Codec for ContentType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(ContentType::from(u8::decode(cursor)?))
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone)]
pub enum MLSPlaintextContentType {
    Application(Vec<u8>),
    Proposal(Proposal),
    Commit((Commit, ConfirmationTag)),
}

impl Codec for MLSPlaintextContentType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            MLSPlaintextContentType::Application(application_data) => {
                ContentType::Application.encode(buffer)?;
                encode_vec(VecSize::VecU32, buffer, application_data)?;
            }
            MLSPlaintextContentType::Proposal(proposal) => {
                ContentType::Proposal.encode(buffer)?;
                proposal.encode(buffer)?;
            }
            MLSPlaintextContentType::Commit((commit, confirmation_tag)) => {
                ContentType::Commit.encode(buffer)?;
                commit.encode(buffer)?;
                confirmation_tag.encode(buffer)?;
            }
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let content_type = ContentType::from(u8::decode(cursor)?);
        match content_type {
            ContentType::Application => {
                let application_data = decode_vec(VecSize::VecU32, cursor)?;
                Ok(MLSPlaintextContentType::Application(application_data))
            }
            ContentType::Proposal => {
                let proposal = Proposal::decode(cursor)?;
                Ok(MLSPlaintextContentType::Proposal(proposal))
            }
            ContentType::Commit => {
                let commit = Commit::decode(cursor)?;
                let confirmation_tag = ConfirmationTag::decode(cursor)?;
                Ok(MLSPlaintextContentType::Commit((commit, confirmation_tag)))
            }
            _ => Err(CodecError::DecodingError),
        }
    }
}

struct MLSPlaintextTBS {
    serialized_context_option: Option<Vec<u8>>,
    group_id: GroupId,
    epoch: GroupEpoch,
    sender: LeafIndex,
    authenticated_data: Vec<u8>,
    content_type: ContentType,
    payload: MLSPlaintextContentType,
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

impl Codec for MLSPlaintextTBS {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        if let Some(ref serialized_context) = self.serialized_context_option {
            buffer.extend_from_slice(serialized_context);
        }
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.sender.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        self.content_type.encode(buffer)?;
        self.payload.encode(buffer)?;
        Ok(())
    }
    /*
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let context = GroupContext::decode(cursor)?;
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let sender = LeafIndex::from(u32::decode(cursor)?);
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let payload = MLSPlaintextContentType::decode(cursor)?;

        Ok(MLSPlaintextTBS {
            context,
            group_id,
            epoch,
            sender,
            authenticated_data,
            content_type,
            payload,
        })
    }
    */
}

#[derive(Clone)]
struct MLSSenderData {
    sender: LeafIndex,
    generation: u32,
    reuse_guard: ReuseGuard,
}

impl MLSSenderData {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = Cursor::new(bytes);
        let sender = LeafIndex::from(u32::decode(&mut cursor)?);
        let generation = u32::decode(&mut cursor)?;
        let reuse_guard = ReuseGuard::decode(&mut cursor)?;

        Ok(MLSSenderData {
            sender,
            generation,
            reuse_guard,
        })
    }
}

impl Codec for MLSSenderData {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.sender.encode(buffer)?;
        self.generation.encode(buffer)?;
        self.reuse_guard.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let sender = LeafIndex::from(u32::decode(cursor)?);
        let generation = u32::decode(cursor)?;
        let reuse_guard = ReuseGuard::decode(cursor)?;

        Ok(MLSSenderData {
            sender,
            generation,
            reuse_guard,
        })
    }
}

impl MLSSenderData {
    pub fn new(sender: LeafIndex, generation: u32, reuse_guard: ReuseGuard) -> Self {
        MLSSenderData {
            sender,
            generation,
            reuse_guard,
        }
    }
}

#[derive(Clone)]
struct MLSCiphertextSenderDataAAD {
    group_id: GroupId,
    epoch: GroupEpoch,
    content_type: ContentType,
}

impl MLSCiphertextSenderDataAAD {
    fn new(group_id: GroupId, epoch: GroupEpoch, content_type: ContentType) -> Self {
        Self {
            group_id,
            epoch,
            content_type,
        }
    }
}

impl Codec for MLSCiphertextSenderDataAAD {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.content_type.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        Ok(Self {
            group_id,
            epoch,
            content_type,
        })
    }
}

#[derive(Clone)]
struct MLSCiphertextContent {
    content: MLSPlaintextContentType,
    signature: Signature,
    padding: Vec<u8>,
}

impl MLSCiphertextContent {
    fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = Cursor::new(bytes);
        let content = MLSPlaintextContentType::decode(&mut cursor)?;
        let signature = Signature::decode(&mut cursor)?;
        let padding = decode_vec(VecSize::VecU16, &mut cursor)?;
        Ok(MLSCiphertextContent {
            content,
            signature,
            padding,
        })
    }
}

impl Codec for MLSCiphertextContent {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.content.encode(buffer)?;
        self.signature.encode(buffer)?;
        encode_vec(VecSize::VecU16, buffer, &self.padding)?;
        Ok(())
    }
}

#[derive(Clone)]
struct MLSCiphertextContentAAD {
    group_id: GroupId,
    epoch: GroupEpoch,
    content_type: ContentType,
    authenticated_data: Vec<u8>,
}

impl Codec for MLSCiphertextContentAAD {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.content_type.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        Ok(MLSCiphertextContentAAD {
            group_id,
            epoch,
            content_type,
            authenticated_data,
        })
    }
}

pub(crate) struct MLSPlaintextCommitContent {
    group_id: GroupId,
    epoch: GroupEpoch,
    sender: Sender,
    content_type: ContentType,
    commit: Commit,
}

impl MLSPlaintextCommitContent {
    pub fn new(group_context: &GroupContext, sender: LeafIndex, commit: Commit) -> Self {
        MLSPlaintextCommitContent {
            group_id: group_context.group_id.clone(),
            epoch: group_context.epoch,
            sender: Sender::member(sender),
            content_type: ContentType::Commit,
            commit,
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
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

impl Codec for MLSPlaintextCommitContent {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.sender.encode(buffer)?;
        self.content_type.encode(buffer)?;
        self.commit.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let sender = Sender::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let commit = Commit::decode(cursor)?;
        Ok(MLSPlaintextCommitContent {
            group_id,
            epoch,
            sender,
            content_type,
            commit,
        })
    }
}

pub(crate) struct MLSPlaintextCommitAuthData {
    pub confirmation_tag: Vec<u8>,
}

impl MLSPlaintextCommitAuthData {
    pub fn serialize(&self) -> Vec<u8> {
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
            confirmation_tag: confirmation_tag.0.clone(),
        }
    }
}

impl From<&ConfirmationTag> for MLSPlaintextCommitAuthData {
    fn from(confirmation_tag: &ConfirmationTag) -> Self {
        MLSPlaintextCommitAuthData {
            confirmation_tag: confirmation_tag.to_vec(),
        }
    }
}

impl Codec for MLSPlaintextCommitAuthData {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.confirmation_tag)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let confirmation_tag = decode_vec(VecSize::VecU8, cursor)?;
        Ok(MLSPlaintextCommitAuthData { confirmation_tag })
    }
}
