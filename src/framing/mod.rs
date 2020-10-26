// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::ciphersuite::*;
use crate::codec::*;
use crate::creds::*;
use crate::group::*;
use crate::messages::{proposals::*, *};
use crate::schedule::*;
use crate::tree::{index::*, secret_tree::*};
use crate::utils::*;

use std::convert::TryFrom;

pub mod sender;
use sender::*;

#[cfg(test)]
mod test_framing;

pub enum MLSCiphertextError {
    InvalidContentType,
    GenerationOutOfBound,
}

#[derive(Debug, PartialEq, Clone)]
pub struct MLSPlaintext {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub sender: Sender,
    pub authenticated_data: Vec<u8>,
    pub content_type: ContentType,
    pub content: MLSPlaintextContentType,
    pub signature: Signature,
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
        let group_id = GroupId::decode(cursor).unwrap();
        let epoch = GroupEpoch::decode(cursor).unwrap();
        let sender = Sender::decode(cursor).unwrap();
        let authenticated_data = decode_vec(VecSize::VecU32, cursor).unwrap();
        let content_type = ContentType::decode(cursor).unwrap();
        let content = MLSPlaintextContentType::decode(cursor).unwrap();
        let signature = Signature::decode(cursor).unwrap();

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

#[derive(Clone)]
pub struct MLSCiphertext {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>,
    pub sender_data_nonce: Vec<u8>,
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
        ratchet_secrets: &RatchetSecrets,
    ) -> MLSCiphertext {
        const PADDING_SIZE: usize = 10;

        let ciphersuite = mls_group.ciphersuite();
        let context = mls_group.context();
        let epoch_secrets = mls_group.epoch_secrets();
        let sender_data = MLSSenderData::new(mls_plaintext.sender.sender, generation);
        let sender_data_key_bytes = hkdf_expand_label(
            ciphersuite,
            &epoch_secrets.sender_data_secret,
            "sd key",
            &[],
            ciphersuite.aead_key_length(),
        );
        let sender_data_nonce = AeadNonce::random();
        let sender_data_key = AeadKey::from_slice(&sender_data_key_bytes);
        let mls_ciphertext_sender_data_aad = MLSCiphertextSenderDataAAD::new(
            context.group_id.clone(),
            context.epoch,
            mls_plaintext.content_type,
            mls_plaintext.authenticated_data.to_vec(),
            sender_data_nonce.as_slice().to_vec(),
        );
        let mls_ciphertext_sender_data_aad_bytes =
            mls_ciphertext_sender_data_aad.encode_detached().unwrap(); // TODO: error handling
        let encrypted_sender_data = ciphersuite
            .aead_seal(
                &sender_data.encode_detached().unwrap(),
                &mls_ciphertext_sender_data_aad_bytes,
                &sender_data_key,
                &sender_data_nonce,
            )
            .unwrap();
        let mls_ciphertext_content_aad = MLSCiphertextContentAAD {
            group_id: context.group_id.clone(),
            epoch: context.epoch,
            content_type: mls_plaintext.content_type,
            authenticated_data: mls_plaintext.authenticated_data.to_vec(),
            sender_data_nonce: sender_data_nonce.as_slice().to_vec(),
            encrypted_sender_data: encrypted_sender_data.clone(),
        };
        let mls_ciphertext_content_aad_bytes =
            mls_ciphertext_content_aad.encode_detached().unwrap(); // TODO: error handling;
                                                                   // TODO: Clean this mess up
        let padding_offset = context.group_id.encode_detached().unwrap().len()
            + context.epoch.encode_detached().unwrap().len()
            + mls_plaintext.content_type.encode_detached().unwrap().len()
            + mls_plaintext.authenticated_data.len()
            + 4
            + sender_data_nonce.as_slice().len()
            + 1
            + encrypted_sender_data.len()
            + 1
            + mls_plaintext.content.encode_detached().unwrap().len()
            + mls_plaintext.signature.encode_detached().unwrap().len()
            + 2
            + TAG_BYTES
            + 4;
        let mut padding_length = PADDING_SIZE - (padding_offset % PADDING_SIZE);
        if PADDING_SIZE == padding_length {
            padding_length = 0;
        }
        let padding_block = vec![0u8; padding_length];
        let mls_ciphertext_content = MLSCiphertextContent {
            content: mls_plaintext.content.clone(),
            signature: mls_plaintext.signature.clone(),
            padding: padding_block,
        };

        let ciphertext = ciphersuite
            .aead_seal(
                &mls_ciphertext_content.encode_detached().unwrap(),
                &mls_ciphertext_content_aad_bytes,
                ratchet_secrets.get_key(),
                ratchet_secrets.get_nonce(),
            )
            .unwrap();
        MLSCiphertext {
            group_id: context.group_id.clone(),
            epoch: context.epoch,
            content_type: mls_plaintext.content_type,
            authenticated_data: mls_plaintext.authenticated_data.to_vec(),
            sender_data_nonce: sender_data_nonce.as_slice().to_vec(),
            encrypted_sender_data,
            ciphertext,
        }
    }

    pub fn to_plaintext(
        &self,
        ciphersuite: &Ciphersuite,
        roster: &[&Credential],
        epoch_secrets: &EpochSecrets,
        secret_tree: &mut SecretTree,
        context: &GroupContext,
    ) -> Result<MLSPlaintext, MLSCiphertextError> {
        let sender_data_nonce = AeadNonce::from_slice(&self.sender_data_nonce);
        let sender_data_key_bytes = hkdf_expand_label(
            ciphersuite,
            &epoch_secrets.sender_data_secret,
            "sd key",
            &[],
            ciphersuite.aead_key_length(),
        );
        let sender_data_key = AeadKey::from_slice(&sender_data_key_bytes);
        let mls_ciphertext_sender_data_aad = MLSCiphertextSenderDataAAD::new(
            self.group_id.clone(),
            self.epoch,
            self.content_type,
            self.authenticated_data.clone(),
            sender_data_nonce.as_slice().to_vec(),
        );
        let mls_ciphertext_sender_data_aad_bytes =
            mls_ciphertext_sender_data_aad.encode_detached().unwrap();
        let sender_data_bytes = ciphersuite
            .aead_open(
                &self.encrypted_sender_data,
                &mls_ciphertext_sender_data_aad_bytes,
                &sender_data_key,
                &sender_data_nonce,
            )
            .unwrap();
        let sender_data = MLSSenderData::from_bytes(&sender_data_bytes).unwrap();
        let secret_type = match SecretType::try_from(&self.content_type) {
            Ok(secret_type) => secret_type,
            Err(_) => return Err(MLSCiphertextError::InvalidContentType),
        };
        let ratchet_secrets = match secret_tree.get_secret_for_decryption(
            ciphersuite,
            sender_data.sender,
            secret_type,
            sender_data.generation,
        ) {
            Ok(ratchet_secrets) => ratchet_secrets,
            Err(_) => return Err(MLSCiphertextError::GenerationOutOfBound),
        };
        let mls_ciphertext_content_aad = MLSCiphertextContentAAD {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            content_type: self.content_type,
            authenticated_data: self.authenticated_data.clone(),
            sender_data_nonce: sender_data_nonce.as_slice().to_vec(),
            encrypted_sender_data: self.encrypted_sender_data.clone(),
        };
        let mls_ciphertext_content_aad_bytes =
            mls_ciphertext_content_aad.encode_detached().unwrap();
        let mls_ciphertext_content_bytes = ciphersuite
            .aead_open(
                &self.ciphertext,
                &mls_ciphertext_content_aad_bytes,
                ratchet_secrets.get_key(),
                ratchet_secrets.get_nonce(),
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
}

impl Codec for MLSCiphertext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.content_type.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        encode_vec(VecSize::VecU8, buffer, &self.sender_data_nonce)?;
        encode_vec(VecSize::VecU8, buffer, &self.encrypted_sender_data)?;
        encode_vec(VecSize::VecU32, buffer, &self.ciphertext)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        let sender_data_nonce = decode_vec(VecSize::VecU8, cursor)?;
        let encrypted_sender_data = decode_vec(VecSize::VecU8, cursor)?;
        let ciphertext = decode_vec(VecSize::VecU32, cursor)?;
        Ok(MLSCiphertext {
            group_id,
            epoch,
            content_type,
            authenticated_data,
            sender_data_nonce,
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

pub struct MLSPlaintextTBS {
    pub serialized_context_option: Option<Vec<u8>>,
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub sender: LeafIndex,
    pub authenticated_data: Vec<u8>,
    pub content_type: ContentType,
    pub payload: MLSPlaintextContentType,
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
pub struct MLSSenderData {
    pub sender: LeafIndex,
    pub generation: u32,
    pub reuse_guard: u32,
}

impl MLSSenderData {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = Cursor::new(bytes);
        let sender = LeafIndex::from(u32::decode(&mut cursor)?);
        let generation = u32::decode(&mut cursor)?;
        let reuse_guard = u32::decode(&mut cursor)?;

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
        let reuse_guard = u32::decode(cursor)?;

        Ok(MLSSenderData {
            sender,
            generation,
            reuse_guard,
        })
    }
}

impl MLSSenderData {
    pub fn new(sender: LeafIndex, generation: u32) -> Self {
        MLSSenderData {
            sender,
            generation,
            reuse_guard: random_u32(),
        }
    }
}

#[derive(Clone)]
struct MLSCiphertextSenderDataAAD {
    group_id: GroupId,
    epoch: GroupEpoch,
    content_type: ContentType,
    authenticated_data: Vec<u8>,
    sender_data_nonce: Vec<u8>,
}

impl MLSCiphertextSenderDataAAD {
    fn new(
        group_id: GroupId,
        epoch: GroupEpoch,
        content_type: ContentType,
        authenticated_data: Vec<u8>,
        sender_data_nonce: Vec<u8>,
    ) -> Self {
        Self {
            group_id,
            epoch,
            content_type,
            authenticated_data,
            sender_data_nonce,
        }
    }
}

impl Codec for MLSCiphertextSenderDataAAD {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.content_type.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        encode_vec(VecSize::VecU8, buffer, &self.sender_data_nonce)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        let sender_data_nonce = decode_vec(VecSize::VecU8, cursor)?;
        Ok(Self {
            group_id,
            epoch,
            content_type,
            authenticated_data,
            sender_data_nonce,
        })
    }
}

#[derive(Clone)]
pub struct MLSCiphertextContent {
    pub content: MLSPlaintextContentType,
    pub signature: Signature,
    pub padding: Vec<u8>,
}

impl MLSCiphertextContent {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
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
pub struct MLSCiphertextContentAAD {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>,
    pub sender_data_nonce: Vec<u8>,
    pub encrypted_sender_data: Vec<u8>,
}

impl Codec for MLSCiphertextContentAAD {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.content_type.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        encode_vec(VecSize::VecU8, buffer, &self.sender_data_nonce)?;
        encode_vec(VecSize::VecU8, buffer, &self.encrypted_sender_data)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        let sender_data_nonce = decode_vec(VecSize::VecU8, cursor)?;
        let encrypted_sender_data = decode_vec(VecSize::VecU8, cursor)?;
        Ok(MLSCiphertextContentAAD {
            group_id,
            epoch,
            content_type,
            authenticated_data,
            sender_data_nonce,
            encrypted_sender_data,
        })
    }
}

pub struct MLSPlaintextCommitContent {
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

pub struct MLSPlaintextCommitAuthData {
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
            confirmation_tag: confirmation_tag.as_slice(),
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
