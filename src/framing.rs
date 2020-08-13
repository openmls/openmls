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
use crate::messages::*;
use crate::schedule::*;
use crate::tree::astree::*;
use crate::utils::*;

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
        key_pair: &SignatureKeypair,
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
            content_type: ContentType::from(content.clone()),
            content,
            signature: Signature::new_empty(),
        };
        mls_plaintext.sign(key_pair, context);
        mls_plaintext
    }
    pub fn sign(&mut self, key_pair: &SignatureKeypair, context: &GroupContext) {
        let signature_input = MLSPlaintextTBS::new_from(&self, context);
        self.signature = signature_input.sign(key_pair);
    }
    pub fn verify(&self, context: &GroupContext, credential: &Credential) -> bool {
        let signature_input = MLSPlaintextTBS::new_from(&self, context);
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

impl MLSCiphertext {
    fn compute_handshake_key(
        config: &GroupConfig,
        epoch_secrets: &EpochSecrets,
        sender_data: &MLSSenderData,
        mls_plaintext: Option<&MLSPlaintext>,
        ciphersuite: &Ciphersuite,
    ) -> (AEADKey, Nonce) {
        let sender_id = match mls_plaintext {
            Some(mls_plaintext) => mls_plaintext.sender.encode_detached().unwrap(),
            None => sender_data.sender.as_u32().encode_detached().unwrap(),
        };
        let mut handshake_nonce_input = hkdf_expand_label(
            config.ciphersuite,
            &epoch_secrets.handshake_secret,
            "hs nonce",
            &sender_id,
            config.ciphersuite.aead_nonce_length(),
        );
        let reuse_guard = sender_data.reuse_guard.encode_detached().unwrap();
        for i in 0..4 {
            handshake_nonce_input[i] ^= reuse_guard[i];
        }
        let handshake_nonce = ciphersuite.new_aead_nonce(&handshake_nonce_input).unwrap();
        let handshake_key_input = hkdf_expand_label(
            config.ciphersuite,
            &epoch_secrets.handshake_secret,
            "hs key",
            &sender_id,
            config.ciphersuite.aead_key_length(),
        );
        let handshake_key = ciphersuite.new_aead_key(&handshake_key_input).unwrap();
        (handshake_key, handshake_nonce)
    }
    pub fn new_from_plaintext(
        mls_plaintext: &MLSPlaintext,
        astree: &mut ASTree,
        epoch_secrets: &EpochSecrets,
        context: &GroupContext,
        config: GroupConfig,
    ) -> MLSCiphertext {
        let ciphersuite = config.ciphersuite;
        let generation = astree.get_generation(mls_plaintext.sender.sender);
        let application_secrets = astree
            .get_secret(mls_plaintext.sender.sender, generation)
            .unwrap();
        match mls_plaintext.content_type {
            ContentType::Application => {}
            ContentType::Commit => {}
            ContentType::Proposal => {}
            _ => {}
        }
        let sender_data = MLSSenderData::new(mls_plaintext.sender.sender, generation);
        let sender_data_key_bytes = hkdf_expand_label(
            ciphersuite,
            &epoch_secrets.sender_data_secret,
            "sd key",
            &[],
            ciphersuite.aead_key_length(),
        );
        let sender_data_nonce = ciphersuite.new_aead_nonce_random();
        let sender_data_key = ciphersuite.new_aead_key(&sender_data_key_bytes).unwrap();
        let mls_ciphertext_sender_data_aad = MLSCiphertextSenderDataAAD {
            group_id: context.group_id.clone(),
            epoch: context.epoch,
            content_type: mls_plaintext.content_type,
            authenticated_data: mls_plaintext.authenticated_data.to_vec(),
            sender_data_nonce: sender_data_nonce.as_slice().to_vec(),
        };
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
        let mut padding_length = (config.padding_block_size as usize)
            - (padding_offset % (config.padding_block_size as usize));
        if (config.padding_block_size as usize) == padding_length {
            padding_length = 0;
        }
        let padding_block = vec![0u8; padding_length];
        let mls_ciphertext_content = MLSCiphertextContent {
            content: mls_plaintext.content.clone(),
            signature: mls_plaintext.signature.clone(),
            padding: padding_block,
        };

        let (k1, n1) = Self::compute_handshake_key(
            &config,
            epoch_secrets,
            &sender_data,
            Some(mls_plaintext),
            &ciphersuite,
        );
        let (key, nonce) = match mls_plaintext.content_type {
            ContentType::Application => (
                application_secrets.get_key(),
                application_secrets.get_nonce(),
            ),
            _ => (&k1, &n1),
        };
        let ciphertext = ciphersuite
            .aead_seal(
                &mls_ciphertext_content.encode_detached().unwrap(),
                &mls_ciphertext_content_aad_bytes,
                key,
                nonce,
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
        roster: &[Credential],
        epoch_secrets: &EpochSecrets,
        astree: &mut ASTree,
        context: &GroupContext,
        config: GroupConfig,
    ) -> MLSPlaintext {
        let ciphersuite = config.ciphersuite;
        let sender_data_nonce = ciphersuite.new_aead_nonce(&self.sender_data_nonce).unwrap();
        let sender_data_key_bytes = hkdf_expand_label(
            config.ciphersuite,
            &epoch_secrets.sender_data_secret,
            "sd key",
            &[],
            ciphersuite.aead_key_length(),
        );
        let sender_data_key = ciphersuite.new_aead_key(&sender_data_key_bytes).unwrap();
        let mls_ciphertext_sender_data_aad = MLSCiphertextSenderDataAAD {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            content_type: self.content_type,
            authenticated_data: self.authenticated_data.clone(),
            sender_data_nonce: sender_data_nonce.as_slice().to_vec(),
        };
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
        let sender_data = MLSSenderData::decode_detached(&sender_data_bytes).unwrap();
        let application_secrets = astree
            .get_secret(sender_data.sender, sender_data.generation)
            .unwrap();
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
        let (k1, n1) =
            Self::compute_handshake_key(&config, epoch_secrets, &sender_data, None, &ciphersuite);
        let (key, nonce) = match self.content_type {
            ContentType::Application => (
                application_secrets.get_key(),
                application_secrets.get_nonce(),
            ),
            _ => (&k1, &n1),
        };
        let mls_ciphertext_content_bytes = ciphersuite
            .aead_open(
                &self.ciphertext,
                &mls_ciphertext_content_aad_bytes,
                key,
                nonce,
            )
            .unwrap();
        let mls_ciphertext_content =
            MLSCiphertextContent::decode_detached(&mls_ciphertext_content_bytes).unwrap();
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
        let credential = &roster.get(sender_data.sender.as_usize()).unwrap();
        assert!(mls_plaintext.verify(context, credential));
        mls_plaintext
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum SenderType {
    Invalid = 0,
    Member = 1,
    Preconfigured = 2,
    NewMember = 3,
    Default = 255,
}

impl From<u8> for SenderType {
    fn from(value: u8) -> Self {
        match value {
            0 => SenderType::Invalid,
            1 => SenderType::Member,
            2 => SenderType::Preconfigured,
            3 => SenderType::NewMember,
            _ => SenderType::Default,
        }
    }
}

impl Codec for SenderType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(SenderType::from(u8::decode(cursor)?))
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub struct Sender {
    pub sender_type: SenderType,
    pub sender: LeafIndex,
}

impl Sender {
    pub fn member(sender: LeafIndex) -> Self {
        Sender {
            sender_type: SenderType::Member,
            sender,
        }
    }
    pub fn as_tree_index(self) -> NodeIndex {
        NodeIndex::from(self.sender)
    }
}

impl Codec for Sender {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.sender_type.encode(buffer)?;
        self.sender.as_u32().encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let sender_type = SenderType::decode(cursor)?;
        let sender = LeafIndex::from(u32::decode(cursor)?);
        Ok(Sender {
            sender_type,
            sender,
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

impl From<MLSPlaintextContentType> for ContentType {
    fn from(value: MLSPlaintextContentType) -> Self {
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
    Commit((Commit, Confirmation)),
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
            MLSPlaintextContentType::Commit((commit, confirmation)) => {
                ContentType::Commit.encode(buffer)?;
                commit.encode(buffer)?;
                confirmation.encode(buffer)?;
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
                let confirmation = Confirmation::decode(cursor)?;
                Ok(MLSPlaintextContentType::Commit((commit, confirmation)))
            }
            _ => Err(CodecError::DecodingError),
        }
    }
}

pub struct MLSPlaintextTBS {
    pub context: GroupContext,
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub sender: LeafIndex,
    pub authenticated_data: Vec<u8>,
    pub content_type: ContentType,
    pub payload: MLSPlaintextContentType,
}

impl MLSPlaintextTBS {
    pub fn new_from(mls_plaintext: &MLSPlaintext, context: &GroupContext) -> Self {
        MLSPlaintextTBS {
            context: context.clone(),
            group_id: mls_plaintext.group_id.clone(),
            epoch: mls_plaintext.epoch,
            sender: mls_plaintext.sender.sender,
            authenticated_data: mls_plaintext.authenticated_data.clone(),
            content_type: mls_plaintext.content_type,
            payload: mls_plaintext.content.clone(),
        }
    }
    pub fn sign(&self, key_pair: &SignatureKeypair) -> Signature {
        let bytes = self.encode_detached().unwrap();
        key_pair.sign(&bytes)
    }
    pub fn verify(&self, credential: &Credential, signature: &Signature) -> bool {
        let bytes = self.encode_detached().unwrap();
        credential.verify(&bytes, &signature)
    }
}

impl Codec for MLSPlaintextTBS {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.context.encode(buffer)?;
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.sender.as_u32().encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        self.content_type.encode(buffer)?;
        self.payload.encode(buffer)?;
        Ok(())
    }
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
}

#[derive(Clone)]
pub struct MLSSenderData {
    pub sender: LeafIndex,
    pub generation: u32,
    pub reuse_guard: u32,
}

impl Codec for MLSSenderData {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.sender.as_u32().encode(buffer)?;
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
pub struct MLSCiphertextSenderDataAAD {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>,
    pub sender_data_nonce: Vec<u8>,
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
        Ok(MLSCiphertextSenderDataAAD {
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

impl Codec for MLSCiphertextContent {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.content.encode(buffer)?;
        self.signature.encode(buffer)?;
        encode_vec(VecSize::VecU16, buffer, &self.padding)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let content = MLSPlaintextContentType::decode(cursor)?;
        let signature = Signature::decode(cursor)?;
        let padding = decode_vec(VecSize::VecU16, cursor)?;
        Ok(MLSCiphertextContent {
            content,
            signature,
            padding,
        })
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
}

impl From<MLSPlaintext> for MLSPlaintextCommitContent {
    fn from(mls_plaintext: MLSPlaintext) -> Self {
        let commit = match mls_plaintext.content {
            MLSPlaintextContentType::Commit((commit, _confirmation)) => commit,
            _ => panic!("MLSPlaintext needs to contain a Commit"),
        };
        MLSPlaintextCommitContent {
            group_id: mls_plaintext.group_id,
            epoch: mls_plaintext.epoch,
            sender: mls_plaintext.sender,
            content_type: mls_plaintext.content_type,
            commit,
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
    pub confirmation: Vec<u8>,
    pub signature: Vec<u8>,
}

impl From<MLSPlaintext> for MLSPlaintextCommitAuthData {
    fn from(mls_plaintext: MLSPlaintext) -> Self {
        let confirmation = match mls_plaintext.content {
            MLSPlaintextContentType::Commit((_commit, confirmation)) => confirmation,
            _ => panic!("MLSPlaintext needs to contain a Commit"),
        };
        MLSPlaintextCommitAuthData {
            confirmation: confirmation.0,
            signature: mls_plaintext.signature.as_slice().to_vec(),
        }
    }
}

impl Codec for MLSPlaintextCommitAuthData {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.confirmation)?;
        encode_vec(VecSize::VecU16, buffer, &self.signature)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let confirmation = decode_vec(VecSize::VecU8, cursor)?;
        let signature = decode_vec(VecSize::VecU16, cursor)?;
        Ok(MLSPlaintextCommitAuthData {
            confirmation,
            signature,
        })
    }
}

#[test]
fn codec() {
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let keypair = ciphersuite.new_signature_keypair();
    let sender = Sender {
        sender_type: SenderType::Member,
        sender: LeafIndex::from(2u32),
    };
    let mut orig = MLSPlaintext {
        group_id: GroupId::random(),
        epoch: GroupEpoch(1u64),
        sender,
        authenticated_data: vec![1, 2, 3],
        content_type: ContentType::Application,
        content: MLSPlaintextContentType::Application(vec![4, 5, 6]),
        signature: Signature::new_empty(),
    };
    let context = GroupContext {
        group_id: GroupId::random(),
        epoch: GroupEpoch(1u64),
        tree_hash: vec![],
        confirmed_transcript_hash: vec![],
    };
    let signature_input = MLSPlaintextTBS::new_from(&orig, &context);
    orig.signature = signature_input.sign(&keypair);

    let enc = orig.encode_detached().unwrap();
    let copy = MLSPlaintext::decode_detached(&enc).unwrap();
    assert_eq!(orig, copy);
}
