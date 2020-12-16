use super::*;

use std::collections::HashMap;
use std::convert::TryFrom;

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
        indexed_members: HashMap<LeafIndex, &Credential>,
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
        let (ratchet_key, mut ratchet_nonce) = match secret_tree.secret_for_decryption(
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
        let credential = match indexed_members.get(&sender_data.sender) {
            Some(c) => c,
            None => {
                return Err(MLSCiphertextError::UnknownSender);
            }
        };

        let serialized_context = context.encode_detached().unwrap();
        assert!(mls_plaintext.verify(Some(serialized_context), credential));
        Ok(mls_plaintext)
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        self.content_type.is_handshake_message()
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

#[derive(Clone)]
pub(crate) struct MLSSenderData {
    pub(crate) sender: LeafIndex,
    pub(crate) generation: u32,
    pub(crate) reuse_guard: ReuseGuard,
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
pub(crate) struct MLSCiphertextSenderDataAAD {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) content_type: ContentType,
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

#[derive(Clone)]
pub(crate) struct MLSCiphertextContent {
    pub(crate) content: MLSPlaintextContentType,
    pub(crate) signature: Signature,
    pub(crate) padding: Vec<u8>,
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

#[derive(Clone)]
pub(crate) struct MLSCiphertextContentAAD {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) content_type: ContentType,
    pub(crate) authenticated_data: Vec<u8>,
}
