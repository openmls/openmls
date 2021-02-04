use super::*;

use std::convert::TryFrom;

/// `MLSCiphertext` is the framing struct for an encrypted `MLSPlaintext`.
/// This message format is meant to be sent to and received from the Delivery
/// Service.
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
    /// Try to create a new `MLSCiphertext` from an `MLSPlaintext`
    pub(crate) fn try_from_plaintext(
        mls_plaintext: &MLSPlaintext,
        ciphersuite: &Ciphersuite,
        context: &GroupContext,
        sender: LeafIndex,
        epoch_secrets: &EpochSecrets,
        secret_tree: &mut SecretTree,
        padding_size: usize,
    ) -> Result<MLSCiphertext, MLSCiphertextError> {
        // Serialize the content AAD
        let mls_ciphertext_content_aad = MLSCiphertextContentAAD {
            group_id: context.group_id().clone(),
            epoch: context.epoch(),
            content_type: mls_plaintext.content_type,
            authenticated_data: mls_plaintext.authenticated_data.to_vec(),
        };
        let mls_ciphertext_content_aad_bytes = mls_ciphertext_content_aad.encode_detached()?;
        // Extract generation and key material for encryption
        let secret_type = SecretType::try_from(mls_plaintext)
            .map_err(|_| MLSCiphertextError::InvalidContentType)?;
        let (generation, (ratchet_key, mut ratchet_nonce)) =
            secret_tree.secret_for_encryption(ciphersuite, sender, secret_type)?;
        // Sample reuse guard uniformly at random.
        let reuse_guard: ReuseGuard = ReuseGuard::from_random();
        // Prepare the nonce by xoring with the reuse guard.
        ratchet_nonce.xor_with_reuse_guard(&reuse_guard);
        // Encrypt the payload
        let ciphertext = ratchet_key
            .aead_seal(
                &Self::encode_padded_ciphertext_content_detached(mls_plaintext, padding_size)?,
                &mls_ciphertext_content_aad_bytes,
                &ratchet_nonce,
            )
            .map_err(|_| MLSCiphertextError::EncryptionError)?;
        // Extract ciphertext sample for key/nonce derivation
        let sample_length = ciphersuite.hash_length();
        let ciphertext_sample = if ciphertext.len() <= sample_length {
            &ciphertext
        } else {
            &ciphertext[0..sample_length]
        };
        // Derive the sender data key from the key schedule using the ciphertext.
        let sender_data_key = AeadKey::from_sender_data_secret(
            ciphersuite,
            ciphertext_sample,
            epoch_secrets.sender_data_secret(),
        );
        // Derive initial nonce from the key schedule using the ciphertext.
        let sender_data_nonce = AeadNonce::from_sender_data_secret(
            ciphersuite,
            ciphertext_sample,
            epoch_secrets.sender_data_secret(),
        );
        // Compute sender data nonce by xoring reuse guard and key schedule
        // nonce as per spec.
        let mls_sender_data_aad = MLSSenderDataAAD::new(
            context.group_id().clone(),
            context.epoch(),
            mls_plaintext.content_type,
        );
        // Serialize the sender data AAD
        let mls_sender_data_aad_bytes = mls_sender_data_aad.encode_detached()?;
        let sender_data = MLSSenderData::new(mls_plaintext.sender.sender, generation, reuse_guard);
        // Encrypt the sender data
        let encrypted_sender_data = sender_data_key
            .aead_seal(
                &sender_data.encode_detached()?,
                &mls_sender_data_aad_bytes,
                &sender_data_nonce,
            )
            .map_err(|_| MLSCiphertextError::EncryptionError)?;
        Ok(MLSCiphertext {
            group_id: context.group_id().clone(),
            epoch: context.epoch(),
            content_type: mls_plaintext.content_type,
            authenticated_data: mls_plaintext.authenticated_data.to_vec(),
            encrypted_sender_data,
            ciphertext: ciphertext.to_vec(),
        })
    }

    pub(crate) fn to_plaintext(
        &self,
        ciphersuite: &Ciphersuite,
        epoch_secrets: &EpochSecrets,
        secret_tree: &mut SecretTree,
    ) -> Result<MLSPlaintext, MLSCiphertextError> {
        // Extract ciphertext sample for key/nonce derivation
        let sample_length = ciphersuite.hash_length();
        let ciphertext_sample = if self.ciphertext.len() <= sample_length {
            &self.ciphertext
        } else {
            &self.ciphertext[0..sample_length]
        };
        // Derive key from the key schedule using the ciphertext.
        let sender_data_key = AeadKey::from_sender_data_secret(
            ciphersuite,
            ciphertext_sample,
            epoch_secrets.sender_data_secret(),
        );
        // Derive initial nonce from the key schedule using the ciphertext.
        let sender_data_nonce = AeadNonce::from_sender_data_secret(
            ciphersuite,
            ciphertext_sample,
            epoch_secrets.sender_data_secret(),
        );
        // Serialize sender data AAD
        let mls_sender_data_aad =
            MLSSenderDataAAD::new(self.group_id.clone(), self.epoch, self.content_type);
        let mls_sender_data_aad_bytes = mls_sender_data_aad.encode_detached()?;
        // Decrypt sender data
        let sender_data_bytes = &sender_data_key
            .aead_open(
                &self.encrypted_sender_data,
                &mls_sender_data_aad_bytes,
                &sender_data_nonce,
            )
            .map_err(|_| MLSCiphertextError::DecryptionError)?;
        let sender_data = MLSSenderData::decode_detached(&sender_data_bytes)?;
        let secret_type = SecretType::try_from(&self.content_type)
            .map_err(|_| MLSCiphertextError::InvalidContentType)?;
        // Extract generation and key material for encryption
        let (ratchet_key, mut ratchet_nonce) = secret_tree
            .secret_for_decryption(
                ciphersuite,
                sender_data.sender,
                secret_type,
                sender_data.generation,
            )
            .map_err(|_| MLSCiphertextError::GenerationOutOfBound)?;
        // Prepare the nonce by xoring with the reuse guard.
        ratchet_nonce.xor_with_reuse_guard(&sender_data.reuse_guard);
        // Serialize content AAD
        let mls_ciphertext_content_aad = MLSCiphertextContentAAD {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            content_type: self.content_type,
            authenticated_data: self.authenticated_data.clone(),
        };
        let mls_ciphertext_content_aad_bytes = mls_ciphertext_content_aad.encode_detached()?;
        // Decrypt payload
        let mls_ciphertext_content_bytes = ratchet_key
            .aead_open(
                &self.ciphertext,
                &mls_ciphertext_content_aad_bytes,
                &ratchet_nonce,
            )
            .map_err(|_| MLSCiphertextError::DecryptionError)?;
        let mls_ciphertext_content =
            MLSCiphertextContent::decode_detached(&mls_ciphertext_content_bytes)?;
        // Extract sender. The sender type is always of type Member for MLSCiphertext.
        let sender = Sender {
            sender_type: SenderType::Member,
            sender: sender_data.sender,
        };
        // Return the MLSPlaintext
        Ok(MLSPlaintext {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            sender,
            authenticated_data: self.authenticated_data.clone(),
            content_type: self.content_type,
            content: mls_ciphertext_content.content,
            signature: mls_ciphertext_content.signature,
            confirmation_tag: mls_ciphertext_content.confirmation_tag,
            membership_tag: None,
        })
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        self.content_type.is_handshake_message()
    }

    /// Encodes the `MLSCiphertextContent` struct with padding
    /// ```c
    /// struct {
    ///     select (MLSCiphertext.content_type) {
    ///         case application:
    ///             opaque application_data<0..2^32-1>;
    ///
    ///         case proposal:
    ///             Proposal proposal;
    ///
    ///         case commit:
    ///             Commit commit;
    /// }
    ///
    /// opaque signature<0..2^16-1>;
    /// optional<MAC> confirmation_tag;
    /// opaque padding<0..2^16-1>;
    /// } MLSCiphertextContent;
    /// ```
    fn encode_padded_ciphertext_content_detached(
        mls_plaintext: &MLSPlaintext,
        padding_size: usize,
    ) -> Result<Vec<u8>, CodecError> {
        // Persist all initial fields manually (avoids cloning them)
        let buffer = &mut Vec::new();
        mls_plaintext.content.encode(buffer)?;
        mls_plaintext.signature.encode(buffer)?;
        mls_plaintext.confirmation_tag.encode(buffer)?;
        // Add padding if needed
        let padding_length = if padding_size > 0 {
            // Calculate padding block size
            // The length of the padding block takes 2 bytes and the AEAD tag is also added.
            let padding_offset = buffer.len() + 2 + TAG_BYTES;
            // Return padding block size
            (padding_size - (padding_offset % padding_size)) % padding_size
        } else {
            0
        };
        let padding_block = vec![0u8; padding_length];
        encode_vec(VecSize::VecU16, buffer, &padding_block)?;
        Ok(buffer.to_vec())
    }
}

// === Helper structs ===

#[derive(Clone)]
pub(crate) struct MLSSenderData {
    pub(crate) sender: LeafIndex,
    pub(crate) generation: u32,
    pub(crate) reuse_guard: ReuseGuard,
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
pub(crate) struct MLSSenderDataAAD {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) content_type: ContentType,
}

impl MLSSenderDataAAD {
    fn new(group_id: GroupId, epoch: GroupEpoch, content_type: ContentType) -> Self {
        Self {
            group_id,
            epoch,
            content_type,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MLSCiphertextContent {
    pub(crate) content: MLSPlaintextContentType,
    pub(crate) signature: Signature,
    pub(crate) confirmation_tag: Option<ConfirmationTag>,
    pub(crate) padding: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct MLSCiphertextContentAAD {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) content_type: ContentType,
    pub(crate) authenticated_data: Vec<u8>,
}
