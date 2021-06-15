use super::*;

use std::convert::TryFrom;

/// `MlsCiphertext` is the framing struct for an encrypted `MlsPlaintext`.
/// This message format is meant to be sent to and received from the Delivery
/// Service.
#[derive(Debug, PartialEq, Clone)]
pub struct MlsCiphertext {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>,
    pub encrypted_sender_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl MlsCiphertext {
    /// Try to create a new `MlsCiphertext` from an `MlsPlaintext`
    pub(crate) fn try_from_plaintext(
        mls_plaintext: &MlsPlaintext,
        ciphersuite: &Ciphersuite,
        context: &GroupContext,
        sender: LeafIndex,
        epoch_secrets: &EpochSecrets,
        secret_tree: &mut SecretTree,
        padding_size: usize,
    ) -> Result<MlsCiphertext, MlsCiphertextError> {
        log::debug!("MlsCiphertext::try_from_plaintext");
        log::trace!("  ciphersuite: {}", ciphersuite);
        // Serialize the content AAD
        let mls_ciphertext_content_aad = MlsCiphertextContentAad {
            group_id: context.group_id().clone(),
            epoch: context.epoch(),
            content_type: *mls_plaintext.content_type(),
            authenticated_data: mls_plaintext.authenticated_data().to_vec(),
        };
        let mls_ciphertext_content_aad_bytes = mls_ciphertext_content_aad.encode_detached()?;
        // Extract generation and key material for encryption
        let secret_type = SecretType::try_from(mls_plaintext)
            .map_err(|_| MlsCiphertextError::InvalidContentType)?;
        let (generation, (ratchet_key, mut ratchet_nonce)) =
            secret_tree.secret_for_encryption(ciphersuite, sender, secret_type)?;
        // Sample reuse guard uniformly at random.
        let reuse_guard: ReuseGuard = ReuseGuard::from_random();
        // Prepare the nonce by xoring with the reuse guard.
        ratchet_nonce.xor_with_reuse_guard(&reuse_guard);
        // Encrypt the payload
        let ciphertext = ratchet_key
            .aead_seal(
                &Self::encode_padded_ciphertext_content_detached(
                    mls_plaintext,
                    padding_size,
                    ciphersuite.mac_length(),
                )?,
                &mls_ciphertext_content_aad_bytes,
                &ratchet_nonce,
            )
            .map_err(|e| {
                log::error!("MlsCiphertext::try_from_plaintext encryption error {:?}", e);
                MlsCiphertextError::EncryptionError
            })?;
        // Derive the sender data key from the key schedule using the ciphertext.
        let sender_data_key = epoch_secrets
            .sender_data_secret()
            .derive_aead_key(&ciphertext);
        // Derive initial nonce from the key schedule using the ciphertext.
        let sender_data_nonce = epoch_secrets
            .sender_data_secret()
            .derive_aead_nonce(ciphersuite, &ciphertext);
        // Compute sender data nonce by xoring reuse guard and key schedule
        // nonce as per spec.
        let mls_sender_data_aad = MlsSenderDataAad::new(
            context.group_id().clone(),
            context.epoch(),
            *mls_plaintext.content_type(),
        );
        // Serialize the sender data AAD
        let mls_sender_data_aad_bytes = mls_sender_data_aad.encode_detached()?;
        let sender_data = MlsSenderData::new(mls_plaintext.sender_index(), generation, reuse_guard);
        // Encrypt the sender data
        let encrypted_sender_data = sender_data_key
            .aead_seal(
                &sender_data.encode_detached()?,
                &mls_sender_data_aad_bytes,
                &sender_data_nonce,
            )
            .map_err(|e| {
                log::error!("MlsCiphertext::try_from_plaintext encryption error {:?}", e);
                MlsCiphertextError::EncryptionError
            })?;
        Ok(MlsCiphertext {
            group_id: context.group_id().clone(),
            epoch: context.epoch(),
            content_type: *mls_plaintext.content_type(),
            authenticated_data: mls_plaintext.authenticated_data().to_vec(),
            encrypted_sender_data,
            ciphertext: ciphertext.to_vec(),
        })
    }

    /// This function decrypts an [`MlsCiphertext`] into an [`VerifiableMlsPlaintext`].
    /// In order to get an [`MlsPlaintext`] the result must be verified.
    pub(crate) fn to_plaintext(
        &self,
        ciphersuite: &Ciphersuite,
        epoch_secrets: &EpochSecrets,
        secret_tree: &mut SecretTree,
    ) -> Result<VerifiableMlsPlaintext, MlsCiphertextError> {
        log::debug!("Decrypting MlsCiphertext");
        // Derive key from the key schedule using the ciphertext.
        let sender_data_key = epoch_secrets
            .sender_data_secret()
            .derive_aead_key(&self.ciphertext);
        // Derive initial nonce from the key schedule using the ciphertext.
        let sender_data_nonce = epoch_secrets
            .sender_data_secret()
            .derive_aead_nonce(ciphersuite, &self.ciphertext);
        // Serialize sender data AAD
        let mls_sender_data_aad =
            MlsSenderDataAad::new(self.group_id.clone(), self.epoch, self.content_type);
        let mls_sender_data_aad_bytes = mls_sender_data_aad.encode_detached()?;
        // Decrypt sender data
        let sender_data_bytes = &sender_data_key
            .aead_open(
                &self.encrypted_sender_data,
                &mls_sender_data_aad_bytes,
                &sender_data_nonce,
            )
            .map_err(|_| {
                log::error!("Sender data decryption error");
                MlsCiphertextError::DecryptionError
            })?;
        log::trace!("  Successfully decrypted sender data.");
        let sender_data = MlsSenderData::decode_detached(&sender_data_bytes)?;
        let secret_type = SecretType::try_from(&self.content_type)
            .map_err(|_| MlsCiphertextError::InvalidContentType)?;
        // Extract generation and key material for encryption
        let (ratchet_key, mut ratchet_nonce) = secret_tree
            .secret_for_decryption(
                ciphersuite,
                sender_data.sender,
                secret_type,
                sender_data.generation,
            )
            .map_err(|_| {
                log::error!("  Ciphertext generation out of bounds");
                MlsCiphertextError::GenerationOutOfBound
            })?;
        // Prepare the nonce by xoring with the reuse guard.
        ratchet_nonce.xor_with_reuse_guard(&sender_data.reuse_guard);
        // Serialize content AAD
        let mls_ciphertext_content_aad = MlsCiphertextContentAad {
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
            .map_err(|_| {
                log::error!("  Ciphertext decryption error");
                MlsCiphertextError::DecryptionError
            })?;
        log_content!(
            trace,
            "  Successfully decrypted MlsPlaintext bytes: {:x?}",
            mls_ciphertext_content_bytes
        );
        let mls_ciphertext_content = MlsCiphertextContent::decode(
            self.content_type,
            &mut Cursor::new(&mls_ciphertext_content_bytes),
        )?;
        // Extract sender. The sender type is always of type Member for MlsCiphertext.
        let sender = Sender {
            sender_type: SenderType::Member,
            sender: sender_data.sender,
        };
        log_content!(
            trace,
            "  Successfully decoded MlsPlaintext with: {:x?}",
            mls_ciphertext_content.content
        );

        let verifiable = VerifiableMlsPlaintext::new(
            MlsPlaintextTbs::new(
                None,
                self.group_id.clone(),
                self.epoch,
                sender,
                self.authenticated_data.clone(),
                self.content_type,
                mls_ciphertext_content.content,
            ),
            mls_ciphertext_content.signature,
            mls_ciphertext_content.confirmation_tag,
            None, /* MlsCiphertexts don't carry along the membership tag. */
        );
        Ok(verifiable)
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
        mls_plaintext: &MlsPlaintext,
        padding_size: usize,
        mac_len: usize,
    ) -> Result<Vec<u8>, CodecError> {
        // Persist all initial fields manually (avoids cloning them)
        let buffer = &mut Vec::new();
        mls_plaintext.content().encode(buffer)?;
        mls_plaintext.signature().encode(buffer)?;
        mls_plaintext.confirmation_tag().encode(buffer)?;
        // Add padding if needed
        let padding_length = if padding_size > 0 {
            // Calculate padding block size
            // The length of the padding block takes 2 bytes and the AEAD tag is also added.
            let padding_offset = buffer.len() + 2 + mac_len;
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
pub(crate) struct MlsSenderData {
    pub(crate) sender: LeafIndex,
    pub(crate) generation: u32,
    pub(crate) reuse_guard: ReuseGuard,
}

impl MlsSenderData {
    pub fn new(sender: LeafIndex, generation: u32, reuse_guard: ReuseGuard) -> Self {
        MlsSenderData {
            sender,
            generation,
            reuse_guard,
        }
    }
}

#[derive(Clone)]
pub(crate) struct MlsSenderDataAad {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) content_type: ContentType,
}

impl MlsSenderDataAad {
    fn new(group_id: GroupId, epoch: GroupEpoch, content_type: ContentType) -> Self {
        Self {
            group_id,
            epoch,
            content_type,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MlsCiphertextContent {
    pub(crate) content: MlsPlaintextContentType,
    pub(crate) signature: Signature,
    pub(crate) confirmation_tag: Option<ConfirmationTag>,
    pub(crate) padding: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct MlsCiphertextContentAad {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) content_type: ContentType,
    pub(crate) authenticated_data: Vec<u8>,
}
