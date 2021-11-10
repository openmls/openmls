use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{
    Deserialize, Serialize, Size, TlsByteSliceU16, TlsByteVecU16, TlsByteVecU32, TlsByteVecU8,
    TlsDeserialize, TlsSerialize, TlsSize,
};

use super::*;

use std::convert::TryFrom;

/// `MlsCiphertext` is the framing struct for an encrypted `MlsPlaintext`.
/// This message format is meant to be sent to and received from the Delivery
/// Service.
#[derive(Debug, PartialEq, Clone, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct MlsCiphertext {
    pub(crate) wire_format: WireFormat,
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) content_type: ContentType,
    pub(crate) authenticated_data: TlsByteVecU32,
    pub(crate) encrypted_sender_data: TlsByteVecU8,
    pub(crate) ciphertext: TlsByteVecU32,
}

pub(crate) struct Secrets<'a> {
    pub(crate) epoch_secrets: &'a EpochSecrets,
    pub(crate) secret_tree: &'a mut SecretTree,
}

impl MlsCiphertext {
    /// Try to create a new `MlsCiphertext` from an `MlsPlaintext`
    pub(crate) fn try_from_plaintext(
        mls_plaintext: &MlsPlaintext,
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        context: &GroupContext,
        sender: LeafIndex,
        secrets: Secrets,
        padding_size: usize,
    ) -> Result<MlsCiphertext, MlsCiphertextError> {
        log::debug!("MlsCiphertext::try_from_plaintext");
        log::trace!("  ciphersuite: {}", ciphersuite);
        // Check the plaintext has the correct wire format
        if mls_plaintext.wire_format() != WireFormat::MlsCiphertext {
            return Err(MlsCiphertextError::WrongWireFormat);
        }
        // Serialize the content AAD
        let mls_ciphertext_content_aad = MlsCiphertextContentAad {
            group_id: context.group_id().clone(),
            epoch: context.epoch(),
            content_type: *mls_plaintext.content_type(),
            authenticated_data: mls_plaintext.authenticated_data().into(),
        };
        let mls_ciphertext_content_aad_bytes =
            mls_ciphertext_content_aad.tls_serialize_detached()?;
        // Extract generation and key material for encryption
        let secret_type = SecretType::try_from(mls_plaintext)
            .map_err(|_| MlsCiphertextError::InvalidContentType)?;
        let (generation, (ratchet_key, mut ratchet_nonce)) = secrets
            .secret_tree
            .secret_for_encryption(ciphersuite, backend, sender, secret_type)?;
        // Sample reuse guard uniformly at random.
        let reuse_guard: ReuseGuard = ReuseGuard::from_random(backend);
        // Prepare the nonce by xoring with the reuse guard.
        ratchet_nonce.xor_with_reuse_guard(&reuse_guard);
        // Encrypt the payload
        let ciphertext = ratchet_key
            .aead_seal(
                backend,
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
        let sender_data_key = secrets
            .epoch_secrets
            .sender_data_secret()
            .derive_aead_key(backend, &ciphertext);
        // Derive initial nonce from the key schedule using the ciphertext.
        let sender_data_nonce = secrets
            .epoch_secrets
            .sender_data_secret()
            .derive_aead_nonce(ciphersuite, backend, &ciphertext);
        // Compute sender data nonce by xoring reuse guard and key schedule
        // nonce as per spec.
        let mls_sender_data_aad = MlsSenderDataAad::new(
            context.group_id().clone(),
            context.epoch(),
            *mls_plaintext.content_type(),
        );
        // Serialize the sender data AAD
        let mls_sender_data_aad_bytes = mls_sender_data_aad.tls_serialize_detached()?;
        let sender_data = MlsSenderData::new(mls_plaintext.sender_index(), generation, reuse_guard);
        // Encrypt the sender data
        let encrypted_sender_data = sender_data_key
            .aead_seal(
                backend,
                &sender_data.tls_serialize_detached()?,
                &mls_sender_data_aad_bytes,
                &sender_data_nonce,
            )
            .map_err(|e| {
                log::error!("MlsCiphertext::try_from_plaintext encryption error {:?}", e);
                MlsCiphertextError::EncryptionError
            })?;
        Ok(MlsCiphertext {
            wire_format: WireFormat::MlsCiphertext,
            group_id: context.group_id().clone(),
            epoch: context.epoch(),
            content_type: *mls_plaintext.content_type(),
            authenticated_data: mls_plaintext.authenticated_data().into(),
            encrypted_sender_data: encrypted_sender_data.into(),
            ciphertext: ciphertext.into(),
        })
    }

    /// This function decrypts an [`MlsCiphertext`] into an [`VerifiableMlsPlaintext`].
    /// In order to get an [`MlsPlaintext`] the result must be verified.
    pub(crate) fn to_plaintext(
        &self,
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        epoch_secrets: &EpochSecrets,
        secret_tree: &mut SecretTree,
    ) -> Result<VerifiableMlsPlaintext, MlsCiphertextError> {
        log::debug!("Decrypting MlsCiphertext");
        // Check the ciphertext has the correct wire format
        if self.wire_format != WireFormat::MlsCiphertext {
            return Err(MlsCiphertextError::WrongWireFormat);
        }
        // Derive key from the key schedule using the ciphertext.
        let sender_data_key = epoch_secrets
            .sender_data_secret()
            .derive_aead_key(backend, self.ciphertext.as_slice());
        // Derive initial nonce from the key schedule using the ciphertext.
        let sender_data_nonce = epoch_secrets.sender_data_secret().derive_aead_nonce(
            ciphersuite,
            backend,
            self.ciphertext.as_slice(),
        );
        // Serialize sender data AAD
        let mls_sender_data_aad =
            MlsSenderDataAad::new(self.group_id.clone(), self.epoch, self.content_type);
        let mls_sender_data_aad_bytes = mls_sender_data_aad.tls_serialize_detached()?;
        // Decrypt sender data
        let sender_data_bytes = sender_data_key
            .aead_open(
                backend,
                self.encrypted_sender_data.as_slice(),
                &mls_sender_data_aad_bytes,
                &sender_data_nonce,
            )
            .map_err(|_| {
                log::error!("Sender data decryption error");
                MlsCiphertextError::DecryptionError
            })?;
        log::trace!("  Successfully decrypted sender data.");
        let sender_data = MlsSenderData::tls_deserialize(&mut sender_data_bytes.as_slice())?;
        let secret_type = SecretType::try_from(&self.content_type)
            .map_err(|_| MlsCiphertextError::InvalidContentType)?;
        // Extract generation and key material for encryption
        let (ratchet_key, mut ratchet_nonce) = secret_tree
            .secret_for_decryption(
                ciphersuite,
                backend,
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
        let mls_ciphertext_content_aad_bytes =
            mls_ciphertext_content_aad.tls_serialize_detached()?;
        // Decrypt payload
        let mls_ciphertext_content_bytes = ratchet_key
            .aead_open(
                backend,
                self.ciphertext.as_slice(),
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
        let mls_ciphertext_content = MlsCiphertextContent::deserialize(
            self.content_type,
            &mut mls_ciphertext_content_bytes.as_slice(),
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
                self.wire_format,
                self.group_id.clone(),
                self.epoch,
                sender,
                self.authenticated_data.clone(),
                Payload {
                    payload: mls_ciphertext_content.content,
                    content_type: self.content_type,
                },
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
    /// ```text
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
    ///     }
    ///
    ///     opaque signature<0..2^16-1>;
    ///     optional<MAC> confirmation_tag;
    ///     opaque padding<0..2^16-1>;
    /// } MLSCiphertextContent;
    /// ```
    fn encode_padded_ciphertext_content_detached(
        mls_plaintext: &MlsPlaintext,
        padding_size: usize,
        mac_len: usize,
    ) -> Result<Vec<u8>, tls_codec::Error> {
        // Persist all initial fields manually (avoids cloning them)
        let buffer = &mut Vec::with_capacity(
            mls_plaintext.content().tls_serialized_len()
                + mls_plaintext.signature().tls_serialized_len()
                + mls_plaintext.confirmation_tag().tls_serialized_len(),
        );
        mls_plaintext.content().tls_serialize(buffer)?;
        mls_plaintext.signature().tls_serialize(buffer)?;
        mls_plaintext.confirmation_tag().tls_serialize(buffer)?;
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
        TlsByteSliceU16(&vec![0u8; padding_length]).tls_serialize(buffer)?;
        Ok(buffer.to_vec())
    }

    /// Returns the `group_id` in the `MlsCiphertext`.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Get the cipher text bytes as slice.
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_slice()
    }

    /// Returns the `epoch` in the `MlsCiphertext`.
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    #[cfg(test)]
    pub(super) fn set_wire_format(&mut self, wire_format: WireFormat) {
        self.wire_format = wire_format;
    }
}

// === Helper structs ===

#[derive(Clone, TlsDeserialize, TlsSerialize, TlsSize)]
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

#[derive(Clone, TlsDeserialize, TlsSerialize, TlsSize)]
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

#[derive(Debug, Clone, TlsSerialize, TlsSize)]
pub(crate) struct MlsCiphertextContent {
    pub(crate) content: MlsPlaintextContentType,
    pub(crate) signature: Signature,
    pub(crate) confirmation_tag: Option<ConfirmationTag>,
    pub(crate) padding: TlsByteVecU16,
}

#[derive(Clone, TlsSerialize, TlsDeserialize, TlsSize)]
pub(crate) struct MlsCiphertextContentAad {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) content_type: ContentType,
    pub(crate) authenticated_data: TlsByteVecU32,
}
