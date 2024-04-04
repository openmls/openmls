use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::Ciphersuite;
use tls_codec::{
    Deserialize, Serialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
};

use super::{
    codec::deserialize_ciphertext_content, mls_auth_content::FramedContentAuthData,
    mls_auth_content_in::VerifiableAuthenticatedContentIn, mls_content_in::FramedContentBodyIn,
};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    error::LibraryError,
    framing::mls_content_in::FramedContentIn,
    tree::{secret_tree::SecretType, sender_ratchet::SenderRatchetConfiguration},
};

use super::*;

/// `PrivateMessage` is the framing struct for an encrypted `PublicMessage`.
/// This message format is meant to be sent to and received from the Delivery
/// Service.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     ContentType content_type;
///     opaque authenticated_data<V>;
///     opaque encrypted_sender_data<V>;
///     opaque ciphertext<V>;
/// } PrivateMessage;
/// ```
#[derive(
    Debug, PartialEq, Eq, Clone, TlsSerialize, TlsSize, TlsDeserialize, TlsDeserializeBytes,
)]
pub struct PrivateMessageIn {
    group_id: GroupId,
    epoch: GroupEpoch,
    content_type: ContentType,
    authenticated_data: VLBytes,
    encrypted_sender_data: VLBytes,
    ciphertext: VLBytes,
}

impl PrivateMessageIn {
    /// Decrypt the sender data from this [`PrivateMessageIn`].
    pub(crate) fn sender_data(
        &self,
        message_secrets: &MessageSecrets,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<MlsSenderData, MessageDecryptionError> {
        log::debug!("Decrypting PrivateMessage");
        // Derive key from the key schedule using the ciphertext.
        let sender_data_key = message_secrets
            .sender_data_secret()
            .derive_aead_key(crypto, ciphersuite, self.ciphertext.as_slice())
            .map_err(LibraryError::unexpected_crypto_error)?;
        // Derive initial nonce from the key schedule using the ciphertext.
        let sender_data_nonce = message_secrets
            .sender_data_secret()
            .derive_aead_nonce(ciphersuite, crypto, self.ciphertext.as_slice())
            .map_err(LibraryError::unexpected_crypto_error)?;
        // Serialize sender data AAD
        let mls_sender_data_aad =
            MlsSenderDataAad::new(self.group_id.clone(), self.epoch, self.content_type);
        let mls_sender_data_aad_bytes = mls_sender_data_aad
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        // Decrypt sender data
        log_crypto!(
            trace,
            "Decryption key for sender data: {sender_data_key:x?}"
        );
        log_crypto!(trace, "Decryption of sender data mls_sender_data_aad_bytes: {mls_sender_data_aad_bytes:x?} - sender_data_nonce: {sender_data_nonce:x?}");
        let sender_data_bytes = sender_data_key
            .aead_open(
                crypto,
                self.encrypted_sender_data.as_slice(),
                &mls_sender_data_aad_bytes,
                &sender_data_nonce,
            )
            .map_err(|_| {
                log::error!("Sender data decryption error");
                MessageDecryptionError::AeadError
            })?;
        log::trace!("  Successfully decrypted sender data.");
        MlsSenderData::tls_deserialize(&mut sender_data_bytes.as_slice())
            .map_err(|_| MessageDecryptionError::MalformedContent)
    }

    /// Decrypt this [`PrivateMessage`] and return the
    /// [`PrivateMessageContentIn`].
    #[inline]
    fn decrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ratchet_key: AeadKey,
        ratchet_nonce: &AeadNonce,
    ) -> Result<PrivateMessageContentIn, MessageDecryptionError> {
        // Serialize content AAD
        let private_message_content_aad_bytes = PrivateContentAad {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            content_type: self.content_type,
            authenticated_data: VLByteSlice(self.authenticated_data.as_slice()),
        }
        .tls_serialize_detached()
        .map_err(LibraryError::missing_bound_check)?;
        // Decrypt payload
        log_crypto!(
            trace,
            "Decryption key for private message: {ratchet_key:x?}"
        );
        log_crypto!(trace, "Decryption of private message private_message_content_aad_bytes: {private_message_content_aad_bytes:x?} - ratchet_nonce: {ratchet_nonce:x?}");
        log::trace!("Decrypting ciphertext {:x?}", self.ciphertext);
        let private_message_content_bytes = ratchet_key
            .aead_open(
                crypto,
                self.ciphertext.as_slice(),
                &private_message_content_aad_bytes,
                ratchet_nonce,
            )
            .map_err(|_| {
                log::error!("  Ciphertext decryption error");
                debug_assert!(false, "Ciphertext decryption failed");
                MessageDecryptionError::AeadError
            })?;
        log_content!(
            trace,
            "  Successfully decrypted PublicMessage bytes: {:x?}",
            private_message_content_bytes
        );
        deserialize_ciphertext_content(
            &mut private_message_content_bytes.as_slice(),
            self.content_type(),
        )
        .map_err(|_| MessageDecryptionError::MalformedContent)
    }

    /// This function decrypts a [`PrivateMessage`] into a
    /// [`VerifiableAuthenticatedContent`]. In order to get an
    /// [`FramedContent`] the result must be verified.
    pub(crate) fn to_verifiable_content(
        &self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        message_secrets: &mut MessageSecrets,
        sender_index: LeafNodeIndex,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
        sender_data: MlsSenderData,
    ) -> Result<VerifiableAuthenticatedContentIn, MessageDecryptionError> {
        let secret_type = SecretType::from(&self.content_type);
        // Extract generation and key material for encryption
        let (ratchet_key, ratchet_nonce) = message_secrets
            .secret_tree_mut()
            .secret_for_decryption(
                ciphersuite,
                crypto,
                sender_index,
                secret_type,
                sender_data.generation,
                sender_ratchet_configuration,
            )
            .map_err(|e| {
                log::error!(
                    "  Ciphertext generation out of bounds {}\n\t{e:?}",
                    sender_data.generation
                );
                MessageDecryptionError::SecretTreeError(e)
            })?;
        // Prepare the nonce by xoring with the reuse guard.
        let prepared_nonce = ratchet_nonce.xor_with_reuse_guard(&sender_data.reuse_guard);
        let private_message_content = self.decrypt(crypto, ratchet_key, &prepared_nonce)?;

        // Extract sender. The sender type is always of type Member for PrivateMessage.
        let sender = Sender::from_sender_data(sender_data);
        log_content!(
            trace,
            "  Successfully decoded PublicMessage with: {:x?}",
            private_message_content.content
        );

        let verifiable = VerifiableAuthenticatedContentIn::new(
            WireFormat::PrivateMessage,
            FramedContentIn {
                group_id: self.group_id.clone(),
                epoch: self.epoch,
                sender,
                authenticated_data: self.authenticated_data.clone(),
                body: private_message_content.content,
            },
            Some(message_secrets.serialized_context().to_vec()),
            private_message_content.auth,
        );
        Ok(verifiable)
    }

    /// Get the `group_id` in the `PrivateMessage`.
    pub(crate) fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Get the `epoch` in the `PrivateMessage`.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Get the `content_type` in the `PrivateMessage`.
    pub(crate) fn content_type(&self) -> ContentType {
        self.content_type
    }

    /// Set the ciphertext.
    #[cfg(test)]
    pub(crate) fn set_ciphertext(&mut self, ciphertext: Vec<u8>) {
        self.ciphertext = ciphertext.into();
    }
}

// === Helper structs ===

/// PrivateMessageContent
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     select (PrivateMessage.content_type) {
///         case application:
///           opaque application_data<V>;
///
///         case proposal:
///           Proposal proposal;
///
///         case commit:
///           Commit commit;
///     }
///
///     FramedContentAuthData auth;
///     opaque padding[length_of_padding];
/// } PrivateMessageContent;
/// ```
#[derive(Debug, Clone)]
pub(crate) struct PrivateMessageContentIn {
    // The `content` field is serialized and deserialized manually without the
    // `content_type`, which is not part of the struct as per MLS spec. See the
    // implementation of `TlsSerialize` for `PrivateMessageContentIn`, as well
    // as `deserialize_ciphertext_content`.
    pub(crate) content: FramedContentBodyIn,
    pub(crate) auth: FramedContentAuthData,
}

// The following `From` implementation( breaks abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
#[cfg(any(feature = "test-utils", test))]
impl From<PrivateMessageIn> for PrivateMessage {
    fn from(value: PrivateMessageIn) -> Self {
        Self {
            group_id: value.group_id,
            epoch: value.epoch,
            content_type: value.content_type,
            authenticated_data: value.authenticated_data,
            encrypted_sender_data: value.encrypted_sender_data,
            ciphertext: value.ciphertext,
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<PrivateMessage> for PrivateMessageIn {
    fn from(value: PrivateMessage) -> Self {
        Self {
            group_id: value.group_id,
            epoch: value.epoch,
            content_type: value.content_type,
            authenticated_data: value.authenticated_data,
            encrypted_sender_data: value.encrypted_sender_data,
            ciphertext: value.ciphertext,
        }
    }
}
