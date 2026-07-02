//! # Targeted Messages (draft-ietf-mls-targeted-messages)
//!
//! This module implements the MLS targeted messages extension, which allows
//! a group member to send an HPKE-encrypted message to a specific member
//! of the group. The message is authenticated using the group's PSK and
//! the sender's signature key.

mod errors;

#[cfg(test)]
pub mod kat;

#[cfg(test)]
mod tests;

pub use errors::*;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    signatures::Signer,
    types::{Ciphersuite, HpkeCiphertext},
};
use serde::{Deserialize, Serialize};
use tls_codec::{
    DeserializeBytes, Serialize as TlsSerializeTrait, Size, TlsDeserialize, TlsDeserializeBytes,
    TlsSerialize, TlsSize, VLByteSlice, VLBytes,
};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::{
        signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
        AeadKey, AeadNonce, OpenMlsSignaturePublicKey, Secret, Signature,
    },
    error::LibraryError,
    framing::WireFormat,
    group::{GroupEpoch, GroupId},
    treesync::node::{
        encryption_keys::{EncryptionKey, EncryptionPrivateKey},
        leaf_node::LeafNode,
    },
    versions::ProtocolVersion,
};

const TARGETED_MESSAGE_EXPORTER_LABEL: &str = "targeted message";
const PSK_SUBLABEL: &str = "psk";
const SENDER_AUTH_DATA_SECRET_SUBLABEL: &str = "sender auth data secret";
const TARGETED_MESSAGE_TBS_LABEL: &str = "TargetedMessageTBS";
const TARGETED_MESSAGE_DATA_LABEL: &str = "TargetedMessageData";
const PSK_LABEL: &str = "MLS 1.0 targeted message psk";

/// A targeted message as defined in draft-ietf-mls-targeted-messages.
///
/// ```text
/// struct {
///   opaque group_id<V>;
///   uint64 epoch;
///   uint32 recipient_leaf_index;
///   opaque authenticated_data<V>;
///   opaque encrypted_sender_auth_data<V>;
///   opaque ciphertext<V>;
/// } TargetedMessage;
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct TargetedMessage {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) recipient_leaf_index: u32,
    pub(crate) authenticated_data: VLBytes,
    pub(crate) encrypted_sender_auth_data: VLBytes,
    pub(crate) ciphertext: VLBytes,
}

impl TargetedMessage {
    /// Returns the group ID.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Returns the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Returns the recipient leaf index.
    pub fn recipient_leaf_index(&self) -> u32 {
        self.recipient_leaf_index
    }

    /// Returns the authenticated data.
    pub fn authenticated_data(&self) -> &[u8] {
        self.authenticated_data.as_slice()
    }
}

/// A received targeted message, used as input for processing.
#[derive(Debug, Clone, PartialEq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub struct TargetedMessageIn {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) recipient_leaf_index: u32,
    pub(crate) authenticated_data: VLBytes,
    pub(crate) encrypted_sender_auth_data: VLBytes,
    pub(crate) ciphertext: VLBytes,
}

impl TargetedMessageIn {
    /// Returns the group ID.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Returns the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Returns the recipient leaf index.
    pub fn recipient_leaf_index(&self) -> u32 {
        self.recipient_leaf_index
    }

    /// Returns the authenticated data.
    pub fn authenticated_data(&self) -> &[u8] {
        self.authenticated_data.as_slice()
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<TargetedMessageIn> for TargetedMessage {
    fn from(msg: TargetedMessageIn) -> Self {
        Self {
            group_id: msg.group_id,
            epoch: msg.epoch,
            recipient_leaf_index: msg.recipient_leaf_index,
            authenticated_data: msg.authenticated_data,
            encrypted_sender_auth_data: msg.encrypted_sender_auth_data,
            ciphertext: msg.ciphertext,
        }
    }
}

impl From<TargetedMessage> for TargetedMessageIn {
    fn from(msg: TargetedMessage) -> Self {
        Self {
            group_id: msg.group_id,
            epoch: msg.epoch,
            recipient_leaf_index: msg.recipient_leaf_index,
            authenticated_data: msg.authenticated_data,
            encrypted_sender_auth_data: msg.encrypted_sender_auth_data,
            ciphertext: msg.ciphertext,
        }
    }
}

/// The plaintext content of a targeted message.
///
/// ```text
/// struct {
///   opaque application_data<V>;
///   opaque padding[length_of_padding];
/// } TargetedMessageContent;
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct TargetedMessageContent {
    application_data: VLBytes,
    padding_length: usize,
}

impl TargetedMessageContent {
    fn new(data: &[u8], padding_length: usize) -> Self {
        Self {
            application_data: data.into(),
            padding_length,
        }
    }

    pub(crate) fn application_data(&self) -> &[u8] {
        self.application_data.as_slice()
    }

    /// Serialize to bytes: VLBytes application_data followed by raw zero
    /// padding (no length prefix on the padding).
    fn serialize_detached(&self) -> Result<Vec<u8>, tls_codec::Error> {
        use std::io::Write;
        let app_data_len = self.application_data.tls_serialized_len();
        // Guard against overflow and against exceeding Rust's allocation limit
        // of isize::MAX bytes, since padding_length is caller-controlled.
        let total_len = app_data_len
            .checked_add(self.padding_length)
            .filter(|&len| len <= isize::MAX as usize)
            .ok_or_else(|| {
                tls_codec::Error::EncodingError(
                    "Targeted message content exceeds the maximum size.".into(),
                )
            })?;
        let mut buffer = Vec::with_capacity(total_len);
        self.application_data.tls_serialize(&mut buffer)?;
        buffer
            .write_all(&vec![0u8; self.padding_length])
            .map_err(|e| {
                tls_codec::Error::EncodingError(format!("Failed to write padding: {e}"))
            })?;
        Ok(buffer)
    }

    /// Deserialize: read VLBytes application_data, treat remaining bytes as
    /// raw padding, and validate all padding bytes are zero.
    fn deserialize_detached(bytes: &[u8]) -> Result<Self, tls_codec::Error> {
        let (application_data, rest) = VLBytes::tls_deserialize_bytes(bytes)?;
        if !rest.iter().all(|&b| b == 0x00) {
            return Err(tls_codec::Error::DecodingError(
                "Non-zero padding in TargetedMessageContent".into(),
            ));
        }
        Ok(Self {
            application_data,
            padding_length: rest.len(),
        })
    }
}

/// Sender authentication data, encrypted within the targeted message.
///
/// ```text
/// struct {
///   uint32 sender_leaf_index;
///   opaque signature<V>;
///   opaque kem_output<V>;
/// } TargetedMessageSenderAuthData;
/// ```
#[derive(Debug, Clone, PartialEq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
struct TargetedMessageSenderAuthData {
    sender_leaf_index: u32,
    signature: Signature,
    kem_output: VLBytes,
}

/// AAD for encrypting sender authentication data.
///
/// ```text
/// struct {
///   opaque group_id<V>;
///   uint64 epoch;
///   uint32 recipient_leaf_index;
/// } SenderAuthDataAAD;
/// ```
#[derive(TlsSerialize, TlsSize)]
struct SenderAuthDataAAD<'a> {
    group_id: &'a GroupId,
    epoch: GroupEpoch,
    recipient_leaf_index: u32,
}

/// The part of targeted messages that is authenticated with a signature.
///
/// ```text
/// struct {
///   ProtocolVersion version = mls10;
///   WireFormat wire_format = mls_targeted_message;
///   opaque group_id<V>;
///   uint64 epoch;
///   uint32 recipient_leaf_index;
///   opaque authenticated_data<V>;
///   uint32 sender_leaf_index;
///   opaque kem_output<V>;
/// } TargetedMessageTBS;
/// ```
#[derive(TlsSerialize, TlsSize)]
struct TargetedMessageTBS<'a> {
    version: ProtocolVersion,
    wire_format: WireFormat,
    group_id: &'a GroupId,
    epoch: GroupEpoch,
    recipient_leaf_index: u32,
    authenticated_data: VLByteSlice<'a>,
    sender_leaf_index: u32,
    kem_output: VLByteSlice<'a>,
}

/// The part of targeted messages that is authenticated with a MAC (used as AAD
/// for the HPKE operation).
///
/// ```text
/// struct {
///   opaque group_id<V>;
///   uint64 epoch;
///   uint32 recipient_leaf_index;
///   opaque authenticated_data<V>;
///   TargetedMessageSenderAuthData sender_auth_data;
/// } TargetedMessageTBM;
/// ```
#[derive(TlsSerialize, TlsSize)]
struct TargetedMessageTBM<'a> {
    group_id: &'a GroupId,
    epoch: GroupEpoch,
    recipient_leaf_index: u32,
    authenticated_data: VLByteSlice<'a>,
    sender_auth_data: &'a TargetedMessageSenderAuthData,
}

/// PSK ID for the targeted message HPKE PSK mode.
///
/// ```text
/// struct {
///   opaque group_id<V>;
///   uint64 epoch;
///   opaque label<V> = "MLS 1.0 targeted message psk";
/// } PSKId;
/// ```
#[derive(TlsSerialize, TlsSize)]
struct TargetedMessagePskId<'a> {
    group_id: &'a GroupId,
    epoch: GroupEpoch,
    label: VLByteSlice<'a>,
}

impl<'a> TargetedMessagePskId<'a> {
    fn new(group_id: &'a GroupId, epoch: GroupEpoch) -> Self {
        Self {
            group_id,
            epoch,
            label: VLByteSlice(PSK_LABEL.as_bytes()),
        }
    }
}

/// Group-level context needed for targeted message operations.
pub(crate) struct TargetedMessageGroupContext<'a> {
    pub ciphersuite: Ciphersuite,
    pub group_id: &'a GroupId,
    pub epoch: GroupEpoch,
    pub exporter_secret: &'a crate::schedule::ExporterSecret,
    pub serialized_group_context: &'a [u8],
}

/// Verified targeted message content, returned after successful processing.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessedTargetedMessage {
    sender_leaf_index: LeafNodeIndex,
    application_data: Vec<u8>,
    authenticated_data: Vec<u8>,
}

impl ProcessedTargetedMessage {
    /// Returns the sender's leaf index.
    pub fn sender_leaf_index(&self) -> LeafNodeIndex {
        self.sender_leaf_index
    }

    /// Returns the application data payload.
    pub fn application_data(&self) -> &[u8] {
        &self.application_data
    }

    /// Returns the authenticated data.
    pub fn authenticated_data(&self) -> &[u8] {
        &self.authenticated_data
    }

    /// Returns both the application data and authenticated data.
    pub fn into_data(self) -> (Vec<u8>, Vec<u8>) {
        (self.application_data, self.authenticated_data)
    }
}

/// Derive the targeted message PSK from the MLS exporter.
fn derive_targeted_message_psk(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    exporter_secret: &crate::schedule::ExporterSecret,
) -> Result<Vec<u8>, LibraryError> {
    exporter_secret
        .derive_exported_secret(
            ciphersuite,
            crypto,
            TARGETED_MESSAGE_EXPORTER_LABEL,
            PSK_SUBLABEL.as_bytes(),
            ciphersuite.hash_length(),
        )
        .map_err(LibraryError::unexpected_crypto_error)
}

/// Derive the sender auth data secret from the MLS exporter.
fn derive_sender_auth_data_secret(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    exporter_secret: &crate::schedule::ExporterSecret,
) -> Result<Secret, LibraryError> {
    let secret_bytes = exporter_secret
        .derive_exported_secret(
            ciphersuite,
            crypto,
            TARGETED_MESSAGE_EXPORTER_LABEL,
            SENDER_AUTH_DATA_SECRET_SUBLABEL.as_bytes(),
            ciphersuite.hash_length(),
        )
        .map_err(LibraryError::unexpected_crypto_error)?;
    Ok(Secret::from_slice(&secret_bytes))
}

/// Derive sender auth data key and nonce from the ciphertext sample.
fn derive_sender_auth_data_key_nonce(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    sender_auth_data_secret: &Secret,
    ciphertext: &[u8],
) -> Result<(AeadKey, AeadNonce), LibraryError> {
    let sample_len = ciphersuite.hash_length().min(ciphertext.len());
    let ciphertext_sample = &ciphertext[..sample_len];

    let key_secret = sender_auth_data_secret
        .kdf_expand_label(
            crypto,
            ciphersuite,
            "key",
            ciphertext_sample,
            ciphersuite.aead_key_length(),
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

    let nonce_secret = sender_auth_data_secret
        .kdf_expand_label(
            crypto,
            ciphersuite,
            "nonce",
            ciphertext_sample,
            ciphersuite.aead_nonce_length(),
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

    Ok((
        AeadKey::from_secret(key_secret, ciphersuite),
        AeadNonce::from_secret(nonce_secret),
    ))
}

/// Wraps a TBS struct for use with the Signable/Verifiable traits.
struct TargetedMessageTBSPayload {
    serialized: Vec<u8>,
}

impl Signable for TargetedMessageTBSPayload {
    type SignedOutput = TargetedMessageSignature;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        Ok(self.serialized.clone())
    }

    fn label(&self) -> &str {
        TARGETED_MESSAGE_TBS_LABEL
    }
}

struct TargetedMessageSignature(pub(crate) Signature);

impl SignedStruct<TargetedMessageTBSPayload> for TargetedMessageSignature {
    fn from_payload(
        _payload: TargetedMessageTBSPayload,
        signature: Signature,
        _serialized_payload: Vec<u8>,
    ) -> Self {
        Self(signature)
    }
}

/// Wraps a TBS struct for verification.
struct VerifiableTargetedMessageTBS {
    serialized: Vec<u8>,
    signature: Signature,
}

impl Verifiable for VerifiableTargetedMessageTBS {
    type VerifiedStruct = VerifiedTargetedMessage;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        Ok(self.serialized.clone())
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        TARGETED_MESSAGE_TBS_LABEL
    }

    fn verify(
        self,
        crypto: &impl OpenMlsCrypto,
        pk: &crate::ciphersuite::OpenMlsSignaturePublicKey,
    ) -> Result<Self::VerifiedStruct, crate::ciphersuite::signable::SignatureError> {
        self.verify_no_out(crypto, pk)?;
        Ok(VerifiedTargetedMessage)
    }
}

struct VerifiedTargetedMessage;
impl VerifiedStruct for VerifiedTargetedMessage {}

/// Create a targeted message.
#[allow(clippy::too_many_arguments)]
pub(crate) fn create_targeted_message(
    crypto: &impl OpenMlsCrypto,
    signer: &impl Signer,
    ctx: &TargetedMessageGroupContext<'_>,
    sender_leaf_index: LeafNodeIndex,
    recipient_leaf_index: LeafNodeIndex,
    recipient_encryption_key: &EncryptionKey,
    authenticated_data: &[u8],
    application_data: &[u8],
    padding_length: usize,
) -> Result<TargetedMessage, CreateTargetedMessageError> {
    let psk = derive_targeted_message_psk(crypto, ctx.ciphersuite, ctx.exporter_secret)?;
    let sender_auth_data_secret =
        derive_sender_auth_data_secret(crypto, ctx.ciphersuite, ctx.exporter_secret)?;

    let psk_id = TargetedMessagePskId::new(ctx.group_id, ctx.epoch);
    let psk_id_bytes = psk_id
        .tls_serialize_detached()
        .map_err(LibraryError::missing_bound_check)?;

    let content = TargetedMessageContent::new(application_data, padding_length);
    let content_bytes = content
        .serialize_detached()
        .map_err(LibraryError::missing_bound_check)?;

    let mut sender_auth_data_bytes = None;
    let hpke_ct = recipient_encryption_key.encrypt_with_label_psk_resolved_aad(
        crate::ciphersuite::hpke::PskEncryptParams {
            label: TARGETED_MESSAGE_DATA_LABEL,
            context: ctx.serialized_group_context,
            psk: &psk,
            psk_id: &psk_id_bytes,
        },
        &content_bytes,
        ctx.ciphersuite,
        crypto,
        |kem_output| {
            let tbs = TargetedMessageTBS {
                version: ProtocolVersion::default(),
                wire_format: WireFormat::TargetedMessage,
                group_id: ctx.group_id,
                epoch: ctx.epoch,
                recipient_leaf_index: recipient_leaf_index.u32(),
                authenticated_data: VLByteSlice(authenticated_data),
                sender_leaf_index: sender_leaf_index.u32(),
                kem_output: VLByteSlice(kem_output),
            };
            let tbs_bytes = tbs
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?;

            let tbs_payload = TargetedMessageTBSPayload {
                serialized: tbs_bytes,
            };
            let signature = tbs_payload.sign(signer).map_err(|e| {
                log::error!("Signing targeted message failed: {e:?}");
                LibraryError::custom("Signing targeted message failed")
            })?;

            let sender_auth_data = TargetedMessageSenderAuthData {
                sender_leaf_index: sender_leaf_index.u32(),
                signature: signature.0,
                kem_output: kem_output.to_vec().into(),
            };
            let current_sender_auth_data_bytes = sender_auth_data
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?;
            let tbm = TargetedMessageTBM {
                group_id: ctx.group_id,
                epoch: ctx.epoch,
                recipient_leaf_index: recipient_leaf_index.u32(),
                authenticated_data: VLByteSlice(authenticated_data),
                sender_auth_data: &sender_auth_data,
            };
            sender_auth_data_bytes = Some(current_sender_auth_data_bytes);
            tbm.tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)
        },
    )?;
    let sender_auth_data_bytes = sender_auth_data_bytes.ok_or_else(|| {
        LibraryError::custom("Targeted message sender authentication data missing")
    })?;

    // Encrypt sender auth data
    let (key, nonce) = derive_sender_auth_data_key_nonce(
        crypto,
        ctx.ciphersuite,
        &sender_auth_data_secret,
        hpke_ct.ciphertext.as_slice(),
    )?;

    let sender_auth_aad = SenderAuthDataAAD {
        group_id: ctx.group_id,
        epoch: ctx.epoch,
        recipient_leaf_index: recipient_leaf_index.u32(),
    };
    let sender_auth_aad_bytes = sender_auth_aad
        .tls_serialize_detached()
        .map_err(LibraryError::missing_bound_check)?;

    let encrypted_sender_auth_data = key
        .aead_seal(
            crypto,
            &sender_auth_data_bytes,
            &sender_auth_aad_bytes,
            &nonce,
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

    Ok(TargetedMessage {
        group_id: ctx.group_id.clone(),
        epoch: ctx.epoch,
        recipient_leaf_index: recipient_leaf_index.u32(),
        authenticated_data: authenticated_data.to_vec().into(),
        encrypted_sender_auth_data: encrypted_sender_auth_data.into(),
        ciphertext: hpke_ct.ciphertext,
    })
}

/// Process (decrypt and verify) a targeted message.
pub(crate) fn process_targeted_message<StorageError>(
    crypto: &impl OpenMlsCrypto,
    ctx: &TargetedMessageGroupContext<'_>,
    own_leaf_index: LeafNodeIndex,
    own_encryption_private_key: &EncryptionPrivateKey,
    message: &TargetedMessageIn,
    leaves: &[Option<&LeafNode>],
) -> Result<ProcessedTargetedMessage, ProcessTargetedMessageError<StorageError>> {
    // Validate group_id
    if &message.group_id != ctx.group_id {
        return Err(ProcessTargetedMessageError::GroupIdMismatch);
    }

    // Validate epoch
    if message.epoch != ctx.epoch {
        return Err(ProcessTargetedMessageError::EpochMismatch);
    }

    // Validate recipient
    if message.recipient_leaf_index != own_leaf_index.u32() {
        return Err(ProcessTargetedMessageError::NotIntendedRecipient);
    }

    let sender_auth_data_secret =
        derive_sender_auth_data_secret(crypto, ctx.ciphersuite, ctx.exporter_secret)?;

    // Derive key/nonce for sender auth data decryption
    let (key, nonce) = derive_sender_auth_data_key_nonce(
        crypto,
        ctx.ciphersuite,
        &sender_auth_data_secret,
        message.ciphertext.as_slice(),
    )?;

    let sender_auth_aad = SenderAuthDataAAD {
        group_id: ctx.group_id,
        epoch: ctx.epoch,
        recipient_leaf_index: own_leaf_index.u32(),
    };
    let sender_auth_aad_bytes = sender_auth_aad
        .tls_serialize_detached()
        .map_err(LibraryError::missing_bound_check)?;

    // Decrypt sender auth data
    let sender_auth_data_bytes = key
        .aead_open(
            crypto,
            message.encrypted_sender_auth_data.as_slice(),
            &sender_auth_aad_bytes,
            &nonce,
        )
        .map_err(|e| {
            log::error!("Targeted message sender auth data decryption failed: {e:?}");
            ProcessTargetedMessageError::SenderAuthDataDecryptionFailed
        })?;

    let sender_auth_data =
        TargetedMessageSenderAuthData::tls_deserialize_exact_bytes(&sender_auth_data_bytes)
            .map_err(|e| {
                log::error!("Targeted message sender auth data is malformed: {e:?}");
                ProcessTargetedMessageError::MalformedSenderAuthData
            })?;

    let sender_leaf_index = LeafNodeIndex::new(sender_auth_data.sender_leaf_index);

    let sender_leaf = leaves
        .get(sender_leaf_index.usize())
        .and_then(|opt| opt.as_ref())
        .ok_or(ProcessTargetedMessageError::SenderNotFound)?;
    let sender_signature_key = OpenMlsSignaturePublicKey::from_signature_key(
        sender_leaf.signature_key().clone(),
        ctx.ciphersuite.signature_algorithm(),
    );

    // Verify signature over TBS
    let tbs = TargetedMessageTBS {
        version: ProtocolVersion::default(),
        wire_format: WireFormat::TargetedMessage,
        group_id: ctx.group_id,
        epoch: ctx.epoch,
        recipient_leaf_index: own_leaf_index.u32(),
        authenticated_data: VLByteSlice(message.authenticated_data.as_slice()),
        sender_leaf_index: sender_auth_data.sender_leaf_index,
        kem_output: VLByteSlice(sender_auth_data.kem_output.as_slice()),
    };
    let tbs_bytes = tbs
        .tls_serialize_detached()
        .map_err(LibraryError::missing_bound_check)?;

    let verifiable = VerifiableTargetedMessageTBS {
        serialized: tbs_bytes,
        signature: sender_auth_data.signature.clone(),
    };

    verifiable
        .verify(crypto, &sender_signature_key)
        .map_err(|e| {
            log::error!("Targeted message signature verification failed: {e:?}");
            ProcessTargetedMessageError::SignatureVerificationFailed
        })?;

    // Decrypt the content via HPKE PSK open
    let psk = derive_targeted_message_psk(crypto, ctx.ciphersuite, ctx.exporter_secret)?;

    let psk_id = TargetedMessagePskId::new(ctx.group_id, ctx.epoch);
    let psk_id_bytes = psk_id
        .tls_serialize_detached()
        .map_err(LibraryError::missing_bound_check)?;

    let tbm = TargetedMessageTBM {
        group_id: ctx.group_id,
        epoch: ctx.epoch,
        recipient_leaf_index: own_leaf_index.u32(),
        authenticated_data: VLByteSlice(message.authenticated_data.as_slice()),
        sender_auth_data: &sender_auth_data,
    };
    let tbm_bytes = tbm
        .tls_serialize_detached()
        .map_err(LibraryError::missing_bound_check)?;

    let hpke_ciphertext = HpkeCiphertext {
        kem_output: sender_auth_data.kem_output.as_slice().to_vec().into(),
        ciphertext: message.ciphertext.as_slice().to_vec().into(),
    };

    let content_bytes = own_encryption_private_key
        .decrypt_with_label_psk_aad(
            crate::ciphersuite::hpke::PskEncryptParams {
                label: TARGETED_MESSAGE_DATA_LABEL,
                context: ctx.serialized_group_context,
                psk: &psk,
                psk_id: &psk_id_bytes,
            },
            &tbm_bytes,
            &hpke_ciphertext,
            ctx.ciphersuite,
            crypto,
        )
        .map_err(|e| {
            log::error!("Targeted message content decryption failed: {e:?}");
            ProcessTargetedMessageError::ContentDecryptionFailed
        })?;

    let content = TargetedMessageContent::deserialize_detached(&content_bytes).map_err(|e| {
        log::error!("Targeted message content is malformed: {e:?}");
        ProcessTargetedMessageError::MalformedContent
    })?;

    Ok(ProcessedTargetedMessage {
        sender_leaf_index,
        application_data: content.application_data().to_vec(),
        authenticated_data: message.authenticated_data.as_slice().to_vec(),
    })
}
