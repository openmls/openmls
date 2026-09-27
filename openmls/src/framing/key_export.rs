//! Per-message key export (non-standard extension).
//!
//! This module defines [`ExportedMessageKey`], a bundle carrying the raw AEAD
//! key and nonce used to seal exactly **one** application message, together
//! with enough metadata to locate the corresponding [`PrivateMessage`] on the
//! wire.
//!
//! This is a **non-standard** OpenMLS extension. RFC 9420 gives no member the
//! ability to hand out a single message's key. The exported key opens exactly
//! that one application message and nothing else (it is a leaf of the message
//! ratchet, not a ratchet secret), but it is still raw key material: the caller
//! is entirely responsible for protecting it, and for never exposing it to a
//! party that should not be able to read the message.

use tls_codec::SecretVLBytes;

use super::NONCE_BYTES;
use crate::group::{GroupEpoch, GroupId};

/// The AEAD key and nonce that open a single application message, plus the
/// metadata needed to find that message on the wire.
///
/// Produced by the `message-key-export` public API. The `key` field is a
/// [`SecretVLBytes`], which zeroizes its contents on drop; the [`Debug`]
/// implementation redacts both `key` and `nonce`.
///
/// See the module documentation: this is a non-standard extension, the key
/// opens exactly one application message, and the caller is responsible for
/// protecting it.
pub struct ExportedMessageKey {
    key: SecretVLBytes,
    nonce: [u8; NONCE_BYTES],
    group_id: GroupId,
    epoch: GroupEpoch,
    sender_leaf_index: u32,
    generation: u32,
    ciphertext: Vec<u8>,
}

impl ExportedMessageKey {
    /// Build an exported key bundle. Crate-internal: the framing layer is the
    /// only producer.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        key: &[u8],
        nonce: [u8; NONCE_BYTES],
        group_id: GroupId,
        epoch: GroupEpoch,
        sender_leaf_index: u32,
        generation: u32,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            key: key.into(),
            nonce,
            group_id,
            epoch,
            sender_leaf_index,
            generation,
            ciphertext,
        }
    }

    /// Raw AEAD key bytes that open the message.
    pub fn key(&self) -> &[u8] {
        self.key.as_slice()
    }

    /// The final AEAD nonce (already xored with the reuse guard).
    pub fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    /// The group the message belongs to.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// The epoch the message was sent in.
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// The sender's leaf index.
    pub fn sender_leaf_index(&self) -> u32 {
        self.sender_leaf_index
    }

    /// The ratchet generation of the message.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The ciphertext this key opens (matches [`PrivateMessage`]'s ciphertext).
    ///
    /// [`PrivateMessage`]: super::PrivateMessage
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl core::fmt::Debug for ExportedMessageKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExportedMessageKey")
            .field("key", &"***")
            .field("nonce", &"***")
            .field("group_id", &self.group_id)
            .field("epoch", &self.epoch)
            .field("sender_leaf_index", &self.sender_leaf_index)
            .field("generation", &self.generation)
            .field("ciphertext", &self.ciphertext)
            .finish()
    }
}
