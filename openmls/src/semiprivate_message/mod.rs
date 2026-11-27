//! # SemiPrivateMessage
//!
//! The wire format of draft-mahy-mls-semiprivatemessage, which frames a
//! handshake so that a named list of external receivers can read it
//! while the rest of the message stays private to the group.
//!
//! This module carries the frame only: the types here serialize and
//! deserialize a `SemiPrivateMessage`, and nothing in them encrypts or
//! decrypts one. The draft's §3.1 construction needs the sender's
//! handshake ratchet, so it belongs beside `PrivateMessage` rather than
//! here, and an application that already has the per-message keys can
//! build and read the frame with these types alone.
//!
//! A single type serves both `MlsMessageIn` and `MlsMessageOut`. The
//! other bodies split into validated and unvalidated forms because
//! OpenMLS checks them; it performs no checks on this frame beyond the
//! codec, so there is no second state to name.

use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes as TlsDeserializeBytesTrait,
    Serialize as TlsSerializeTrait, *,
};

use openmls_traits::types::HpkeCiphertext;

use crate::{
    binary_tree::LeafNodeIndex,
    framing::ContentType,
    group::{GroupEpoch, GroupId},
};

/// A sender's per-message keys, sealed to one external receiver
/// (draft-mahy-mls-semiprivatemessage §3.1).
///
/// ```text
/// struct {
///   ExternalReceiverRef external_receiver_ref;
///   HPKECiphertext encrypted_keys_and_nonces;
/// } KeyForExternalReceiver;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct KeyForExternalReceiver {
    /// `hash(ExternalReceiver)`, naming which external receiver this
    /// entry is for.
    pub external_receiver_ref: VLBytes,
    /// The sealed `PerMessageKeyAndNonces`.
    pub encrypted_keys_and_nonces: HpkeCiphertext,
}

/// The per-message keys an external receiver unseals
/// (draft-mahy-mls-semiprivatemessage §3.1).
///
/// ```text
/// struct {
///   opaque key<V>;
///   opaque nonce<V>;
///   opaque reuse_guard[4];
///   uint32 sender_leaf_index;
/// } PerMessageKeyAndNonces;
/// ```
///
/// `sender_leaf_index` is how an external receiver learns the sender: it
/// cannot decrypt the `encrypted_sender_data` that tells a member.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct PerMessageKeyAndNonces {
    /// The AEAD key for the frame's `ciphertext`.
    pub key: VLBytes,
    /// The AEAD nonce, before the `reuse_guard` is applied.
    pub nonce: VLBytes,
    /// XORed into the nonce's first four octets, as RFC 9420 §6.3.2
    /// does for a `PrivateMessage`.
    pub reuse_guard: [u8; 4],
    /// The leaf that sent the message.
    pub sender_leaf_index: LeafNodeIndex,
}

/// The HPKE context the per-message keys are sealed under
/// (draft-mahy-mls-semiprivatemessage §3.1).
///
/// ```text
/// struct {
///   opaque group_id<V>;
///   uint64 epoch;
///   opaque partial_context_hash<V>;
/// } SemiPrivateMessageContext;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct SemiPrivateMessageContext {
    /// The group.
    pub group_id: GroupId,
    /// The epoch.
    pub epoch: GroupEpoch,
    /// `hash(sender_leaf_index || nonce)`, which the frame also carries
    /// so a receiver can build this context before decrypting.
    pub partial_context_hash: VLBytes,
}

/// A handshake framed for a group and a list of external receivers
/// (draft-mahy-mls-semiprivatemessage §3.1).
///
/// ```text
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     ContentType content_type;
///     opaque authenticated_data<V>;
///     opaque partial_context_hash<V>;
///     KeyForExternalReceiver keys_for_external_receivers<V>;
///     opaque framed_content_tbs_hash<V>;
///     opaque encrypted_sender_data<V>;
///     opaque ciphertext<V>;
/// } SemiPrivateMessage;
/// ```
///
/// `content_type` is never `application`: §3.1's
/// `SemiPrivateMessageContent` has no application arm, and
/// [`SemiPrivateMessage::validate`] rejects one.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct SemiPrivateMessage {
    group_id: GroupId,
    epoch: GroupEpoch,
    content_type: ContentType,
    authenticated_data: VLBytes,
    partial_context_hash: VLBytes,
    keys_for_external_receivers: Vec<KeyForExternalReceiver>,
    framed_content_tbs_hash: VLBytes,
    encrypted_sender_data: VLBytes,
    ciphertext: VLBytes,
}

impl SemiPrivateMessage {
    /// Builds a frame from parts an application has already produced.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        group_id: GroupId,
        epoch: GroupEpoch,
        content_type: ContentType,
        authenticated_data: VLBytes,
        partial_context_hash: VLBytes,
        keys_for_external_receivers: Vec<KeyForExternalReceiver>,
        framed_content_tbs_hash: VLBytes,
        encrypted_sender_data: VLBytes,
        ciphertext: VLBytes,
    ) -> Self {
        Self {
            group_id,
            epoch,
            content_type,
            authenticated_data,
            partial_context_hash,
            keys_for_external_receivers,
            framed_content_tbs_hash,
            encrypted_sender_data,
            ciphertext,
        }
    }

    /// The group this frame belongs to.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// The epoch this frame belongs to.
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Whether this frame carries a proposal or a commit.
    pub fn content_type(&self) -> ContentType {
        self.content_type
    }

    /// The AAD, which is authenticated but not encrypted.
    pub fn authenticated_data(&self) -> &[u8] {
        self.authenticated_data.as_slice()
    }

    /// `hash(sender_leaf_index || nonce)`, the extra input to the HPKE
    /// context the per-message keys are sealed under.
    pub fn partial_context_hash(&self) -> &[u8] {
        self.partial_context_hash.as_slice()
    }

    /// The per-message keys, one entry per external receiver the sender
    /// addressed.
    pub fn keys_for_external_receivers(&self) -> &[KeyForExternalReceiver] {
        &self.keys_for_external_receivers
    }

    /// `hash(FramedContentTBS)`, which binds the content the members see
    /// to the content the external receivers see.
    pub fn framed_content_tbs_hash(&self) -> &[u8] {
        self.framed_content_tbs_hash.as_slice()
    }

    /// The sealed `SenderData`, which only a member can open.
    pub fn encrypted_sender_data(&self) -> &[u8] {
        self.encrypted_sender_data.as_slice()
    }

    /// The sealed `SemiPrivateMessageContent`.
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_slice()
    }

    /// Checks what the codec alone cannot: that `content_type` is one
    /// §3.1 defines for this frame.
    ///
    /// # Errors
    ///
    /// Returns an error if `content_type` is
    /// [`ContentType::Application`], which §3.1's
    /// `SemiPrivateMessageContent` does not define.
    pub fn validate(&self) -> Result<(), SemiPrivateMessageError> {
        match self.content_type {
            ContentType::Application => Err(SemiPrivateMessageError::ApplicationContent),
            ContentType::Proposal | ContentType::Commit => Ok(()),
        }
    }
}

/// Why a [`SemiPrivateMessage`] is not usable.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum SemiPrivateMessageError {
    /// The frame claims to carry an application message, which
    /// draft-mahy-mls-semiprivatemessage §3.1 does not define for it.
    #[error("a SemiPrivateMessage carries a proposal or a commit, not an application message")]
    ApplicationContent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, WireFormat};

    /// A frame hand-encoded from §3.1's presentation language, byte by
    /// byte, with one external receiver.
    #[rustfmt::skip]
    const FRAME: &[u8] = &[
        0x03, b'g', b'i', b'd',             // group_id<V>
        0, 0, 0, 0, 0, 0, 0, 7,             // epoch = 7
        0x02,                               // content_type: proposal
        0x02, 0xaa, 0xbb,                   // authenticated_data<V>
        0x02, 0xbe, 0xef,                   // partial_context_hash<V>
        0x0b,                               // keys_for_external_receivers<V>: 11 bytes
          0x04, 0x01, 0x02, 0x03, 0x04,     //   external_receiver_ref<V>
          0x02, 0x11, 0x22,                 //   kem_output<V>
          0x02, 0x33, 0x44,                 //   ciphertext<V>
        0x02, 0xfe, 0xed,                   // framed_content_tbs_hash<V>
        0x01, 0x99,                         // encrypted_sender_data<V>
        0x03, 0x01, 0x02, 0x03,             // ciphertext<V>
    ];

    #[test]
    fn a_frame_round_trips() {
        let frame = SemiPrivateMessage::tls_deserialize_exact(FRAME).expect("decodes");
        assert_eq!(frame.group_id().as_slice(), b"gid");
        assert_eq!(frame.epoch(), GroupEpoch::from(7));
        assert_eq!(frame.content_type(), ContentType::Proposal);
        assert_eq!(frame.authenticated_data(), [0xaa, 0xbb]);
        assert_eq!(frame.partial_context_hash(), [0xbe, 0xef]);
        assert_eq!(frame.keys_for_external_receivers().len(), 1);
        assert_eq!(frame.framed_content_tbs_hash(), [0xfe, 0xed]);
        assert_eq!(frame.encrypted_sender_data(), [0x99]);
        assert_eq!(frame.ciphertext(), [0x01, 0x02, 0x03]);
        assert_eq!(
            frame.tls_serialize_detached().expect("encodes"),
            FRAME,
            "re-encoding gives the received bytes"
        );
    }

    /// The whole point of the wire format: an MlsMessage carries the
    /// frame, and its discriminant is the one §5.1 asks for.
    #[test]
    fn an_mls_message_carries_the_frame_under_0x0011() {
        let frame = SemiPrivateMessage::tls_deserialize_exact(FRAME).expect("decodes");
        let out = MlsMessageOut::from(frame.clone());
        let wire = out.tls_serialize_detached().expect("encodes");

        // version (1), then the body's discriminant.
        assert_eq!(&wire[..2], &[0x00, 0x01], "ProtocolVersion mls10");
        assert_eq!(&wire[2..4], &[0x00, 0x11], "mls_semiprivate_message");
        assert_eq!(&wire[4..], FRAME, "then the frame, unchanged");

        let back = MlsMessageIn::tls_deserialize_exact(&wire).expect("decodes");
        assert_eq!(back.wire_format(), WireFormat::SemiPrivateMessage);
        match back.extract() {
            MlsMessageBodyIn::SemiPrivateMessage(got) => assert_eq!(got, frame),
            other => panic!("wrong body: {other:?}"),
        }
    }

    /// §3.1 defines no application arm for SemiPrivateMessageContent, so
    /// a frame claiming one is refused -- by `validate`, not the codec,
    /// which cannot know.
    #[test]
    fn an_application_content_type_is_refused() {
        let mut wire = FRAME.to_vec();
        wire[12] = 0x01; // content_type: application
        let frame = SemiPrivateMessage::tls_deserialize_exact(&wire).expect("the codec allows it");
        assert_eq!(
            frame.validate(),
            Err(SemiPrivateMessageError::ApplicationContent)
        );

        let proposal = SemiPrivateMessage::tls_deserialize_exact(FRAME).expect("decodes");
        assert_eq!(proposal.validate(), Ok(()));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut wire = FRAME.to_vec();
        wire.push(0x00);
        assert!(SemiPrivateMessage::tls_deserialize_exact(&wire).is_err());
    }
}
