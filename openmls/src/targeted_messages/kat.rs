//! KAT vectors for targeted messages.
//!
//! Vectors follow the receiver-side format of the draft's Test Vectors
//! appendix, extended with `valid`, `failure` and `description` so that a
//! vector can also describe a message that the recipient MUST reject, together
//! with the first Recipient Validation step that rejects it.

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{
    crypto::OpenMlsCrypto, random::OpenMlsRand, signatures::Signer, types::Ciphersuite,
};
use serde::{Deserialize, Serialize};
use tls_codec::{DeserializeBytes, Serialize as TlsSerializeTrait, VLBytes};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageIn, MlsMessageOut},
    group::{GroupEpoch, GroupId},
    key_packages::KeyPackageBundle,
    schedule::ExporterSecret,
    storage::OpenMlsProvider,
    targeted_messages::{
        create_targeted_message, derive_sender_auth_data_key_nonce, derive_sender_auth_data_secret,
        process_targeted_message, seal_targeted_message, ProcessTargetedMessageError,
        ProcessedTargetedMessage, SenderAuthDataAAD, TargetedMessage, TargetedMessageContent,
        TargetedMessageGroupContext, TargetedMessageIn, TargetedMessageSenderAuthData,
    },
    treesync::node::{
        encryption_keys::{EncryptionKey, EncryptionPrivateKey},
        leaf_node::{LeafNode, LeafNodeIn},
    },
};

/// The first Recipient Validation step that rejects a message, in the order
/// the draft's Recipient Validation section lists them.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Decode,
    GroupId,
    Epoch,
    RecipientLeafIndex,
    SenderData,
    SenderLeafIndex,
    Signature,
    Ciphertext,
    Padding,
}

impl Failure {
    fn as_str(self) -> &'static str {
        match self {
            Failure::Decode => "decode",
            Failure::GroupId => "group_id",
            Failure::Epoch => "epoch",
            Failure::RecipientLeafIndex => "recipient_leaf_index",
            Failure::SenderData => "sender_data",
            Failure::SenderLeafIndex => "sender_leaf_index",
            Failure::Signature => "signature",
            Failure::Ciphertext => "ciphertext",
            Failure::Padding => "padding",
        }
    }
}

fn default_true() -> bool {
    true
}

/// KAT vector entry
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TargetedMessageKatVector {
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub valid: bool,
    #[serde(default)]
    pub failure: Option<Failure>,
    pub cipher_suite: u16,
    #[serde(with = "hex")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    #[serde(with = "hex")]
    pub exporter_secret: Vec<u8>,
    pub sender_leaf_index: u32,
    #[serde(with = "hex")]
    pub sender_leaf_node: Vec<u8>,
    pub recipient_leaf_index: u32,
    #[serde(with = "hex")]
    pub recipient_encryption_priv: Vec<u8>,
    #[serde(with = "hex")]
    pub authenticated_data: Vec<u8>,
    #[serde(with = "hex")]
    pub application_data: Vec<u8>,
    #[serde(default)]
    pub padding_length: usize,
    #[serde(with = "hex")]
    pub targeted_message: Vec<u8>,
}

/// Fresh key material for one sender and one recipient, plus the group state
/// the recipient holds.
struct Fixture {
    ciphersuite: Ciphersuite,
    epoch: u64,
    sender_leaf_index: u32,
    recipient_leaf_index: u32,
    sender_signer: SignatureKeyPair,
    sender_leaf_node: Vec<u8>,
    recipient_encryption_key: EncryptionKey,
    recipient_encryption_priv: Vec<u8>,
    group_id: GroupId,
    exporter_secret: ExporterSecret,
    exporter_secret_bytes: Vec<u8>,
}

fn hpke_keypair(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
) -> (EncryptionKey, Vec<u8>) {
    let ikm = provider
        .rand()
        .random_vec(ciphersuite.hash_length())
        .expect("IKM generation failed");
    let keypair = provider
        .crypto()
        .derive_hpke_keypair(ciphersuite.hpke_config(), &ikm)
        .expect("HPKE keypair derivation failed");
    (
        EncryptionKey::from(keypair.public),
        (*keypair.private).to_vec(),
    )
}

fn encode(msg: TargetedMessage) -> Vec<u8> {
    MlsMessageOut::from(msg)
        .tls_serialize_detached()
        .expect("MlsMessageOut serialization failed")
}

fn flipped(bytes: &VLBytes, index: usize) -> VLBytes {
    let mut bytes = bytes.as_slice().to_vec();
    bytes[index] ^= 0x01;
    bytes.into()
}

impl Fixture {
    fn new(
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        epoch: u64,
        sender_leaf_index: u32,
        recipient_leaf_index: u32,
    ) -> Self {
        let sender_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .expect("signature keypair generation failed");
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(b"sender".to_vec()).into(),
            signature_key: sender_signer.to_public_vec().into(),
        };
        let sender_kpb =
            KeyPackageBundle::generate(provider, &sender_signer, ciphersuite, credential_with_key);
        let sender_leaf_node = sender_kpb
            .key_package()
            .leaf_node()
            .tls_serialize_detached()
            .expect("LeafNode serialization failed");

        let (recipient_encryption_key, recipient_encryption_priv) =
            hpke_keypair(provider, ciphersuite);

        let rand = provider.rand();
        let group_id = GroupId::from_slice(&rand.random_vec(16).expect("group_id failed"));
        let exporter_secret_bytes = rand
            .random_vec(ciphersuite.hash_length())
            .expect("exporter_secret generation failed");

        Self {
            ciphersuite,
            epoch,
            sender_leaf_index,
            recipient_leaf_index,
            sender_signer,
            sender_leaf_node,
            recipient_encryption_key,
            recipient_encryption_priv,
            group_id,
            exporter_secret: ExporterSecret::from_slice(&exporter_secret_bytes),
            exporter_secret_bytes,
        }
    }

    fn ctx(&self) -> TargetedMessageGroupContext<'_> {
        TargetedMessageGroupContext {
            ciphersuite: self.ciphersuite,
            group_id: &self.group_id,
            epoch: GroupEpoch::from(self.epoch),
            exporter_secret: &self.exporter_secret,
        }
    }

    /// A well-formed message from the sender to the recipient, built through
    /// the production `create_targeted_message`.
    fn create(
        &self,
        authenticated_data: &[u8],
        application_data: &[u8],
        padding: usize,
    ) -> TargetedMessage {
        create_targeted_message(
            &openmls_rust_crypto::RustCrypto::default(),
            &self.sender_signer,
            &self.ctx(),
            LeafNodeIndex::new(self.sender_leaf_index),
            LeafNodeIndex::new(self.recipient_leaf_index),
            &self.recipient_encryption_key,
            authenticated_data,
            application_data,
            padding,
        )
        .expect("create_targeted_message failed")
    }

    /// A message built from explicit parts, for vectors that need one of them
    /// to be wrong.
    #[allow(clippy::too_many_arguments)]
    fn seal(
        &self,
        ctx: &TargetedMessageGroupContext<'_>,
        signer: &impl Signer,
        sender_leaf_index: u32,
        recipient_leaf_index: u32,
        recipient_encryption_key: &EncryptionKey,
        authenticated_data: &[u8],
        content_bytes: &[u8],
    ) -> TargetedMessage {
        seal_targeted_message(
            &openmls_rust_crypto::RustCrypto::default(),
            signer,
            ctx,
            LeafNodeIndex::new(sender_leaf_index),
            LeafNodeIndex::new(recipient_leaf_index),
            recipient_encryption_key,
            authenticated_data,
            content_bytes,
        )
        .expect("seal_targeted_message failed")
    }

    /// Decrypt the sender auth data of `msg`, let `edit` change it, and
    /// re-encrypt it under the same key and nonce, so that the
    /// `sender_data` step still succeeds.
    fn reseal_sender_auth_data(
        &self,
        msg: &mut TargetedMessage,
        edit: impl FnOnce(&mut TargetedMessageSenderAuthData),
    ) {
        let crypto = openmls_rust_crypto::RustCrypto::default();
        let secret =
            derive_sender_auth_data_secret(&crypto, self.ciphersuite, &self.exporter_secret)
                .expect("sender auth data secret");
        let (key, nonce) = derive_sender_auth_data_key_nonce(
            &crypto,
            self.ciphersuite,
            &secret,
            msg.ciphertext.as_slice(),
        )
        .expect("sender auth data key/nonce");
        let aad = SenderAuthDataAAD {
            group_id: &msg.group_id,
            epoch: msg.epoch,
            recipient_leaf_index: msg.recipient_leaf_index,
        }
        .tls_serialize_detached()
        .expect("SenderAuthDataAAD serialization");
        let plaintext = key
            .aead_open(
                &crypto,
                msg.encrypted_sender_auth_data.as_slice(),
                &aad,
                &nonce,
            )
            .expect("sender auth data open");
        let mut sender_auth_data =
            TargetedMessageSenderAuthData::tls_deserialize_exact_bytes(&plaintext)
                .expect("sender auth data decode");
        edit(&mut sender_auth_data);
        let plaintext = sender_auth_data
            .tls_serialize_detached()
            .expect("sender auth data encode");
        msg.encrypted_sender_auth_data = key
            .aead_seal(&crypto, &plaintext, &aad, &nonce)
            .expect("sender auth data seal")
            .into();
    }

    fn vector(
        &self,
        description: String,
        targeted_message: Vec<u8>,
        failure: Option<Failure>,
        authenticated_data: &[u8],
        application_data: &[u8],
        padding_length: usize,
    ) -> TargetedMessageKatVector {
        let valid = failure.is_none();
        TargetedMessageKatVector {
            description,
            valid,
            failure,
            cipher_suite: u16::from(self.ciphersuite),
            group_id: self.group_id.as_slice().to_vec(),
            epoch: self.epoch,
            exporter_secret: self.exporter_secret_bytes.clone(),
            sender_leaf_index: self.sender_leaf_index,
            sender_leaf_node: self.sender_leaf_node.clone(),
            recipient_leaf_index: self.recipient_leaf_index,
            recipient_encryption_priv: self.recipient_encryption_priv.clone(),
            authenticated_data: authenticated_data.to_vec(),
            application_data: if valid {
                application_data.to_vec()
            } else {
                Vec::new()
            },
            padding_length: if valid { padding_length } else { 0 },
            targeted_message,
        }
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

struct ValidCase {
    description: &'static str,
    epoch: u64,
    sender_leaf_index: u32,
    recipient_leaf_index: u32,
    authenticated_data: &'static [u8],
    application_data_len: usize,
    padding_length: usize,
    /// HPKE ciphertext length: varint length prefix + application data +
    /// padding + 16-byte AEAD tag, computed by hand.
    ciphertext_len: usize,
}

const VALID_CASES: &[ValidCase] = &[
    ValidCase {
        description: "empty application_data, no padding: 17-byte ciphertext, shorter than KDF.Nh",
        epoch: 0,
        sender_leaf_index: 0,
        recipient_leaf_index: 1,
        authenticated_data: b"",
        application_data_len: 0,
        padding_length: 0,
        ciphertext_len: 17,
    },
    ValidCase {
        description: "31-byte ciphertext, one byte shorter than KDF.Nh",
        epoch: 1,
        sender_leaf_index: 0,
        recipient_leaf_index: 1,
        authenticated_data: b"",
        application_data_len: 14,
        padding_length: 0,
        ciphertext_len: 31,
    },
    ValidCase {
        description: "32-byte ciphertext, exactly KDF.Nh",
        epoch: 1,
        sender_leaf_index: 1,
        recipient_leaf_index: 0,
        authenticated_data: b"",
        application_data_len: 15,
        padding_length: 0,
        ciphertext_len: 32,
    },
    ValidCase {
        description: "33-byte ciphertext, one byte longer than KDF.Nh",
        epoch: 1,
        sender_leaf_index: 0,
        recipient_leaf_index: 1,
        authenticated_data: b"",
        application_data_len: 16,
        padding_length: 0,
        ciphertext_len: 33,
    },
    ValidCase {
        description:
            "typical: 40-byte application_data, non-empty authenticated_data, non-zero epoch",
        epoch: 7,
        sender_leaf_index: 3,
        recipient_leaf_index: 5,
        authenticated_data: b"request-id=42",
        application_data_len: 40,
        padding_length: 0,
        ciphertext_len: 57,
    },
    ValidCase {
        description: "long: 4096-byte application_data, 2-byte varint length prefix",
        epoch: 1000,
        sender_leaf_index: 5,
        recipient_leaf_index: 3,
        authenticated_data: b"long",
        application_data_len: 4096,
        padding_length: 0,
        ciphertext_len: 4114,
    },
    ValidCase {
        description: "large padding: 2-byte application_data, 256 bytes of zero padding",
        epoch: 42,
        sender_leaf_index: 3,
        recipient_leaf_index: 7,
        authenticated_data: b"",
        application_data_len: 2,
        padding_length: 256,
        ciphertext_len: 275,
    },
];

fn valid_vectors(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
) -> Vec<TargetedMessageKatVector> {
    VALID_CASES
        .iter()
        .map(|c| {
            let f = Fixture::new(
                provider,
                ciphersuite,
                c.epoch,
                c.sender_leaf_index,
                c.recipient_leaf_index,
            );
            let application_data = pattern(c.application_data_len);
            let msg = f.create(c.authenticated_data, &application_data, c.padding_length);
            assert_eq!(
                msg.ciphertext.as_slice().len(),
                c.ciphertext_len,
                "{}",
                c.description
            );
            f.vector(
                c.description.to_string(),
                encode(msg),
                None,
                c.authenticated_data,
                &application_data,
                c.padding_length,
            )
        })
        .collect()
}

/// One vector per Recipient Validation step. The receiver is leaf 5 at epoch
/// 7, the sender is leaf 3, and leaf 4 is blank.
fn invalid_vectors(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
) -> Vec<TargetedMessageKatVector> {
    const AD: &[u8] = b"request-id=42";
    let app = pattern(40);
    let new = || Fixture::new(provider, ciphersuite, 7, 3, 5);
    let content = |padding: &[u8]| {
        let mut bytes = TargetedMessageContent::new(&app, 0)
            .serialize_detached()
            .expect("content serialization");
        bytes.extend_from_slice(padding);
        bytes
    };
    let mut out = Vec::new();
    let mut push = |f: &Fixture, failure: Failure, description: &str, msg: Vec<u8>| {
        out.push(f.vector(description.to_string(), msg, Some(failure), AD, &[], 0));
    };

    let f = new();
    let mut bytes = encode(f.create(AD, &app, 0));
    bytes.pop();
    push(
        &f,
        Failure::Decode,
        "targeted_message truncated by one byte",
        bytes,
    );

    let f = new();
    let other_group = GroupId::from_slice(b"some other group");
    let ctx = TargetedMessageGroupContext {
        group_id: &other_group,
        ..f.ctx()
    };
    let msg = f.seal(
        &ctx,
        &f.sender_signer,
        3,
        5,
        &f.recipient_encryption_key,
        AD,
        &content(&[]),
    );
    push(
        &f,
        Failure::GroupId,
        "valid message for a different group_id",
        encode(msg),
    );

    let f = new();
    let ctx = TargetedMessageGroupContext {
        epoch: GroupEpoch::from(6),
        ..f.ctx()
    };
    let msg = f.seal(
        &ctx,
        &f.sender_signer,
        3,
        5,
        &f.recipient_encryption_key,
        AD,
        &content(&[]),
    );
    push(
        &f,
        Failure::Epoch,
        "valid message for the previous epoch, which the receiver does not retain",
        encode(msg),
    );

    let f = new();
    let msg = f.seal(
        &f.ctx(),
        &f.sender_signer,
        3,
        6,
        &f.recipient_encryption_key,
        AD,
        &content(&[]),
    );
    push(
        &f,
        Failure::RecipientLeafIndex,
        "valid message addressed to leaf 6; the receiver is leaf 5",
        encode(msg),
    );

    let f = new();
    let mut msg = f.create(AD, &app, 0);
    msg.encrypted_sender_auth_data = flipped(&msg.encrypted_sender_auth_data, 0);
    push(
        &f,
        Failure::SenderData,
        "first byte of encrypted_sender_auth_data flipped",
        encode(msg),
    );

    let f = new();
    let mut msg = f.create(AD, &app, 0);
    msg.ciphertext = flipped(&msg.ciphertext, 0);
    push(&f, Failure::SenderData, "first byte of ciphertext flipped: changes the KDF.Nh sample, so the sender data key and nonce change", encode(msg));

    let f = new();
    let msg = f.seal(
        &f.ctx(),
        &f.sender_signer,
        4,
        5,
        &f.recipient_encryption_key,
        AD,
        &content(&[]),
    );
    push(
        &f,
        Failure::SenderLeafIndex,
        "sender data decrypts and names leaf 4, which is blank",
        encode(msg),
    );

    let f = new();
    let mut msg = f.create(AD, &app, 0);
    let last = msg.ciphertext.as_slice().len() - 1;
    assert!(
        last >= ciphersuite.hash_length(),
        "flip must be outside the sample"
    );
    msg.ciphertext = flipped(&msg.ciphertext, last);
    push(&f, Failure::Signature, "last byte of ciphertext flipped, outside the KDF.Nh sample: ciphertext_hash no longer matches", encode(msg));

    let f = new();
    let mut msg = f.create(AD, &app, 0);
    f.reseal_sender_auth_data(&mut msg, |s| s.kem_output = flipped(&s.kem_output, 0));
    push(
        &f,
        Failure::Signature,
        "first byte of kem_output flipped and sender data re-encrypted",
        encode(msg),
    );

    let f = new();
    let mut msg = f.create(AD, &app, 0);
    msg.authenticated_data = flipped(&msg.authenticated_data, 0);
    push(
        &f,
        Failure::Signature,
        "first byte of authenticated_data flipped",
        encode(msg),
    );

    let f = new();
    let other_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .expect("signature keypair generation failed");
    let msg = f.seal(
        &f.ctx(),
        &other_signer,
        3,
        5,
        &f.recipient_encryption_key,
        AD,
        &content(&[]),
    );
    push(
        &f,
        Failure::Signature,
        "signed by a key that is not the signature key of sender_leaf_node",
        encode(msg),
    );

    let f = new();
    let (wrong_key, _) = hpke_keypair(provider, ciphersuite);
    let msg = f.seal(
        &f.ctx(),
        &f.sender_signer,
        3,
        5,
        &wrong_key,
        AD,
        &content(&[]),
    );
    push(
        &f,
        Failure::Ciphertext,
        "correctly signed, but HPKE-encrypted to a key other than the recipient's leaf key",
        encode(msg),
    );

    let f = new();
    let msg = f.seal(
        &f.ctx(),
        &f.sender_signer,
        3,
        5,
        &f.recipient_encryption_key,
        AD,
        &content(&[0, 0, 1, 0]),
    );
    push(
        &f,
        Failure::Padding,
        "correctly signed and decryptable, but the third of four padding bytes is 0x01",
        encode(msg),
    );

    out
}

/// Generate the full vector set for cipher suites 1, 2 and 3.
pub fn generate_vectors(provider: &impl OpenMlsProvider) -> Vec<TargetedMessageKatVector> {
    [
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    ]
    .into_iter()
    .flat_map(|cs| {
        let mut v = valid_vectors(provider, cs);
        v.extend(invalid_vectors(provider, cs));
        v
    })
    .collect()
}

/// Format KAT vectors in the `key: hex` style customary in IETF drafts.
pub fn vectors_to_text(vectors: &[TargetedMessageKatVector]) -> String {
    let mut out = String::new();
    for (i, v) in vectors.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        append_vector_text(&mut out, i + 1, v);
    }
    out
}

fn append_vector_text(out: &mut String, number: usize, v: &TargetedMessageKatVector) {
    use std::fmt::Write;
    let _ = writeln!(out, "# Vector {number}");
    let _ = writeln!(out, "description: {}", v.description);
    let _ = writeln!(out, "valid: {}", v.valid);
    if let Some(failure) = v.failure {
        let _ = writeln!(out, "failure: {}", failure.as_str());
    }
    let _ = writeln!(out, "cipher_suite: {}", v.cipher_suite);
    let _ = writeln!(out, "epoch: {}", v.epoch);
    let _ = writeln!(out, "sender_leaf_index: {}", v.sender_leaf_index);
    let _ = writeln!(out, "recipient_leaf_index: {}", v.recipient_leaf_index);
    let _ = writeln!(out, "padding_length: {}", v.padding_length);
    write_hex_field(out, "group_id", &v.group_id);
    write_hex_field(out, "exporter_secret", &v.exporter_secret);
    write_hex_field(out, "sender_leaf_node", &v.sender_leaf_node);
    write_hex_field(
        out,
        "recipient_encryption_priv",
        &v.recipient_encryption_priv,
    );
    write_hex_field(out, "authenticated_data", &v.authenticated_data);
    write_hex_field(out, "application_data", &v.application_data);
    write_hex_field(out, "targeted_message", &v.targeted_message);
}

fn write_hex_field(out: &mut String, name: &str, bytes: &[u8]) {
    use std::fmt::Write;
    const LINE_LIMIT: usize = 72;
    const WRAP: usize = 64;
    let encoded = hex::encode(bytes);
    if encoded.is_empty() {
        let _ = writeln!(out, "{name}:");
        return;
    }
    if name.len() + 2 + encoded.len() <= LINE_LIMIT {
        let _ = writeln!(out, "{name}: {encoded}");
        return;
    }
    let _ = writeln!(out, "{name}:");
    for chunk in encoded.as_bytes().chunks(WRAP) {
        let line = std::str::from_utf8(chunk).expect("hex output is ASCII");
        let _ = writeln!(out, "  {line}");
    }
}

/// Map an OpenMLS processing error to the Recipient Validation step it
/// reports. `MalformedContent` covers both a non-zero padding byte and an
/// undecodable `application_data` length prefix; OpenMLS cannot tell them
/// apart, so both are reported as `padding`.
fn failure_of(
    e: ProcessTargetedMessageError<core::convert::Infallible>,
) -> Result<Failure, String> {
    use ProcessTargetedMessageError as E;
    Ok(match e {
        E::GroupIdMismatch => Failure::GroupId,
        E::EpochMismatch => Failure::Epoch,
        E::NotIntendedRecipient => Failure::RecipientLeafIndex,
        E::SenderAuthDataDecryptionFailed | E::MalformedSenderAuthData => Failure::SenderData,
        E::SenderNotFound => Failure::SenderLeafIndex,
        E::SignatureVerificationFailed => Failure::Signature,
        E::ContentDecryptionFailed => Failure::Ciphertext,
        E::MalformedContent => Failure::Padding,
        e @ (E::GroupNotActive | E::StorageError(_) | E::LibraryError(_)) => {
            return Err(format!("unexpected error: {e}"))
        }
    })
}

/// Run receiver processing on a vector. `Err` means the vector's receiver
/// state is unusable or processing failed for a reason that is not a
/// Recipient Validation step.
fn process_vector(
    vector: &TargetedMessageKatVector,
    crypto: &impl OpenMlsCrypto,
) -> Result<Result<ProcessedTargetedMessage, Failure>, String> {
    let ciphersuite = Ciphersuite::try_from(vector.cipher_suite)
        .map_err(|e| format!("unknown cipher_suite {}: {e:?}", vector.cipher_suite))?;
    let (sender_leaf_in, rest) = LeafNodeIn::tls_deserialize_bytes(&vector.sender_leaf_node)
        .map_err(|e| format!("sender_leaf_node does not decode: {e}"))?;
    if !rest.is_empty() {
        return Err("trailing bytes after sender_leaf_node".into());
    }
    let sender_leaf: LeafNode = sender_leaf_in.into();

    let group_id = GroupId::from_slice(&vector.group_id);
    let exporter_secret = ExporterSecret::from_slice(&vector.exporter_secret);
    let ctx = TargetedMessageGroupContext {
        ciphersuite,
        group_id: &group_id,
        epoch: GroupEpoch::from(vector.epoch),
        exporter_secret: &exporter_secret,
    };
    let private_key = EncryptionPrivateKey::from(vector.recipient_encryption_priv.clone());

    // Only the sender's leaf is looked up during processing; the recipient's
    // own leaf is not needed and stays `None`.
    let leaves_len = vector.sender_leaf_index.max(vector.recipient_leaf_index) as usize + 1;
    let mut leaves: Vec<Option<&LeafNode>> = vec![None; leaves_len];
    leaves[vector.sender_leaf_index as usize] = Some(&sender_leaf);

    let targeted: TargetedMessageIn =
        match MlsMessageIn::tls_deserialize_bytes(&vector.targeted_message) {
            Ok((mls_in, [])) => match mls_in.into_targeted_message() {
                Some(t) => t,
                None => return Ok(Err(Failure::Decode)),
            },
            _ => return Ok(Err(Failure::Decode)),
        };

    match process_targeted_message(
        crypto,
        &ctx,
        LeafNodeIndex::new(vector.recipient_leaf_index),
        &private_key,
        &targeted,
        &leaves,
    ) {
        Ok(processed) => Ok(Ok(processed)),
        Err(e) => failure_of(e).map(Err),
    }
}

/// Check one vector. Returns the outcome OpenMLS reported (`accepted`, a
/// `failure` value, or `error`) and whether it matches the vector.
pub fn check_vector(
    vector: &TargetedMessageKatVector,
    crypto: &impl OpenMlsCrypto,
) -> (&'static str, Result<(), String>) {
    if vector.valid == vector.failure.is_some() {
        return (
            "error",
            Err("inconsistent vector: `failure` must be null exactly when `valid` is true".into()),
        );
    }
    match process_vector(vector, crypto) {
        Err(e) => ("error", Err(e)),
        Ok(Err(reported)) => {
            let result = if Some(reported) == vector.failure {
                Ok(())
            } else {
                Err(format!(
                    "rejected at {}, expected {}",
                    reported.as_str(),
                    vector.failure.map_or("acceptance", Failure::as_str)
                ))
            };
            (reported.as_str(), result)
        }
        Ok(Ok(p)) => {
            let mut mismatches = Vec::new();
            if !vector.valid {
                mismatches.push(format!(
                    "accepted, expected rejection at {}",
                    vector.failure.map_or("?", Failure::as_str)
                ));
            } else {
                if p.sender_leaf_index().u32() != vector.sender_leaf_index {
                    mismatches.push("sender_leaf_index".to_string());
                }
                if p.application_data() != vector.application_data.as_slice() {
                    mismatches.push("application_data".to_string());
                }
                if p.authenticated_data() != vector.authenticated_data.as_slice() {
                    mismatches.push("authenticated_data".to_string());
                }
                if p.padding_length() != vector.padding_length {
                    mismatches.push(format!(
                        "padding_length {} != {}",
                        p.padding_length(),
                        vector.padding_length
                    ));
                }
            }
            let result = if mismatches.is_empty() {
                Ok(())
            } else {
                Err(mismatches.join(", "))
            };
            ("accepted", result)
        }
    }
}

pub fn verify_kat_vector(vector: &TargetedMessageKatVector, crypto: &impl OpenMlsCrypto) {
    let (reported, result) = check_vector(vector, crypto);
    if let Err(e) = result {
        panic!(
            "KAT vector {:?} failed (reported {reported}): {e}",
            vector.description
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_test::openmls_test;

    #[openmls_test]
    fn read_checked_in_vectors() {
        let provider = Provider::default();
        let cs_u16 = u16::from(ciphersuite);

        // The draft's vectors, the extended valid and invalid set, and a
        // freshly regenerated set if `write_kats` was run.
        for (path, required) in [
            ("test_vectors/targeted-messages.json", true),
            ("test_vectors/targeted-messages-extended.json", true),
            ("test_vectors/targeted-messages-new.json", false),
        ] {
            let file = match std::fs::File::open(path) {
                Ok(file) => file,
                Err(e) if required => panic!("{path}: {e}"),
                Err(_) => continue,
            };
            let vectors: Vec<TargetedMessageKatVector> =
                serde_json::from_reader(file).unwrap_or_else(|e| panic!("invalid {path}: {e}"));
            let mut verified = 0;
            for vector in vectors.iter().filter(|v| v.cipher_suite == cs_u16) {
                verify_kat_vector(vector, provider.crypto());
                verified += 1;
            }
            log::info!("{path}: verified {verified} entries for {ciphersuite:?}");
        }
    }

    /// Regenerate `test_vectors/targeted-messages-new.{json,txt}`.
    #[test]
    #[ignore]
    fn write_kats() {
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        let vectors = generate_vectors(&provider);

        let file = std::fs::File::create("test_vectors/targeted-messages-new.json")
            .expect("Failed to create test_vectors/targeted-messages-new.json");
        serde_json::to_writer_pretty(file, &vectors)
            .expect("Failed to serialize KAT vectors to JSON");

        // Generate a human-readable version of the vectors for the draft
        std::fs::write(
            "test_vectors/targeted-messages-new.txt",
            vectors_to_text(&vectors),
        )
        .expect("Failed to write test_vectors/targeted-messages-new.txt");
    }

    /// Check every vector in the file named by `TM_VECTORS`, printing one
    /// line per vector: index, PASS/FAIL, reported step, description.
    #[test]
    #[ignore]
    fn verify_vector_file() {
        let path = std::env::var("TM_VECTORS").expect("set TM_VECTORS to a vector file path");
        let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let vectors: Vec<TargetedMessageKatVector> =
            serde_json::from_reader(file).unwrap_or_else(|e| panic!("invalid {path}: {e}"));
        let crypto = openmls_rust_crypto::RustCrypto::default();

        let mut failed = 0;
        for (i, v) in vectors.iter().enumerate() {
            let (reported, result) = check_vector(v, &crypto);
            match result {
                Ok(()) => println!(
                    "{i:3} suite {} PASS {reported:<20} {}",
                    v.cipher_suite, v.description
                ),
                Err(e) => {
                    failed += 1;
                    println!(
                        "{i:3} suite {} FAIL {reported:<20} {} -- {e}",
                        v.cipher_suite, v.description
                    );
                }
            }
        }
        println!("{path}: {} vectors, {failed} failed", vectors.len());
        assert_eq!(failed, 0, "{failed} of {} vectors failed", vectors.len());
    }
}
