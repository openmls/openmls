//! KAT vectors for targeted messages.
//!
//! Vectors follow the receiver-side format of the draft's Test Vectors
//! appendix, extended with `valid`, `failure` and `description` so that a
//! vector can also describe a message that the recipient MUST reject, together
//! with the first Recipient Validation step that rejects it.

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, types::Ciphersuite};
use serde::{Deserialize, Serialize};
use tls_codec::{DeserializeBytes, Serialize as TlsSerializeTrait};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageIn, MlsMessageOut},
    group::{GroupEpoch, GroupId},
    key_packages::KeyPackageBundle,
    schedule::ExporterSecret,
    storage::OpenMlsProvider,
    targeted_messages::{
        create_targeted_message, process_targeted_message, ProcessTargetedMessageError,
        ProcessedTargetedMessage, TargetedMessageGroupContext, TargetedMessageIn,
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

#[allow(clippy::too_many_arguments)]
pub fn generate_kat_vector(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    epoch: u64,
    sender_leaf_index: u32,
    recipient_leaf_index: u32,
    authenticated_data: &[u8],
    application_data: &[u8],
    padding_length: usize,
) -> TargetedMessageKatVector {
    let crypto = provider.crypto();
    let rand = provider.rand();

    let sender_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .expect("signature keypair generation failed");
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(b"sender".to_vec()).into(),
        signature_key: sender_signer.to_public_vec().into(),
    };
    let sender_kpb =
        KeyPackageBundle::generate(provider, &sender_signer, ciphersuite, credential_with_key);
    let sender_leaf = sender_kpb.key_package().leaf_node().clone();
    let sender_leaf_node_bytes = sender_leaf
        .tls_serialize_detached()
        .expect("LeafNode serialization failed");

    let ikm = rand
        .random_vec(ciphersuite.hash_length())
        .expect("IKM generation failed");
    let hpke_keypair = crypto
        .derive_hpke_keypair(ciphersuite.hpke_config(), &ikm)
        .expect("HPKE keypair derivation failed");
    let recipient_encryption_key = EncryptionKey::from(hpke_keypair.public);
    let recipient_encryption_priv_bytes: Vec<u8> = (*hpke_keypair.private).to_vec();

    let group_id_bytes = rand.random_vec(16).expect("group_id generation failed");
    let group_id = GroupId::from_slice(&group_id_bytes);
    let exporter_secret_bytes = rand
        .random_vec(ciphersuite.hash_length())
        .expect("exporter_secret generation failed");
    let exporter_secret = ExporterSecret::from_slice(&exporter_secret_bytes);

    let ctx = TargetedMessageGroupContext {
        ciphersuite,
        group_id: &group_id,
        epoch: GroupEpoch::from(epoch),
        exporter_secret: &exporter_secret,
    };

    let msg = create_targeted_message(
        crypto,
        &sender_signer,
        &ctx,
        LeafNodeIndex::new(sender_leaf_index),
        LeafNodeIndex::new(recipient_leaf_index),
        &recipient_encryption_key,
        authenticated_data,
        application_data,
        padding_length,
    )
    .expect("create_targeted_message failed");

    let mls_out: MlsMessageOut = msg.into();
    let targeted_message_bytes = mls_out
        .tls_serialize_detached()
        .expect("MlsMessageOut serialization failed");

    TargetedMessageKatVector {
        description: String::new(),
        valid: true,
        failure: None,
        cipher_suite: u16::from(ciphersuite),
        group_id: group_id_bytes,
        epoch,
        exporter_secret: exporter_secret_bytes,
        sender_leaf_index,
        sender_leaf_node: sender_leaf_node_bytes,
        recipient_leaf_index,
        recipient_encryption_priv: recipient_encryption_priv_bytes,
        authenticated_data: authenticated_data.to_vec(),
        application_data: application_data.to_vec(),
        padding_length,
        targeted_message: targeted_message_bytes,
    }
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

    struct Scenario {
        epoch: u64,
        sender_leaf_index: u32,
        recipient_leaf_index: u32,
        authenticated_data: &'static [u8],
        application_data: &'static [u8],
        padding_length: usize,
    }

    const SCENARIOS: &[Scenario] = &[
        Scenario {
            epoch: 1,
            sender_leaf_index: 0,
            recipient_leaf_index: 1,
            authenticated_data: b"",
            application_data: b"KAT test payload for targeted messages",
            padding_length: 0,
        },
        Scenario {
            epoch: 5,
            sender_leaf_index: 0,
            recipient_leaf_index: 2,
            authenticated_data: b"request-id=42",
            application_data: b"second targeted payload",
            padding_length: 64,
        },
        Scenario {
            epoch: 42,
            sender_leaf_index: 3,
            recipient_leaf_index: 7,
            authenticated_data: b"",
            application_data: b"",
            padding_length: 128,
        },
    ];

    #[openmls_test]
    fn read_checked_in_vectors() {
        let provider = Provider::default();
        let cs_u16 = u16::from(ciphersuite);

        let committed = "test_vectors/targeted-messages.json";
        let regenerated = "test_vectors/targeted-messages-new.json";

        let file = std::fs::File::open(committed).unwrap_or_else(|_| panic!("{committed} missing"));
        let vectors: Vec<TargetedMessageKatVector> =
            serde_json::from_reader(file).unwrap_or_else(|e| panic!("invalid {committed}: {e}"));
        let mut verified = 0;
        for vector in vectors.iter().filter(|v| v.cipher_suite == cs_u16) {
            verify_kat_vector(vector, provider.crypto());
            verified += 1;
        }
        log::info!("{committed}: verified {verified} entries for {ciphersuite:?}");

        if let Ok(file) = std::fs::File::open(regenerated) {
            let vectors: Vec<TargetedMessageKatVector> = serde_json::from_reader(file)
                .unwrap_or_else(|e| panic!("invalid {regenerated}: {e}"));
            let mut verified = 0;
            for vector in vectors.iter().filter(|v| v.cipher_suite == cs_u16) {
                verify_kat_vector(vector, provider.crypto());
                verified += 1;
            }
            log::info!("{regenerated}: verified {verified} entries for {ciphersuite:?}");
        }
    }

    #[test]
    #[ignore]
    fn write_kats() {
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        // We only generate vectors for one ciphersuite since we only want to
        // test the targeted message logic
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let vectors: Vec<_> = SCENARIOS
            .iter()
            .map(|s| {
                generate_kat_vector(
                    &provider,
                    ciphersuite,
                    s.epoch,
                    s.sender_leaf_index,
                    s.recipient_leaf_index,
                    s.authenticated_data,
                    s.application_data,
                    s.padding_length,
                )
            })
            .collect();

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
