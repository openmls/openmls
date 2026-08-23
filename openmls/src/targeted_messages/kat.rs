//! KAT vectors for targeted messages.

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
        create_targeted_message, process_targeted_message, TargetedMessageGroupContext,
        TargetedMessageIn,
    },
    treesync::node::{
        encryption_keys::{EncryptionKey, EncryptionPrivateKey},
        leaf_node::{LeafNode, LeafNodeIn},
    },
};

/// KAT vector entry
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TargetedMessageKatVector {
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

pub fn verify_kat_vector(vector: &TargetedMessageKatVector, crypto: &impl OpenMlsCrypto) {
    let ciphersuite =
        Ciphersuite::try_from(vector.cipher_suite).expect("Unknown ciphersuite in KAT vector");

    let (mls_in, rest) = MlsMessageIn::tls_deserialize_bytes(&vector.targeted_message)
        .expect("Failed to deserialize MlsMessage from KAT vector");
    assert!(rest.is_empty(), "trailing bytes after MlsMessage");

    let targeted: TargetedMessageIn = mls_in
        .into_targeted_message()
        .expect("Vector message is not a targeted message");

    assert_eq!(targeted.group_id().as_slice(), vector.group_id.as_slice());
    assert_eq!(targeted.epoch().as_u64(), vector.epoch);
    assert_eq!(targeted.recipient_leaf_index(), vector.recipient_leaf_index);
    assert_eq!(
        targeted.authenticated_data(),
        vector.authenticated_data.as_slice()
    );

    let group_id = GroupId::from_slice(&vector.group_id);
    let epoch = GroupEpoch::from(vector.epoch);
    let exporter_secret = ExporterSecret::from_slice(&vector.exporter_secret);

    let ctx = TargetedMessageGroupContext {
        ciphersuite,
        group_id: &group_id,
        epoch,
        exporter_secret: &exporter_secret,
    };

    let recipient_index = LeafNodeIndex::new(vector.recipient_leaf_index);
    let private_key = EncryptionPrivateKey::from(vector.recipient_encryption_priv.clone());

    let (sender_leaf_in, rest) = LeafNodeIn::tls_deserialize_bytes(&vector.sender_leaf_node)
        .expect("Failed to deserialize sender LeafNode");
    assert!(rest.is_empty(), "trailing bytes after sender LeafNode");
    let sender_leaf: LeafNode = sender_leaf_in.into();

    let leaves_len = vector
        .sender_leaf_index
        .max(vector.recipient_leaf_index)
        .saturating_add(1) as usize;
    let mut leaves: Vec<Option<&LeafNode>> = vec![None; leaves_len];
    leaves[vector.sender_leaf_index as usize] = Some(&sender_leaf);

    let processed = process_targeted_message::<core::convert::Infallible>(
        crypto,
        &ctx,
        recipient_index,
        &private_key,
        &targeted,
        &leaves,
    )
    .expect("KAT vector failed to decrypt/verify");

    assert_eq!(
        processed.sender_leaf_index().u32(),
        vector.sender_leaf_index
    );
    assert_eq!(
        processed.application_data(),
        vector.application_data.as_slice()
    );
    assert_eq!(
        processed.authenticated_data(),
        vector.authenticated_data.as_slice()
    );
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
}
