//! # Known Answer Tests for the transcript hashes
//!
//! See https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md
//! for more description on the test vectors.

use std::convert::TryFrom;

use crate::{
    ciphersuite::{CiphersuiteName, Secret, Signature},
    codec::Codec,
    config::Config,
    group::{
        update_confirmed_transcript_hash, update_interim_transcript_hash, GroupContext, GroupEpoch,
        GroupId,
    },
    messages::{Commit, ConfirmationTag},
    prelude::{
        random_u32, random_u64, randombytes, sender::SenderType, ContentType, LeafIndex,
        MLSPlaintext, MLSPlaintextCommitAuthData, MLSPlaintextCommitContent,
        MLSPlaintextContentType, Sender,
    },
    schedule::{ConfirmationKey, MembershipKey},
    test_util::{bytes_to_hex, hex_to_bytes, read, write},
};

use serde::{self, Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct TranscriptTestVector {
    cipher_suite: u16,
    group_id: String,
    epoch: u64,
    tree_hash_before: String,
    confirmed_transcript_hash_before: String,
    interim_transcript_hash_before: String,
    membership_key: String,
    confirmation_key: String,
    commit: String, // TLS serialized MLSPlaintext(Commit)

    confirmed_transcript_hash_after: String,
    interim_transcript_hash_after: String,
}

#[test]
fn generate_test_vectors() {
    let mut tests = Vec::new();
    const NUM_TESTS: usize = 100;

    for ciphersuite in Config::supported_ciphersuites() {
        for _ in 0..NUM_TESTS {
            // Generate random values.
            let group_id = GroupId::random();
            let epoch = random_u64();
            let tree_hash_before = randombytes(ciphersuite.hash_length());
            let confirmed_transcript_hash_before = randombytes(ciphersuite.hash_length());
            let interim_transcript_hash_before = randombytes(ciphersuite.hash_length());
            let membership_key =
                MembershipKey::from_secret(Secret::random(ciphersuite.hash_length()));
            let confirmation_key =
                ConfirmationKey::from_secret(Secret::random(ciphersuite.hash_length()));

            // Build plaintext commit message.
            let mut commit = MLSPlaintext {
                group_id: GroupId::random(),
                epoch: GroupEpoch(epoch),
                sender: Sender {
                    sender_type: SenderType::Member,
                    sender: LeafIndex::from(random_u32()),
                },
                authenticated_data: randombytes(48),
                content_type: ContentType::Commit,
                content: MLSPlaintextContentType::Commit(Commit {
                    proposals: vec![],
                    path: None,
                }),
                signature: Signature::new_empty(),
                confirmation_tag: None,
                membership_tag: None,
            };
            let context = GroupContext::new(
                group_id.clone(),
                GroupEpoch(epoch),
                tree_hash_before.clone(),
                confirmed_transcript_hash_before.clone(),
                &[], // extensions
            )
            .expect("Error creating group context");
            let confirmation_tag = ConfirmationTag::new(
                ciphersuite,
                &confirmation_key,
                &confirmed_transcript_hash_before,
            );
            commit.confirmation_tag = Some(confirmation_tag);
            commit
                .add_membership_tag(ciphersuite, context.serialized(), &membership_key)
                .expect("Error adding membership tag");

            // Compute new transcript hashes.
            let confirmed_transcript_hash_after = update_confirmed_transcript_hash(
                ciphersuite,
                &MLSPlaintextCommitContent::try_from(&commit).unwrap(),
                &interim_transcript_hash_before,
            )
            .expect("Error updating confirmed transcript hash");

            let interim_transcript_hash_after = update_interim_transcript_hash(
                &ciphersuite,
                &MLSPlaintextCommitAuthData::try_from(&commit).unwrap(),
                &confirmed_transcript_hash_after,
            )
            .expect("Error updating interim transcript hash");

            let test = TranscriptTestVector {
                cipher_suite: ciphersuite.name() as u16,
                group_id: bytes_to_hex(&group_id.as_slice()),
                epoch,
                tree_hash_before: bytes_to_hex(&tree_hash_before),
                confirmed_transcript_hash_before: bytes_to_hex(&confirmed_transcript_hash_before),
                interim_transcript_hash_before: bytes_to_hex(&interim_transcript_hash_before),
                membership_key: bytes_to_hex(membership_key.as_slice()),
                confirmation_key: bytes_to_hex(confirmation_key.as_slice()),
                commit: bytes_to_hex(&commit.encode_detached().expect("Error encoding commit")),

                confirmed_transcript_hash_after: bytes_to_hex(&confirmed_transcript_hash_after),
                interim_transcript_hash_after: bytes_to_hex(&interim_transcript_hash_after),
            };
            tests.push(test);
        }
    }

    write("test_vectors/kat_transcripts-new.json", &tests);
}

#[test]
fn run_test_vectors() {
    let tests: Vec<TranscriptTestVector> = read("test_vectors/kat_transcripts.json");

    for test_vector in tests {
        let ciphersuite =
            CiphersuiteName::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");
        let ciphersuite = match Config::ciphersuite(ciphersuite) {
            Ok(cs) => cs,
            Err(_) => {
                println!(
                    "Unsupported ciphersuite {} in test vector. Skipping ...",
                    ciphersuite
                );
                continue;
            }
        };
        println!("Testing test vector for ciphersuite {:?}", ciphersuite);

        // Read input values.
        let group_id = GroupId {
            value: hex_to_bytes(&test_vector.group_id),
        };
        let epoch = test_vector.epoch;
        let tree_hash_before = hex_to_bytes(&test_vector.tree_hash_before);
        let confirmed_transcript_hash_before =
            hex_to_bytes(&test_vector.confirmed_transcript_hash_before);
        let interim_transcript_hash_before =
            hex_to_bytes(&test_vector.interim_transcript_hash_before);
        let membership_key =
            MembershipKey::from_secret(Secret::from(hex_to_bytes(&test_vector.membership_key)));
        let confirmation_key =
            ConfirmationKey::from_secret(Secret::from(hex_to_bytes(&test_vector.confirmation_key)));

        // Check membership and confirmation tags.
        let commit = MLSPlaintext::decode_detached(&hex_to_bytes(&test_vector.commit))
            .expect("Error decoding commit");
        let context = GroupContext::new(
            group_id.clone(),
            GroupEpoch(epoch),
            tree_hash_before.clone(),
            confirmed_transcript_hash_before.clone(),
            &[], // extensions
        )
        .expect("Error creating group context");
        assert!(commit
            .verify_membership_tag(ciphersuite, context.serialized(), &membership_key)
            .is_ok());

        let my_confirmation_tag = ConfirmationTag::new(
            &ciphersuite,
            &confirmation_key,
            &confirmed_transcript_hash_before,
        );
        assert_eq!(
            &my_confirmation_tag,
            commit
                .confirmation_tag
                .as_ref()
                .expect("Confirmation tag is missing")
        );

        // Compute new transcript hashes.
        let my_confirmed_transcript_hash_after = update_confirmed_transcript_hash(
            ciphersuite,
            &MLSPlaintextCommitContent::try_from(&commit).unwrap(),
            &interim_transcript_hash_before,
        )
        .expect("Error updating confirmed transcript hash");
        assert_eq!(
            &my_confirmed_transcript_hash_after,
            &hex_to_bytes(&test_vector.confirmed_transcript_hash_after)
        );

        let my_interim_transcript_hash_after = update_interim_transcript_hash(
            &ciphersuite,
            &MLSPlaintextCommitAuthData::try_from(&commit).unwrap(),
            &my_confirmed_transcript_hash_after,
        )
        .expect("Error updating interim transcript hash");
        assert_eq!(
            &my_interim_transcript_hash_after,
            &hex_to_bytes(&test_vector.interim_transcript_hash_after)
        );
    }
}
