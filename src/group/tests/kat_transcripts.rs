//! # Known Answer Tests for the transcript hashes
//!
//! See https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md
//! for more description on the test vectors.

use std::convert::TryFrom;

#[cfg(test)]
use crate::test_util::{read, write};

use crate::{
    ciphersuite::{Ciphersuite, CiphersuiteName, Secret, Signature},
    codec::Codec,
    config::{Config, ProtocolVersion},
    group::{
        update_confirmed_transcript_hash, update_interim_transcript_hash, GroupContext, GroupEpoch,
        GroupId,
    },
    messages::Commit,
    prelude::{
        random_u32, random_u64, randombytes, sender::SenderType, ContentType, LeafIndex,
        MlsPlaintext, MlsPlaintextCommitAuthData, MlsPlaintextCommitContent,
        MlsPlaintextContentType, Sender,
    },
    schedule::{ConfirmationKey, MembershipKey},
    test_util::{bytes_to_hex, hex_to_bytes},
};

use serde::{self, Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TranscriptTestVector {
    cipher_suite: u16,
    group_id: String,
    epoch: u64,
    tree_hash_before: String,
    confirmed_transcript_hash_before: String,
    interim_transcript_hash_before: String,
    membership_key: String,
    confirmation_key: String,
    commit: String, // TLS serialized MlsPlaintext(Commit)

    confirmed_transcript_hash_after: String,
    interim_transcript_hash_after: String,
}

pub fn generate_test_vector(ciphersuite: &'static Ciphersuite) -> TranscriptTestVector {
    // Generate random values.
    let group_id = GroupId::random();
    let epoch = random_u64();
    let tree_hash_before = randombytes(ciphersuite.hash_length());
    let confirmed_transcript_hash_before = randombytes(ciphersuite.hash_length());
    let interim_transcript_hash_before = randombytes(ciphersuite.hash_length());
    let membership_key =
        MembershipKey::from_secret(Secret::random(ciphersuite, None /* MLS version */));
    let confirmation_key =
        ConfirmationKey::from_secret(Secret::random(ciphersuite, None /* MLS version */));

    // Build plaintext commit message.
    let mut commit = MlsPlaintext {
        group_id: group_id.clone(),
        epoch: GroupEpoch(epoch),
        sender: Sender {
            sender_type: SenderType::Member,
            sender: LeafIndex::from(random_u32()),
        },
        authenticated_data: randombytes(48),
        content_type: ContentType::Commit,
        content: MlsPlaintextContentType::Commit(Commit {
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
    let confirmation_tag = confirmation_key.tag(&confirmed_transcript_hash_before);
    commit.confirmation_tag = Some(confirmation_tag);
    commit
        .add_membership_tag(context.serialized(), &membership_key)
        .expect("Error adding membership tag");

    // Compute new transcript hashes.
    let confirmed_transcript_hash_after = update_confirmed_transcript_hash(
        ciphersuite,
        &MlsPlaintextCommitContent::try_from(&commit).unwrap(),
        &interim_transcript_hash_before,
    )
    .expect("Error updating confirmed transcript hash");

    let interim_transcript_hash_after = update_interim_transcript_hash(
        &ciphersuite,
        &MlsPlaintextCommitAuthData::try_from(&commit).unwrap(),
        &confirmed_transcript_hash_after,
    )
    .expect("Error updating interim transcript hash");

    TranscriptTestVector {
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
    }
}

#[test]
fn write_test_vectors() {
    let mut tests = Vec::new();
    const NUM_TESTS: usize = 100;

    for ciphersuite in Config::supported_ciphersuites() {
        for _ in 0..NUM_TESTS {
            let test = generate_test_vector(ciphersuite);
            tests.push(test);
        }
    }

    write("test_vectors/kat_transcripts-new.json", &tests);
}

pub fn run_test_vector(test_vector: TranscriptTestVector) -> Result<(), TranscriptTestVectorError> {
    let ciphersuite =
        CiphersuiteName::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");
    let ciphersuite = match Config::ciphersuite(ciphersuite) {
        Ok(cs) => cs,
        Err(_) => {
            log::info!(
                "Unsupported ciphersuite {} in test vector. Skipping ...",
                ciphersuite
            );
            return Ok(());
        }
    };
    log::debug!("Testing test vector for ciphersuite {:?}", ciphersuite);

    // Read input values.
    let group_id = GroupId {
        value: hex_to_bytes(&test_vector.group_id),
    };
    let epoch = test_vector.epoch;
    let tree_hash_before = hex_to_bytes(&test_vector.tree_hash_before);
    let confirmed_transcript_hash_before =
        hex_to_bytes(&test_vector.confirmed_transcript_hash_before);
    let interim_transcript_hash_before = hex_to_bytes(&test_vector.interim_transcript_hash_before);
    let membership_key = MembershipKey::from_secret(Secret::from_slice(
        &hex_to_bytes(&test_vector.membership_key),
        ProtocolVersion::default(),
        ciphersuite,
    ));
    let confirmation_key = ConfirmationKey::from_secret(Secret::from_slice(
        &hex_to_bytes(&test_vector.confirmation_key),
        ProtocolVersion::default(),
        ciphersuite,
    ));

    // Check membership and confirmation tags.
    let commit = MlsPlaintext::decode_detached(&hex_to_bytes(&test_vector.commit))
        .expect("Error decoding commit");
    let context = GroupContext::new(
        group_id,
        GroupEpoch(epoch),
        tree_hash_before,
        confirmed_transcript_hash_before.clone(),
        &[], // extensions
    )
    .expect("Error creating group context");
    if commit
        .verify_membership_tag(ciphersuite, context.serialized(), &membership_key)
        .is_err()
    {
        if cfg!(test) {
            panic!("Invalid membership tag");
        }
        return Err(TranscriptTestVectorError::MembershipTagVerificationError);
    }

    let my_confirmation_tag = confirmation_key.tag(&confirmed_transcript_hash_before);
    if &my_confirmation_tag
        != commit
            .confirmation_tag
            .as_ref()
            .expect("Confirmation tag is missing")
    {
        if cfg!(test) {
            panic!("Invalid confirmation tag");
        }
        return Err(TranscriptTestVectorError::ConfirmationTagMismatch);
    }

    // Compute new transcript hashes.
    let my_confirmed_transcript_hash_after = update_confirmed_transcript_hash(
        ciphersuite,
        &MlsPlaintextCommitContent::try_from(&commit).unwrap(),
        &interim_transcript_hash_before,
    )
    .expect("Error updating confirmed transcript hash");
    if my_confirmed_transcript_hash_after
        != hex_to_bytes(&test_vector.confirmed_transcript_hash_after)
    {
        if cfg!(test) {
            panic!("Confirmed transcript hash mismatch");
        }
        return Err(TranscriptTestVectorError::ConfirmedTranscriptHashMismatch);
    }

    let my_interim_transcript_hash_after = update_interim_transcript_hash(
        &ciphersuite,
        &MlsPlaintextCommitAuthData::try_from(&commit).unwrap(),
        &my_confirmed_transcript_hash_after,
    )
    .expect("Error updating interim transcript hash");
    if my_interim_transcript_hash_after != hex_to_bytes(&test_vector.interim_transcript_hash_after)
    {
        if cfg!(test) {
            panic!("Interim transcript hash mismatch");
        }
        return Err(TranscriptTestVectorError::InterimTranscriptHashMismatch);
    }
    Ok(())
}

#[test]
fn read_test_vectors() {
    let tests: Vec<TranscriptTestVector> = read("test_vectors/kat_transcripts.json");

    for test_vector in tests {
        match run_test_vector(test_vector) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking transcript test vector.\n{:?}", e),
        }
    }
}

implement_error! {
    pub enum TranscriptTestVectorError {
        MembershipTagVerificationError = "Membership tag could not be verified.",
        ConfirmationTagMismatch = "The computed confirmation tag doesn't match the one in the test vector.",
        ConfirmedTranscriptHashMismatch = "The computed transcript hash doesn't match the one in the test vector.",
        InterimTranscriptHashMismatch = "The computed interim transcript hash doesn't match the one in the test vector.",
    }
}
