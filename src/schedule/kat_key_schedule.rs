//! # Known Answer Tests for the key schedule
//!
//! See https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md
//! for more description on the test vectors.
//!
//! If values are not present, they are encoded as empty strings.

use std::convert::TryFrom;

use crate::{
    ciphersuite::{Ciphersuite, CiphersuiteName},
    codec::Codec,
    config::Config,
    group::{GroupContext, GroupEpoch, GroupId},
    schedule::{EpochSecrets, InitSecret, JoinerSecret, KeySchedule, WelcomeSecret},
    test_util::{bytes_to_hex, hex_to_bytes, read, write},
    utils::randombytes,
};

use hpke::HPKEKeyPair;
use serde::{self, Deserialize, Serialize};

use super::CommitSecret;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct Epoch {
    // Chosen by the generator
    tree_hash: String,
    commit_secret: String,
    // XXX: PSK is not supported in OpenMLS yet #141
    psk_secret: String,
    confirmed_transcript_hash: String,

    // Computed values
    group_context: String,
    joiner_secret: String,
    welcome_secret: String,
    init_secret: String,
    sender_data_secret: String,
    encryption_secret: String,
    exporter_secret: String,
    authentication_secret: String,
    external_secret: String,
    confirmation_key: String,
    membership_key: String,
    resumption_secret: String,

    external_pub: String, // TLS serialized HPKEPublicKey
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct KeyScheduleTestVector {
    cipher_suite: u16,
    group_id: String,
    initial_init_secret: String,
    epochs: Vec<Epoch>,
}

fn generate(
    ciphersuite: &'static Ciphersuite,
    init_secret: &InitSecret,
    group_id: &[u8],
    epoch: u64,
) -> (
    Vec<u8>,
    CommitSecret,
    JoinerSecret,
    WelcomeSecret,
    EpochSecrets,
    Vec<u8>,
    GroupContext,
    HPKEKeyPair,
) {
    let tree_hash = randombytes(ciphersuite.hash_length());
    let commit_secret = CommitSecret::random(ciphersuite.hash_length());
    let joiner_secret = JoinerSecret::new(ciphersuite, &commit_secret, init_secret);
    let mut key_schedule = KeySchedule::init(ciphersuite, joiner_secret.clone(), None);
    let welcome_secret = key_schedule.welcome().unwrap();

    let confirmed_transcript_hash = randombytes(ciphersuite.hash_length());

    let group_context = GroupContext::new(
        GroupId::from_slice(group_id),
        GroupEpoch(epoch),
        tree_hash.to_vec(),
        confirmed_transcript_hash.clone(),
        &[], // Extensions
    )
    .unwrap();

    key_schedule.add_context(&group_context).unwrap();
    let epoch_secrets = key_schedule.epoch_secrets(true).unwrap();

    // Calculate external HPKE key pair
    let external_key_pair = epoch_secrets
        .external_secret()
        .derive_external_keypair(ciphersuite);

    (
        confirmed_transcript_hash,
        commit_secret,
        joiner_secret,
        welcome_secret,
        epoch_secrets,
        tree_hash,
        group_context,
        external_key_pair,
    )
}

#[test]
fn generate_test_vectors() {
    let mut tests = Vec::new();
    const NUM_EPOCHS: u64 = 200;

    for ciphersuite in Config::supported_ciphersuites() {
        // Set up setting.
        let mut init_secret = InitSecret::random(ciphersuite.hash_length());
        let initial_init_secret = init_secret.clone();
        let group_id = randombytes(16);

        let mut epochs = Vec::new();

        // Generate info for all epochs
        for epoch in 0..NUM_EPOCHS {
            println!("Generating epoch: {:?}", epoch);
            let (
                confirmed_transcript_hash,
                commit_secret,
                joiner_secret,
                welcome_secret,
                epoch_secrets,
                tree_hash,
                group_context,
                external_key_pair,
            ) = generate(ciphersuite, &init_secret, &group_id, epoch);

            let epoch_info = Epoch {
                tree_hash: bytes_to_hex(&tree_hash),
                commit_secret: bytes_to_hex(commit_secret.as_slice()),
                psk_secret: bytes_to_hex(&[]), // XXX: not implemented yet.
                confirmed_transcript_hash: bytes_to_hex(&confirmed_transcript_hash),
                group_context: bytes_to_hex(group_context.serialized()),
                joiner_secret: bytes_to_hex(joiner_secret.as_slice()),
                welcome_secret: bytes_to_hex(welcome_secret.as_slice()),
                init_secret: bytes_to_hex(epoch_secrets.init_secret().unwrap().as_slice()),
                sender_data_secret: bytes_to_hex(epoch_secrets.sender_data_secret().as_slice()),
                encryption_secret: bytes_to_hex(epoch_secrets.encryption_secret().as_slice()),
                exporter_secret: bytes_to_hex(epoch_secrets.exporter_secret().as_slice()),
                authentication_secret: bytes_to_hex(
                    epoch_secrets.authentication_secret().as_slice(),
                ),
                external_secret: bytes_to_hex(epoch_secrets.external_secret().as_slice()),
                confirmation_key: bytes_to_hex(epoch_secrets.confirmation_key().as_slice()),
                membership_key: bytes_to_hex(epoch_secrets.membership_key().as_slice()),
                resumption_secret: bytes_to_hex(epoch_secrets.resumption_secret().as_slice()),
                external_pub: bytes_to_hex(
                    &external_key_pair.public_key().encode_detached().unwrap(),
                ),
            };
            epochs.push(epoch_info);
            init_secret = epoch_secrets.init_secret().unwrap().clone();
        }

        let test = KeyScheduleTestVector {
            cipher_suite: ciphersuite.name() as u16,
            group_id: bytes_to_hex(&group_id),
            initial_init_secret: bytes_to_hex(initial_init_secret.as_slice()),
            epochs,
        };
        tests.push(test);
    }

    write("test_vectors/kat_key_schedule_openmls-new.json", &tests);
}

#[test]
fn run_test_vectors() {
    let tests: Vec<KeyScheduleTestVector> = read("test_vectors/kat_key_schedule_openmls.json");

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

        let group_id = hex_to_bytes(&test_vector.group_id);
        let init_secret = hex_to_bytes(&test_vector.initial_init_secret);
        let mut init_secret = InitSecret::from_slice(&init_secret);

        for (i, epoch) in test_vector.epochs.iter().enumerate() {
            println!("Epoch {:?}", i);
            let tree_hash = hex_to_bytes(&epoch.tree_hash);
            let commit_secret = hex_to_bytes(&epoch.commit_secret);
            let commit_secret = CommitSecret::from_slice(&commit_secret);
            let psk = hex_to_bytes(&epoch.psk_secret);
            if !psk.is_empty() {
                println!("PSK is not supported by OpenMLS yet. See #141");
                continue;
            }

            let joiner_secret = JoinerSecret::new(ciphersuite, &commit_secret, &init_secret);
            assert_eq!(hex_to_bytes(&epoch.joiner_secret), joiner_secret.as_slice());

            let mut key_schedule = KeySchedule::init(ciphersuite, joiner_secret.clone(), None);
            let welcome_secret = key_schedule.welcome().unwrap();
            assert_eq!(
                hex_to_bytes(&epoch.welcome_secret),
                welcome_secret.as_slice()
            );

            let confirmed_transcript_hash = hex_to_bytes(&epoch.confirmed_transcript_hash);

            let group_context = GroupContext::new(
                GroupId::from_slice(&group_id),
                GroupEpoch(i as u64),
                tree_hash.to_vec(),
                confirmed_transcript_hash.clone(),
                &[], // Extensions
            )
            .expect("Error creating group context");

            key_schedule.add_context(&group_context).unwrap();

            let epoch_secrets = key_schedule.epoch_secrets(true).unwrap();

            init_secret = epoch_secrets.init_secret().unwrap().clone();
            assert_eq!(hex_to_bytes(&epoch.init_secret), init_secret.as_slice());

            assert_eq!(
                hex_to_bytes(&epoch.sender_data_secret),
                epoch_secrets.sender_data_secret().as_slice()
            );
            assert_eq!(
                hex_to_bytes(&epoch.encryption_secret),
                epoch_secrets.encryption_secret().as_slice()
            );
            assert_eq!(
                hex_to_bytes(&epoch.exporter_secret),
                epoch_secrets.exporter_secret().as_slice()
            );
            assert_eq!(
                hex_to_bytes(&epoch.authentication_secret),
                epoch_secrets.authentication_secret().as_slice()
            );
            assert_eq!(
                hex_to_bytes(&epoch.external_secret),
                epoch_secrets.external_secret().as_slice()
            );
            assert_eq!(
                hex_to_bytes(&epoch.confirmation_key),
                epoch_secrets.confirmation_key().as_slice()
            );
            assert_eq!(
                hex_to_bytes(&epoch.membership_key),
                epoch_secrets.membership_key().as_slice()
            );
            assert_eq!(
                hex_to_bytes(&epoch.resumption_secret),
                epoch_secrets.resumption_secret().as_slice()
            );

            // Calculate external HPKE key pair
            let external_key_pair = epoch_secrets
                .external_secret()
                .derive_external_keypair(ciphersuite);
            assert_eq!(
                hex_to_bytes(&epoch.external_pub),
                external_key_pair.public_key().encode_detached().unwrap()
            );
        }
    }
}
