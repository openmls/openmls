//! # Known Answer Tests for encrypting to tree nodes
//!
//! This currently differs from the test vectors in https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md
//!
//! ## Parameters:
//! * Ciphersuite
//! * Number of leaves
//!
//! ## Format:
//! ```text
//! struct {
//!   opaque data<0..255>;
//! } CryptoValue;
//!
//! struct {
//!   CryptoValue key;
//!   CryptoValue nonce;
//! } KeyAndNonce;
//!
//! struct {
//!   opaque ciphertext<0..2^32-1>;
//!   KeyAndNonce secret;
//! } SenderDataInfo;
//!
//! struct {
//!   uint32 generations;
//!   KeyAndNonce handshake_keys<0..2^32-1>;
//!   KeyAndNonce application_keys<0..2^32-1>;
//!   SenderDataInfo sender_data_info<0..2^32-1>;
//!   Message messages<0..2^32-1>;
//! } LeafSequence;
//!
//! struct {
//!   uint16 cipher_suite;
//!   uint32 n_leaves;
//!   CryptoValue encryption_secret;
//!   CryptoValue sender_data_secret;
//!
//!   LeafSequence leafs<0..2^32-1>;
//! } EncryptionTestVector;
//! ```
//!
//! ## Verification:
//! For all `N` entries in the LeafSequence and all generations `j`
//! * handshake_keys[N].steps[j].key = handshake_ratchet_key_[2*N]_[j]
//! * handshake_keys[N].steps[j].nonce = handshake_ratchet_nonce_[2*N]_[j]
//! * application_keys[N].steps[j].key = application_ratchet_key_[2*N]_[j]
//! * application_keys[N].steps[j].nonce = application_ratchet_nonce_[2*N]_[j]
//! * sender_data_info[N].steps[j].secret.key = sender_data_key_[2*N]_[j]
//! * sender_data_info[N].steps[j].secret.nonce = sender_data_nonce_[2*N]_[j]
//! * messages decrypt successfully with the respective key, nonce, and the sender_data_secret

use crate::{
    ciphersuite::{AeadKey, AeadNonce, Ciphersuite, Signature},
    codec::*,
    config::Config,
    credentials::{CredentialBundle, CredentialType},
    framing::sender::*,
    framing::*,
    group::*,
    key_packages::KeyPackageBundle,
    messages::proposals::Proposal,
    schedule::{EncryptionSecret, SenderDataSecret},
    test_util::*,
    tree::index::LeafIndex,
    tree::secret_tree::{SecretTree, SecretType},
    tree::*,
    utils::{random_u64, randombytes},
};

use itertools::izip;
use serde::{self, Deserialize, Serialize};
use std::{collections::HashMap, convert::TryFrom};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct KeyAndNonce {
    key: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct SenderDataInfo {
    ciphertext: Vec<u8>,
    secrets: KeyAndNonce,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct Message {
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct LeafSequence {
    generations: u32,
    handshake_keys: Vec<KeyAndNonce>,
    application_keys: Vec<KeyAndNonce>,
    sender_data_info: Vec<SenderDataInfo>,
    messages: Vec<Message>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EncryptionTestVector {
    cipher_suite: u16,
    n_leaves: u32,
    encryption_secret: Vec<u8>,
    sender_data_secret: Vec<u8>,
    leaves: Vec<LeafSequence>,
}

fn group(ciphersuite: &Ciphersuite) -> MlsGroup {
    let credential_bundle =
        CredentialBundle::new("Kreator".into(), CredentialType::Basic, ciphersuite.name()).unwrap();
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, Vec::new()).unwrap();
    let group_id = [1, 2, 3, 4];
    MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        key_package_bundle,
        GroupConfig::default(),
    )
    .unwrap()
}

fn receiver_group(ciphersuite: &Ciphersuite, group_id: &GroupId) -> MlsGroup {
    let credential_bundle =
        CredentialBundle::new("Receiver".into(), CredentialType::Basic, ciphersuite.name())
            .unwrap();
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, Vec::new()).unwrap();
    MlsGroup::new(
        &group_id.as_slice(),
        ciphersuite.name(),
        key_package_bundle,
        GroupConfig::default(),
    )
    .unwrap()
}

fn build_messages(
    leaf: LeafIndex,
    group: &mut MlsGroup,
    generation: u32,
    application_ratchet_key: AeadKey,
    application_ratchet_nonce: AeadNonce,
    handshake_ratchet_key: AeadKey,
    handshake_ratchet_nonce: AeadNonce,
    content_type: &mut ContentType,
) -> (Vec<u8>, Vec<u8>) {
    let sender = Sender {
        sender_type: SenderType::Member,
        sender: leaf,
    };
    let epoch = GroupEpoch(random_u64());
    group.context_mut().epoch = epoch;
    match content_type {
        ContentType::Application => {
            let plaintext = MLSPlaintext {
                group_id: group.group_id().clone(),
                epoch,
                sender,
                authenticated_data: vec![1, 2, 3],
                content_type: ContentType::Application,
                content: MLSPlaintextContentType::Application(vec![4, 5, 6]),
                signature: Signature::new_empty(),
            };
            let ciphertext = MLSCiphertext::new_from_plaintext(
                &plaintext,
                group,
                generation,
                application_ratchet_key,
                application_ratchet_nonce,
            );
            *content_type = ContentType::Proposal;
            (
                plaintext.encode_detached().unwrap(),
                ciphertext.encode_detached().unwrap(),
            )
        }
        ContentType::Proposal => {
            let plaintext = MLSPlaintext {
                group_id: group.group_id().clone(),
                epoch,
                sender,
                authenticated_data: vec![1, 2, 3, 4],
                content_type: ContentType::Proposal,
                content: MLSPlaintextContentType::Proposal(Proposal::Remove(RemoveProposal {
                    removed: 0,
                })),
                signature: Signature::new_empty(),
            };
            let ciphertext = MLSCiphertext::new_from_plaintext(
                &plaintext,
                group,
                generation,
                handshake_ratchet_key,
                handshake_ratchet_nonce,
            );
            *content_type = ContentType::Application;
            (
                plaintext.encode_detached().unwrap(),
                ciphertext.encode_detached().unwrap(),
            )
        }
        _ => unimplemented!(),
    }
}

#[test]
fn generate_test_vectors() {
    let mut tests = Vec::new();
    const NUM_GENERATIONS: u32 = 20;

    fn generate_test_vector(n_leaves: u32, ciphersuite: &Ciphersuite) -> EncryptionTestVector {
        let ciphersuite_name = ciphersuite.name();
        let encryption_secret = EncryptionSecret::from_random(32);
        let encryption_secret_bytes = encryption_secret.to_vec();
        let sender_data_secret = SenderDataSecret::from_random(32);
        let sender_data_secret_bytes = sender_data_secret.to_vec();
        let mut secret_tree = SecretTree::new(encryption_secret, LeafIndex::from(n_leaves));

        let mut group = group(ciphersuite);
        *group.epoch_secrets_mut().sender_data_secret_mut() =
            SenderDataSecret::from(sender_data_secret_bytes.as_slice());

        let mut leaves = Vec::new();
        for leaf in 0..n_leaves {
            let leaf = LeafIndex::from(leaf);
            let mut handshake_keys = Vec::new();
            let mut application_keys = Vec::new();
            let mut sender_data_info = Vec::new();
            let mut messages = Vec::new();
            let mut content_type = ContentType::Application;
            for generation in 0..NUM_GENERATIONS {
                let (application_secret_key, application_secret_nonce) = secret_tree
                    .secret_for_decryption(
                        ciphersuite,
                        leaf,
                        SecretType::ApplicationSecret,
                        generation,
                    )
                    .expect("Error getting decryption secret");
                application_keys.push(KeyAndNonce {
                    key: application_secret_key.as_slice().to_vec(),
                    nonce: application_secret_nonce.as_slice().to_vec(),
                });
                let (handshake_secret_key, handshake_secret_nonce) = secret_tree
                    .secret_for_decryption(
                        ciphersuite,
                        leaf,
                        SecretType::HandshakeSecret,
                        generation,
                    )
                    .expect("Error getting decryption secret");
                handshake_keys.push(KeyAndNonce {
                    key: handshake_secret_key.as_slice().to_vec(),
                    nonce: handshake_secret_nonce.as_slice().to_vec(),
                });

                // Create sender_data_key/secret
                let ciphertext = randombytes(77);
                let sender_data_key =
                    AeadKey::from_sender_data_secret(ciphersuite, &ciphertext, &sender_data_secret);
                // Derive initial nonce from the key schedule using the ciphertext.
                let sender_data_nonce = AeadNonce::from_sender_data_secret(
                    ciphersuite,
                    &ciphertext,
                    &sender_data_secret,
                );
                sender_data_info.push(SenderDataInfo {
                    ciphertext,
                    secrets: KeyAndNonce {
                        key: sender_data_key.as_slice().to_vec(),
                        nonce: sender_data_nonce.as_slice().to_vec(),
                    },
                });

                // Create messages
                let (plaintext, ciphertext) = build_messages(
                    leaf,
                    &mut group,
                    generation,
                    application_secret_key,
                    application_secret_nonce,
                    handshake_secret_key,
                    handshake_secret_nonce,
                    &mut content_type,
                );
                messages.push(Message {
                    plaintext,
                    ciphertext,
                });
            }
            leaves.push(LeafSequence {
                generations: NUM_GENERATIONS,
                handshake_keys,
                application_keys,
                sender_data_info,
                messages,
            });
        }

        EncryptionTestVector {
            cipher_suite: ciphersuite_name as u16,
            n_leaves,
            encryption_secret: encryption_secret_bytes,
            sender_data_secret: sender_data_secret_bytes,
            leaves,
        }
    }

    for ciphersuite in Config::supported_ciphersuites() {
        for n_leaves in 1u32..50 {
            let test = generate_test_vector(n_leaves, ciphersuite);
            tests.push(test);
        }
        let test = generate_test_vector(100, ciphersuite);
        tests.push(test);
    }

    write("test_vectors/kat_encryption_openmls-new.json", &tests);
}

#[test]
fn run_test_vectors() {
    let tests: Vec<EncryptionTestVector> = read("test_vectors/kat_encryption_openmls.json");

    for test_vector in tests {
        let n_leaves = test_vector.n_leaves;
        assert_eq!(n_leaves, test_vector.leaves.len() as u32);
        let ciphersuite =
            CiphersuiteName::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");
        let ciphersuite =
            Config::ciphersuite(ciphersuite).expect("Config error getting the ciphersuite");

        let mut secret_tree = SecretTree::new(
            EncryptionSecret::from(test_vector.encryption_secret.as_slice()),
            LeafIndex::from(n_leaves),
        );
        let sender_data_secret = SenderDataSecret::from(test_vector.sender_data_secret.as_slice());

        for (leaf_index, leaf) in test_vector.leaves.iter().enumerate() {
            assert_eq!(leaf.generations, leaf.application_keys.len() as u32);
            assert_eq!(leaf.generations, leaf.handshake_keys.len() as u32);
            assert_eq!(leaf.generations, leaf.messages.len() as u32);
            assert_eq!(leaf.generations, leaf.sender_data_info.len() as u32);
            let leaf_index = LeafIndex::from(leaf_index);

            for (generation, application_key, handshake_key, message, sender_data_info) in izip!(
                (0..leaf.generations).into_iter(),
                &leaf.application_keys,
                &leaf.handshake_keys,
                &leaf.messages,
                &leaf.sender_data_info
            ) {
                // Setup group
                let mls_ciphertext = MLSCiphertext::decode(&mut Cursor::new(&message.ciphertext))
                    .expect("Error parsing MLSCiphertext");
                let mut group = receiver_group(ciphersuite, &mls_ciphertext.group_id);
                *group.epoch_secrets_mut().sender_data_secret_mut() =
                    SenderDataSecret::from(test_vector.sender_data_secret.as_slice());

                // Check keys
                let (application_secret_key, application_secret_nonce) = secret_tree
                    .secret_for_decryption(
                        ciphersuite,
                        leaf_index,
                        SecretType::ApplicationSecret,
                        generation,
                    )
                    .expect("Error getting decryption secret");
                assert_eq!(application_key.key, application_secret_key.as_slice());
                assert_eq!(application_key.nonce, application_secret_nonce.as_slice());

                let (handshake_secret_key, handshake_secret_nonce) = secret_tree
                    .secret_for_decryption(
                        ciphersuite,
                        leaf_index,
                        SecretType::HandshakeSecret,
                        generation,
                    )
                    .expect("Error getting decryption secret");
                assert_eq!(handshake_key.key, handshake_secret_key.as_slice());
                assert_eq!(handshake_key.nonce, handshake_secret_nonce.as_slice());

                let sender_data_key = AeadKey::from_sender_data_secret(
                    ciphersuite,
                    &sender_data_info.ciphertext,
                    &sender_data_secret,
                );
                let sender_data_nonce = AeadNonce::from_sender_data_secret(
                    ciphersuite,
                    &sender_data_info.ciphertext,
                    &sender_data_secret,
                );
                assert_eq!(sender_data_info.secrets.key, sender_data_key.as_slice());
                assert_eq!(sender_data_info.secrets.nonce, sender_data_nonce.as_slice());

                // Decrypt and check message
                let indexed_members = HashMap::new();
                let epoch_secret = group.epoch_secrets();
                let context = group.context();

                // The decryption doesn't check the plaintext in test mode!
                let mls_plaintext = mls_ciphertext
                    .to_plaintext(
                        ciphersuite,
                        indexed_members,
                        epoch_secret,
                        &mut secret_tree,
                        context,
                    )
                    .expect("Error decrypting MLSCiphertext");
                assert_eq!(
                    message.plaintext,
                    mls_plaintext
                        .encode_detached()
                        .expect("Error encoding MLSPlaintext")
                );
            }
        }
    }
}
