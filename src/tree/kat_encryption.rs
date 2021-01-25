//! # Known Answer Tests for encrypting to tree nodes
//!
//! This currently differs from the test vectors in https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md
//! See https://github.com/mlswg/mls-implementations/issues/32 for a discussion.
//!
//! ## Parameters:
//! * Ciphersuite
//! * Number of leaves
//! * Number of generations
//!
//! ## Format:
//!
//! ```text
//! {
//!   "cipher_suite": /* uint16 */,
//!   "n_leaves": /* uint32 */,
//!   "encryption_secret": /* hex-encoded binary data */,
//!   "sender_data_secret": /* hex-encoded binary data */,
//!   "sender_data_info": {
//!     "ciphertext": /* hex-encoded binary data */,
//!     "key": /* hex-encoded binary data */,
//!     "nonce": /* hex-encoded binary data */,
//!   },
//!   "leaves": [
//!     {
//!       "generations": /* uint32 */,
//!       "handshake": [ /* array with `generations` handshake keys and nonces */
//!         {
//!           "key": /* hex-encoded binary data */,
//!           "nonce": /* hex-encoded binary data */,
//!           "plaintext": /* hex-encoded binary data */
//!           "ciphertext": /* hex-encoded binary data */
//!         },
//!         ...
//!       ],
//!       "application": [ /* array with `generations` application keys and nonces */
//!         {
//!           "key": /* hex-encoded binary data */,
//!           "nonce": /* hex-encoded binary data */,
//!           "plaintext": /* hex-encoded binary data */
//!           "ciphertext": /* hex-encoded binary data */
//!         },
//!         ...
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! ## Verification:
//!
//! For all `N` entries in the `leaves` and all generations `j`
//! * `leaves[N].handshake[j].key = handshake_ratchet_key_[2*N]_[j]`
//! * `leaves[N].handshake[j].nonce = handshake_ratchet_nonce_[2*N]_[j]`
//! * `leaves[N].handshake[j].plaintext` represents an MLSPlaintext containing a
//!   handshake message (Proposal or Commit) from leaf `N`
//! * `leaves[N].handshake[j].ciphertext` represents an MLSCiphertext object that
//!   successfully decrypts to an MLSPlaintext equivalent to
//!   `leaves[N].handshake[j].plaintext` using the keys for leaf `N` and generation
//!   `j`.
//! * `leaves[N].application[j].key = application_ratchet_key_[2*N]_[j]`
//! * `leaves[N].application[j].nonce = application_ratchet_nonce_[2*N]_[j]`
//! * `leaves[N].application[j].plaintext` represents an MLSPlaintext containing
//!   application data from leaf `N`
//! * `leaves[N].application[j].ciphertext` represents an MLSCiphertext object that
//!   successfully decrypts to an MLSPlaintext equivalent to
//!   `leaves[N].handshake[j].plaintext` using the keys for leaf `N` and generation
//!   `j`.
//! * `sender_data_info.secret.key = sender_data_key(sender_data_secret, sender_data_info.ciphertext)`
//! * `sender_data_info.secret.nonce = sender_data_nonce(sender_data_secret, sender_data_info.ciphertext)`
//!
//! The extra factor of 2 in `2*N` ensures that only chains rooted at leaf nodes are
//! tested.  The definitions of `ratchet_key` and `ratchet_nonce` are in the
//! [Encryption
//! Keys](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#encryption-keys)
//! section of the specification.

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
    schedule::{EncryptionSecret, EpochSecret, SenderDataSecret},
    test_util::*,
    tree::index::LeafIndex,
    tree::secret_tree::{SecretTree, SecretType},
    tree::*,
    utils::{random_u64, randombytes},
};

use itertools::izip;
use serde::{self, Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct SenderDataInfo {
    ciphertext: String,
    key: String,
    nonce: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct LeafSequence {
    generations: u32,
    // (key, nonce, plaintext, ciphertext)
    handshake: Vec<(String, String, String, String)>,
    // (key, nonce, plaintext, ciphertext)
    application: Vec<(String, String, String, String)>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EncryptionTestVector {
    cipher_suite: u16,
    n_leaves: u32,
    encryption_secret: String,
    sender_data_secret: String,
    sender_data_info: SenderDataInfo,
    leaves: Vec<LeafSequence>,
}

fn group(ciphersuite: &Ciphersuite) -> MlsGroup {
    let credential_bundle = CredentialBundle::new(
        "Kreator".into(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite.name()),
    )
    .unwrap();
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
    let credential_bundle = CredentialBundle::new(
        "Receiver".into(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite.name()),
    )
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

// XXX: we could be more creative in generating these messages.
fn build_handshake_messages(leaf: LeafIndex, group: &mut MlsGroup) -> (Vec<u8>, Vec<u8>) {
    let sender = Sender {
        sender_type: SenderType::Member,
        sender: leaf,
    };
    let epoch = GroupEpoch(random_u64());
    group.context_mut().set_epoch(epoch);
    let plaintext = MLSPlaintext {
        group_id: group.group_id().clone(),
        epoch,
        sender,
        authenticated_data: vec![1, 2, 3, 4],
        content_type: ContentType::Proposal,
        content: MLSPlaintextContentType::Proposal(Proposal::Remove(RemoveProposal { removed: 0 })),
        signature: Signature::new_empty(),
        confirmation_tag: None,
        membership_tag: None,
    };
    let ciphertext = MLSCiphertext::try_from_plaintext(
        &plaintext,
        group.ciphersuite(),
        group.context(),
        leaf,
        group.epoch_secrets(),
        &mut group.secret_tree_mut(),
        0,
    )
    .expect("Could not create MLSCiphertext");
    (
        plaintext.encode_detached().unwrap(),
        ciphertext.encode_detached().unwrap(),
    )
}

fn build_application_messages(leaf: LeafIndex, group: &mut MlsGroup) -> (Vec<u8>, Vec<u8>) {
    let sender = Sender {
        sender_type: SenderType::Member,
        sender: leaf,
    };
    let epoch = GroupEpoch(random_u64());
    group.context_mut().set_epoch(epoch);
    let plaintext = MLSPlaintext {
        group_id: group.group_id().clone(),
        epoch,
        sender,
        authenticated_data: vec![1, 2, 3],
        content_type: ContentType::Application,
        content: MLSPlaintextContentType::Application(vec![4, 5, 6]),
        signature: Signature::new_empty(),
        confirmation_tag: None,
        membership_tag: None,
    };
    let ciphertext = MLSCiphertext::try_from_plaintext(
        &plaintext,
        group.ciphersuite(),
        group.context(),
        leaf,
        group.epoch_secrets(),
        &mut group.secret_tree_mut(),
        0,
    )
    .expect("Could not create MLSCiphertext");
    (
        plaintext.encode_detached().unwrap(),
        ciphertext.encode_detached().unwrap(),
    )
}

#[test]
fn generate_test_vectors() {
    let mut tests = Vec::new();
    const NUM_GENERATIONS: u32 = 20;

    fn generate_test_vector(n_leaves: u32, ciphersuite: &Ciphersuite) -> EncryptionTestVector {
        let ciphersuite_name = ciphersuite.name();
        let epoch_secret = EpochSecret::from_random(ciphersuite);
        let encryption_secret = EncryptionSecret::new(ciphersuite, &epoch_secret);
        let encryption_secret_group = EncryptionSecret::new(ciphersuite, &epoch_secret);
        let encryption_secret_bytes = encryption_secret.to_vec();
        let sender_data_secret = SenderDataSecret::from_random(32);
        let sender_data_secret_bytes = sender_data_secret.to_vec();
        let mut secret_tree = SecretTree::new(encryption_secret, LeafIndex::from(n_leaves));
        let group_secret_tree = SecretTree::new(encryption_secret_group, LeafIndex::from(n_leaves));

        // Create sender_data_key/secret
        let ciphertext = randombytes(77);
        let sender_data_key =
            AeadKey::from_sender_data_secret(ciphersuite, &ciphertext, &sender_data_secret);
        // Derive initial nonce from the key schedule using the ciphertext.
        let sender_data_nonce =
            AeadNonce::from_sender_data_secret(ciphersuite, &ciphertext, &sender_data_secret);
        let sender_data_info = SenderDataInfo {
            ciphertext: bytes_to_hex(&ciphertext),
            key: bytes_to_hex(sender_data_key.as_slice()),
            nonce: bytes_to_hex(sender_data_nonce.as_slice()),
        };

        let mut group = group(ciphersuite);
        *group.epoch_secrets_mut().sender_data_secret_mut() =
            SenderDataSecret::from(sender_data_secret_bytes.as_slice());
        *group.secret_tree_mut() = group_secret_tree;

        let mut leaves = Vec::new();
        for leaf in 0..n_leaves {
            let leaf = LeafIndex::from(leaf);
            let mut handshake = Vec::new();
            let mut application = Vec::new();
            for generation in 0..NUM_GENERATIONS {
                // Application
                let (application_secret_key, application_secret_nonce) = secret_tree
                    .secret_for_decryption(
                        ciphersuite,
                        leaf,
                        SecretType::ApplicationSecret,
                        generation,
                    )
                    .expect("Error getting decryption secret");
                let application_key_string = bytes_to_hex(application_secret_key.as_slice());
                let application_nonce_string = bytes_to_hex(application_secret_nonce.as_slice());
                let (application_plaintext, application_ciphertext) =
                    build_application_messages(leaf, &mut group);
                application.push((
                    application_key_string,
                    application_nonce_string,
                    bytes_to_hex(&application_plaintext),
                    bytes_to_hex(&application_ciphertext),
                ));

                // Handshake
                let (handshake_secret_key, handshake_secret_nonce) = secret_tree
                    .secret_for_decryption(
                        ciphersuite,
                        leaf,
                        SecretType::HandshakeSecret,
                        generation,
                    )
                    .expect("Error getting decryption secret");
                let handshake_key_string = bytes_to_hex(handshake_secret_key.as_slice());
                let handshake_nonce_string = bytes_to_hex(handshake_secret_nonce.as_slice());

                let (handshake_plaintext, handshake_ciphertext) =
                    build_handshake_messages(leaf, &mut group);
                handshake.push((
                    handshake_key_string,
                    handshake_nonce_string,
                    bytes_to_hex(&handshake_plaintext),
                    bytes_to_hex(&handshake_ciphertext),
                ));
            }
            leaves.push(LeafSequence {
                generations: NUM_GENERATIONS,
                handshake,
                application,
            });
        }

        EncryptionTestVector {
            cipher_suite: ciphersuite_name as u16,
            n_leaves,
            encryption_secret: bytes_to_hex(&encryption_secret_bytes),
            sender_data_secret: bytes_to_hex(&sender_data_secret_bytes),
            sender_data_info,
            leaves,
        }
    }

    for ciphersuite in Config::supported_ciphersuites() {
        for n_leaves in 1u32..20 {
            let test = generate_test_vector(n_leaves, ciphersuite);
            tests.push(test);
        }
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
            EncryptionSecret::from(hex_to_bytes(&test_vector.encryption_secret).as_slice()),
            LeafIndex::from(n_leaves),
        );
        let sender_data_secret =
            SenderDataSecret::from(hex_to_bytes(&test_vector.sender_data_secret).as_slice());

        let sender_data_key = AeadKey::from_sender_data_secret(
            ciphersuite,
            &hex_to_bytes(&test_vector.sender_data_info.ciphertext),
            &sender_data_secret,
        );
        let sender_data_nonce = AeadNonce::from_sender_data_secret(
            ciphersuite,
            &hex_to_bytes(&test_vector.sender_data_info.ciphertext),
            &sender_data_secret,
        );
        assert_eq!(
            hex_to_bytes(&test_vector.sender_data_info.key),
            sender_data_key.as_slice()
        );
        assert_eq!(
            hex_to_bytes(&test_vector.sender_data_info.nonce),
            sender_data_nonce.as_slice()
        );

        for (leaf_index, leaf) in test_vector.leaves.iter().enumerate() {
            assert_eq!(leaf.generations, leaf.application.len() as u32);
            assert_eq!(leaf.generations, leaf.handshake.len() as u32);
            let leaf_index = LeafIndex::from(leaf_index);

            for (generation, application, handshake) in
                izip!((0..leaf.generations), &leaf.application, &leaf.handshake,)
            {
                // Check application keys
                let (application_secret_key, application_secret_nonce) = secret_tree
                    .secret_for_decryption(
                        ciphersuite,
                        leaf_index,
                        SecretType::ApplicationSecret,
                        generation,
                    )
                    .expect("Error getting decryption secret");
                assert_eq!(
                    hex_to_bytes(&application.0),
                    application_secret_key.as_slice()
                );
                assert_eq!(
                    hex_to_bytes(&application.1),
                    application_secret_nonce.as_slice()
                );

                // Setup group
                let mls_ciphertext_application =
                    MLSCiphertext::decode(&mut Cursor::new(&hex_to_bytes(&application.3)))
                        .expect("Error parsing MLSCiphertext");
                let mut group = receiver_group(ciphersuite, &mls_ciphertext_application.group_id);
                *group.epoch_secrets_mut().sender_data_secret_mut() = SenderDataSecret::from(
                    hex_to_bytes(&test_vector.sender_data_secret).as_slice(),
                );

                // Decrypt and check application message
                let mls_plaintext_application = mls_ciphertext_application
                    .to_plaintext(ciphersuite, group.epoch_secrets(), &mut secret_tree)
                    .expect("Error decrypting MLSCiphertext");
                assert_eq!(
                    hex_to_bytes(&application.2),
                    mls_plaintext_application
                        .encode_detached()
                        .expect("Error encoding MLSPlaintext")
                );

                // Check handshake keys
                let (handshake_secret_key, handshake_secret_nonce) = secret_tree
                    .secret_for_decryption(
                        ciphersuite,
                        leaf_index,
                        SecretType::HandshakeSecret,
                        generation,
                    )
                    .expect("Error getting decryption secret");
                assert_eq!(hex_to_bytes(&handshake.0), handshake_secret_key.as_slice());
                assert_eq!(
                    hex_to_bytes(&handshake.1),
                    handshake_secret_nonce.as_slice()
                );

                // Setup group
                let mls_ciphertext_handshake =
                    MLSCiphertext::decode(&mut Cursor::new(&hex_to_bytes(&handshake.3)))
                        .expect("Error parsing MLSCiphertext");
                let mut group = receiver_group(ciphersuite, &mls_ciphertext_handshake.group_id);
                *group.epoch_secrets_mut().sender_data_secret_mut() = SenderDataSecret::from(
                    hex_to_bytes(&test_vector.sender_data_secret).as_slice(),
                );

                // Decrypt and check message
                let mls_plaintext_handshake = mls_ciphertext_handshake
                    .to_plaintext(ciphersuite, group.epoch_secrets(), &mut secret_tree)
                    .expect("Error decrypting MLSCiphertext");
                assert_eq!(
                    hex_to_bytes(&handshake.2),
                    mls_plaintext_handshake
                        .encode_detached()
                        .expect("Error encoding MLSPlaintext")
                );
            }
        }
    }
}
