//! # Known Answer Tests for encrypting to tree nodes
//!
//! See https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md
//! for more description on the test vectors.
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
//! * `leaves[N].handshake[j].ciphertext` represents an MLSCiphertext object
//!   that successfully decrypts to an MLSPlaintext equivalent to
//!   `leaves[N].handshake[j].plaintext` using the keys for leaf `N` and
//!   generation `j`.
//! * `leaves[N].application[j].key = application_ratchet_key_[2*N]_[j]`
//! * `leaves[N].application[j].nonce = application_ratchet_nonce_[2*N]_[j]`
//! * `leaves[N].application[j].plaintext` represents an MLSPlaintext containing
//!   application data from leaf `N`
//! * `leaves[N].application[j].ciphertext` represents an MLSCiphertext object
//!   that successfully decrypts to an MLSPlaintext equivalent to
//!   `leaves[N].handshake[j].plaintext` using the keys for leaf `N` and
//!   generation `j`.
//! * `sender_data_info.secret.key = sender_data_key(sender_data_secret,
//!   sender_data_info.ciphertext)`
//! * `sender_data_info.secret.nonce = sender_data_nonce(sender_data_secret,
//!   sender_data_info.ciphertext)`
//!
//! The extra factor of 2 in `2*N` ensures that only chains rooted at leaf nodes
//! are tested.  The definitions of `ratchet_key` and `ratchet_nonce` are in the
//! [Encryption
//! Keys](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#encryption-keys)
//! section of the specification.

use crate::{
    ciphersuite::{Ciphersuite, Signature},
    codec::*,
    config::Config,
    credentials::{CredentialBundle, CredentialType},
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
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct SenderDataInfo {
    ciphertext: String,
    key: String,
    nonce: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct RatchetStep {
    key: String,
    nonce: String,
    plaintext: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct LeafSequence {
    generations: u32,
    handshake: Vec<RatchetStep>,
    application: Vec<RatchetStep>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionTestVector {
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
        None, /* Initial PSK */
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
        None, /* Initial PSK */
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

#[cfg(any(feature = "expose-test-vectors", test))]
pub fn generate_test_vector(
    n_generations: u32,
    n_leaves: u32,
    ciphersuite: &Ciphersuite,
) -> EncryptionTestVector {
    let ciphersuite_name = ciphersuite.name();
    let epoch_secret = randombytes(ciphersuite.hash_length());
    let encryption_secret = EncryptionSecret::from(&epoch_secret[..]);
    let encryption_secret_group = EncryptionSecret::from(&epoch_secret[..]);
    let encryption_secret_bytes = encryption_secret.as_slice().to_vec();
    let sender_data_secret = SenderDataSecret::from_random(32);
    let sender_data_secret_bytes = sender_data_secret.as_slice();
    let mut secret_tree = SecretTree::new(encryption_secret, LeafIndex::from(n_leaves));
    let group_secret_tree = SecretTree::new(encryption_secret_group, LeafIndex::from(n_leaves));

    // Create sender_data_key/secret
    let ciphertext = randombytes(77);
    let sender_data_key = sender_data_secret.derive_aead_key(ciphersuite, &ciphertext);
    // Derive initial nonce from the key schedule using the ciphertext.
    let sender_data_nonce = sender_data_secret.derive_aead_nonce(ciphersuite, &ciphertext);
    let sender_data_info = SenderDataInfo {
        ciphertext: bytes_to_hex(&ciphertext),
        key: bytes_to_hex(sender_data_key.as_slice()),
        nonce: bytes_to_hex(sender_data_nonce.as_slice()),
    };

    let mut group = group(ciphersuite);
    *group.epoch_secrets_mut().sender_data_secret_mut() =
        SenderDataSecret::from(sender_data_secret_bytes);
    *group.secret_tree_mut() = group_secret_tree;

    let mut leaves = Vec::new();
    for leaf in 0..n_leaves {
        let leaf = LeafIndex::from(leaf);
        let mut handshake = Vec::new();
        let mut application = Vec::new();
        for generation in 0..n_generations {
            // Application
            let (application_secret_key, application_secret_nonce) = secret_tree
                .secret_for_decryption(ciphersuite, leaf, SecretType::ApplicationSecret, generation)
                .expect("Error getting decryption secret");
            let application_key_string = bytes_to_hex(application_secret_key.as_slice());
            let application_nonce_string = bytes_to_hex(application_secret_nonce.as_slice());
            let (application_plaintext, application_ciphertext) =
                build_application_messages(leaf, &mut group);
            application.push(RatchetStep {
                key: application_key_string,
                nonce: application_nonce_string,
                plaintext: bytes_to_hex(&application_plaintext),
                ciphertext: bytes_to_hex(&application_ciphertext),
            });

            // Handshake
            let (handshake_secret_key, handshake_secret_nonce) = secret_tree
                .secret_for_decryption(ciphersuite, leaf, SecretType::HandshakeSecret, generation)
                .expect("Error getting decryption secret");
            let handshake_key_string = bytes_to_hex(handshake_secret_key.as_slice());
            let handshake_nonce_string = bytes_to_hex(handshake_secret_nonce.as_slice());

            let (handshake_plaintext, handshake_ciphertext) =
                build_handshake_messages(leaf, &mut group);
            handshake.push(RatchetStep {
                key: handshake_key_string,
                nonce: handshake_nonce_string,
                plaintext: bytes_to_hex(&handshake_plaintext),
                ciphertext: bytes_to_hex(&handshake_ciphertext),
            });
        }
        leaves.push(LeafSequence {
            generations: n_generations,
            handshake,
            application,
        });
    }

    EncryptionTestVector {
        cipher_suite: ciphersuite_name as u16,
        n_leaves,
        encryption_secret: bytes_to_hex(&encryption_secret_bytes),
        sender_data_secret: bytes_to_hex(sender_data_secret_bytes),
        sender_data_info,
        leaves,
    }
}

#[test]
fn write_test_vectors() {
    let mut tests = Vec::new();
    const NUM_GENERATIONS: u32 = 20;

    for ciphersuite in Config::supported_ciphersuites() {
        for n_leaves in 1u32..20 {
            let test = generate_test_vector(NUM_GENERATIONS, n_leaves, ciphersuite);
            tests.push(test);
        }
    }

    write("test_vectors/kat_encryption_openmls-new.json", &tests);
}

#[cfg(any(feature = "expose-test-vectors", test))]
pub fn run_test_vector(test_vector: EncryptionTestVector) -> Result<(), EncTestVectorError> {
    let n_leaves = test_vector.n_leaves;
    if n_leaves != test_vector.leaves.len() as u32 {
        return Err(EncTestVectorError::LeafNumberMismatch);
    }
    let ciphersuite =
        CiphersuiteName::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");
    let ciphersuite = match Config::ciphersuite(ciphersuite) {
        Ok(cs) => cs,
        Err(_) => {
            println!(
                "Unsupported ciphersuite {} in test vector. Skipping ...",
                ciphersuite
            );
            return Ok(());
        }
    };
    log::debug!("Running test vector with {:?}", ciphersuite.name());

    let mut secret_tree = SecretTree::new(
        EncryptionSecret::from(hex_to_bytes(&test_vector.encryption_secret).as_slice()),
        LeafIndex::from(n_leaves),
    );
    log::debug!("Secret tree: {:?}", secret_tree);
    let sender_data_secret =
        SenderDataSecret::from(hex_to_bytes(&test_vector.sender_data_secret).as_slice());

    let sender_data_key = sender_data_secret.derive_aead_key(
        ciphersuite,
        &hex_to_bytes(&test_vector.sender_data_info.ciphertext),
    );
    let sender_data_nonce = sender_data_secret.derive_aead_nonce(
        ciphersuite,
        &hex_to_bytes(&test_vector.sender_data_info.ciphertext),
    );
    if hex_to_bytes(&test_vector.sender_data_info.key) != sender_data_key.as_slice() {
        if cfg!(test) {
            panic!("Sender data key mismatch");
        }
        return Err(EncTestVectorError::SenderDataKeyMismatch);
    }
    if hex_to_bytes(&test_vector.sender_data_info.nonce) != sender_data_nonce.as_slice() {
        if cfg!(test) {
            panic!("Sender data nonce mismatch");
        }
        return Err(EncTestVectorError::SenderDataNonceMismatch);
    }

    for (leaf_index, leaf) in test_vector.leaves.iter().enumerate() {
        log::trace!("Running test vector for leaf {:?}", leaf_index);
        if leaf.generations != leaf.application.len() as u32 {
            if cfg!(test) {
                panic!("Invalid leaf sequence application");
            }
            return Err(EncTestVectorError::InvalidLeafSequenceApplication);
        }
        if leaf.generations != leaf.handshake.len() as u32 {
            if cfg!(test) {
                panic!("Invalid leaf sequence handshake");
            }
            return Err(EncTestVectorError::InvalidLeafSequenceHandshake);
        }
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
            log::debug!(
                "  Secret tree after deriving application keys for leaf {:?} in generation {:?}",
                leaf_index,
                generation
            );
            log::debug!("  {:?}", secret_tree);
            if hex_to_bytes(&application.key) != application_secret_key.as_slice() {
                log::error!("  Application key mismatch:");
                log::debug!("    Calculated: {:x?}", application_secret_key.as_slice());
                log::debug!("    Expected: {:x?}", hex_to_bytes(&application.key));
                if cfg!(test) {
                    panic!("Application secret key mismatch");
                }
                return Err(EncTestVectorError::ApplicationSecretKeyMismatch);
            }
            if hex_to_bytes(&application.nonce) != application_secret_nonce.as_slice() {
                log::error!("  Application nonce mismatch");
                log::debug!("    Calculated: {:x?}", application_secret_nonce.as_slice());
                log::debug!("    Expected: {:x?}", hex_to_bytes(&application.nonce));
                if cfg!(test) {
                    panic!("Application secret nonce mismatch");
                }
                return Err(EncTestVectorError::ApplicationSecretNonceMismatch);
            }

            // Setup group
            let mls_ciphertext_application =
                MLSCiphertext::decode(&mut Cursor::new(&hex_to_bytes(&application.ciphertext)))
                    .expect("Error parsing MLSCiphertext");
            let mut group = receiver_group(ciphersuite, &mls_ciphertext_application.group_id);
            *group.epoch_secrets_mut().sender_data_secret_mut() =
                SenderDataSecret::from(hex_to_bytes(&test_vector.sender_data_secret).as_slice());

            // Decrypt and check application message
            let mls_plaintext_application = mls_ciphertext_application
                .to_plaintext(ciphersuite, group.epoch_secrets(), &mut secret_tree)
                .expect("Error decrypting MLSCiphertext");
            if hex_to_bytes(&application.plaintext)
                != mls_plaintext_application
                    .encode_detached()
                    .expect("Error encoding MLSPlaintext")
            {
                if cfg!(test) {
                    panic!("Decrypted application message mismatch");
                }
                return Err(EncTestVectorError::DecryptedApplicationMessageMismatch);
            }

            // Check handshake keys
            let (handshake_secret_key, handshake_secret_nonce) = secret_tree
                .secret_for_decryption(
                    ciphersuite,
                    leaf_index,
                    SecretType::HandshakeSecret,
                    generation,
                )
                .expect("Error getting decryption secret");
            if hex_to_bytes(&handshake.key) != handshake_secret_key.as_slice() {
                if cfg!(test) {
                    panic!("Handshake secret key mismatch");
                }
                return Err(EncTestVectorError::HandshakeSecretKeyMismatch);
            }
            if hex_to_bytes(&handshake.nonce) != handshake_secret_nonce.as_slice() {
                if cfg!(test) {
                    panic!("Handshake secret nonce mismatch");
                }
                return Err(EncTestVectorError::HandshakeSecretNonceMismatch);
            }

            // Setup group
            let mls_ciphertext_handshake =
                MLSCiphertext::decode(&mut Cursor::new(&hex_to_bytes(&handshake.ciphertext)))
                    .expect("Error parsing MLSCiphertext");
            let mut group = receiver_group(ciphersuite, &mls_ciphertext_handshake.group_id);
            *group.epoch_secrets_mut().sender_data_secret_mut() =
                SenderDataSecret::from(hex_to_bytes(&test_vector.sender_data_secret).as_slice());

            // Decrypt and check message
            let mls_plaintext_handshake = mls_ciphertext_handshake
                .to_plaintext(ciphersuite, group.epoch_secrets(), &mut secret_tree)
                .expect("Error decrypting MLSCiphertext");
            if hex_to_bytes(&handshake.plaintext)
                != mls_plaintext_handshake
                    .encode_detached()
                    .expect("Error encoding MLSPlaintext")
            {
                if cfg!(test) {
                    panic!("Decrypted handshake message mismatch");
                }
                return Err(EncTestVectorError::DecryptedHandshakeMessageMismatch);
            }
        }
        log::trace!("Finished test vector for leaf {:?}", leaf_index);
    }
    log::trace!("Finished test vector verification");
    Ok(())
}

#[test]
fn read_test_vectors() {
    let tests: Vec<EncryptionTestVector> = read("test_vectors/kat_encryption_openmls.json");

    for test_vector in tests {
        match run_test_vector(test_vector) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking encryption test vector.\n{:?}", e),
        }
    }
}

#[cfg(any(feature = "expose-test-vectors", test))]
implement_error! {
    pub enum EncTestVectorError {
        LeafNumberMismatch = "The test vector does not contain as many leaves as advertised.",
        SenderDataKeyMismatch = "The computed sender data key doesn't match the one in the test vector.",
        SenderDataNonceMismatch = "The computed sender data nonce doesn't match the one in the test vector.",
        InvalidLeafSequenceApplication = "The number of generations in leaf sequence doesn't match the number of application messages.",
        InvalidLeafSequenceHandshake = "The number of generations in leaf sequence doesn't match the number of handshake messages.",
        ApplicationSecretKeyMismatch = "The computed application secret key doesn't match the one in the test vector.",
        ApplicationSecretNonceMismatch = "The computed application secret nonce doesn't match the one in the test vector.",
        DecryptedApplicationMessageMismatch = "The decrypted application message doesn't match the one in the test vector.",
        HandshakeSecretKeyMismatch = "The computed handshake secret key doesn't match the one in the test vector.",
        HandshakeSecretNonceMismatch = "The computed handshake secret nonce doesn't match the one in the test vector.",
        DecryptedHandshakeMessageMismatch = "The decrypted handshake message doesn't match the one in the test vector.",
    }
}
