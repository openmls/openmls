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
//! * `leaves[N].handshake[j].plaintext` represents an MlsPlaintext containing a
//!   handshake message (Proposal or Commit) from leaf `N`
//! * `leaves[N].handshake[j].ciphertext` represents an MlsCiphertext object
//!   that successfully decrypts to an MlsPlaintext equivalent to
//!   `leaves[N].handshake[j].plaintext` using the keys for leaf `N` and
//!   generation `j`.
//! * `leaves[N].application[j].key = application_ratchet_key_[2*N]_[j]`
//! * `leaves[N].application[j].nonce = application_ratchet_nonce_[2*N]_[j]`
//! * `leaves[N].application[j].plaintext` represents an MlsPlaintext containing
//!   application data from leaf `N`
//! * `leaves[N].application[j].ciphertext` represents an MlsCiphertext object
//!   that successfully decrypts to an MlsPlaintext equivalent to
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
    ciphersuite::Ciphersuite,
    config::{Config, ProtocolVersion},
    credentials::{CredentialBundle, CredentialType},
    framing::*,
    group::*,
    key_packages::KeyPackageBundle,
    messages::proposals::Proposal,
    schedule::{EncryptionSecret, MembershipKey, SenderDataSecret},
    test_utils::*,
    tree::index::LeafIndex,
    tree::secret_tree::{SecretTree, SecretType},
    tree::*,
    utils::random_u64,
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
    pub cipher_suite: u16,
    pub n_leaves: u32,
    encryption_secret: String,
    sender_data_secret: String,
    sender_data_info: SenderDataInfo,
    leaves: Vec<LeafSequence>,
}

#[cfg(any(feature = "test-utils", test))]
fn group(ciphersuite: &Ciphersuite) -> (MlsGroup, CredentialBundle) {
    let credential_bundle = CredentialBundle::new(
        "Kreator".into(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite.name()),
    )
    .unwrap();
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, Vec::new()).unwrap();
    let group_id = [1, 2, 3, 4];
    (
        MlsGroup::new(
            &group_id,
            ciphersuite.name(),
            key_package_bundle,
            MlsGroupConfig::default(),
            None, /* Initial PSK */
            ProtocolVersion::Mls10,
        )
        .unwrap(),
        credential_bundle,
    )
}

#[cfg(any(feature = "test-utils", test))]
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
        group_id.as_slice(),
        ciphersuite.name(),
        key_package_bundle,
        MlsGroupConfig::default(),
        None, /* Initial PSK */
        ProtocolVersion::Mls10,
    )
    .unwrap()
}

// XXX: we could be more creative in generating these messages.
#[cfg(any(feature = "test-utils", test))]
fn build_handshake_messages(
    leaf: LeafIndex,
    group: &mut MlsGroup,
    credential_bundle: &CredentialBundle,
) -> (Vec<u8>, Vec<u8>) {
    use tls_codec::Serialize;

    let epoch = GroupEpoch(random_u64());
    group.context_mut().set_epoch(epoch);
    let membership_key = MembershipKey::from_secret(Secret::random(
        group.ciphersuite(),
        None, /* MLS version */
    ));
    let mut plaintext = MlsPlaintext::new_proposal(
        WireFormat::MlsCiphertext,
        leaf,
        &[1, 2, 3, 4],
        Proposal::Remove(RemoveProposal { removed: 0 }),
        credential_bundle,
        group.context(),
        &membership_key,
    )
    .unwrap();
    plaintext.remove_membership_tag();
    let ciphertext = MlsCiphertext::try_from_plaintext(
        &plaintext,
        group.ciphersuite(),
        group.context(),
        leaf,
        group.epoch_secrets(),
        &mut group.secret_tree_mut(),
        0,
    )
    .expect("Could not create MlsCiphertext");
    (
        plaintext.tls_serialize_detached().unwrap(),
        ciphertext.tls_serialize_detached().unwrap(),
    )
}

#[cfg(any(feature = "test-utils", test))]
fn build_application_messages(
    leaf: LeafIndex,
    group: &mut MlsGroup,
    credential_bundle: &CredentialBundle,
) -> (Vec<u8>, Vec<u8>) {
    use tls_codec::Serialize;

    let epoch = GroupEpoch(random_u64());
    group.context_mut().set_epoch(epoch);
    let membership_key = MembershipKey::from_secret(Secret::random(
        group.ciphersuite(),
        None, /* MLS version */
    ));
    let mut plaintext = MlsPlaintext::new_application(
        leaf,
        &[1, 2, 3],
        &[4, 5, 6],
        credential_bundle,
        group.context(),
        &membership_key,
    )
    .unwrap();
    plaintext.remove_membership_tag();
    let ciphertext = match MlsCiphertext::try_from_plaintext(
        &plaintext,
        group.ciphersuite(),
        group.context(),
        leaf,
        group.epoch_secrets(),
        &mut group.secret_tree_mut(),
        0,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Could not create MlsCiphertext {}", e),
    };
    (
        plaintext.tls_serialize_detached().unwrap(),
        ciphertext.tls_serialize_detached().unwrap(),
    )
}

#[cfg(any(feature = "test-utils", test))]
pub fn generate_test_vector(
    n_generations: u32,
    n_leaves: u32,
    ciphersuite: &'static Ciphersuite,
) -> EncryptionTestVector {
    let ciphersuite_name = ciphersuite.name();
    let epoch_secret = ciphersuite.randombytes(ciphersuite.hash_length());
    let encryption_secret =
        EncryptionSecret::from_slice(&epoch_secret[..], ProtocolVersion::default(), ciphersuite);
    let encryption_secret_group =
        EncryptionSecret::from_slice(&epoch_secret[..], ProtocolVersion::default(), ciphersuite);
    let encryption_secret_bytes = encryption_secret.as_slice().to_vec();
    let sender_data_secret = SenderDataSecret::random(ciphersuite);
    let sender_data_secret_bytes = sender_data_secret.as_slice();
    let mut secret_tree = SecretTree::new(encryption_secret, LeafIndex::from(n_leaves));
    let group_secret_tree = SecretTree::new(encryption_secret_group, LeafIndex::from(n_leaves));

    // Create sender_data_key/secret
    let ciphertext = ciphersuite.randombytes(77);
    let sender_data_key = sender_data_secret.derive_aead_key(&ciphertext);
    // Derive initial nonce from the key schedule using the ciphertext.
    let sender_data_nonce = sender_data_secret.derive_aead_nonce(ciphersuite, &ciphertext);
    let sender_data_info = SenderDataInfo {
        ciphertext: bytes_to_hex(&ciphertext),
        key: bytes_to_hex(sender_data_key.as_slice()),
        nonce: bytes_to_hex(sender_data_nonce.as_slice()),
    };

    let (mut group, credential_bundle) = group(ciphersuite);
    *group.epoch_secrets_mut().sender_data_secret_mut() = SenderDataSecret::from_slice(
        sender_data_secret_bytes,
        ProtocolVersion::default(),
        ciphersuite,
    );
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
                build_application_messages(leaf, &mut group, &credential_bundle);
            println!("Sender Group: {:?}", group);
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
                build_handshake_messages(leaf, &mut group, &credential_bundle);

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

#[cfg(any(feature = "test-utils", test))]
pub fn run_test_vector(test_vector: EncryptionTestVector) -> Result<(), EncTestVectorError> {
    use tls_codec::{Deserialize, Serialize};

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
        EncryptionSecret::from_slice(
            hex_to_bytes(&test_vector.encryption_secret).as_slice(),
            ProtocolVersion::default(),
            ciphersuite,
        ),
        LeafIndex::from(n_leaves),
    );
    log::debug!("Secret tree: {:?}", secret_tree);
    let sender_data_secret = SenderDataSecret::from_slice(
        hex_to_bytes(&test_vector.sender_data_secret).as_slice(),
        ProtocolVersion::default(),
        ciphersuite,
    );

    let sender_data_key =
        sender_data_secret.derive_aead_key(&hex_to_bytes(&test_vector.sender_data_info.ciphertext));
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
            let ctxt_bytes = hex_to_bytes(&application.ciphertext);
            let mls_ciphertext_application =
                MlsCiphertext::tls_deserialize(&mut ctxt_bytes.as_slice())
                    .expect("Error parsing MlsCiphertext");
            let mut group = receiver_group(ciphersuite, &mls_ciphertext_application.group_id);
            *group.epoch_secrets_mut().sender_data_secret_mut() = SenderDataSecret::from_slice(
                hex_to_bytes(&test_vector.sender_data_secret).as_slice(),
                ProtocolVersion::default(),
                ciphersuite,
            );

            // Note that we can't actually get an MlsPlaintext because we don't
            // have enough information. We encode the VerifiableMlsPlaintext
            // and compare it to the plaintext in the test vector instead.

            // Decrypt and check application message
            let mls_plaintext_application = mls_ciphertext_application
                .to_plaintext(ciphersuite, group.epoch_secrets(), &mut secret_tree)
                .expect("Error decrypting MlsCiphertext");
            if hex_to_bytes(&application.plaintext)
                != mls_plaintext_application
                    .tls_serialize_detached()
                    .expect("Error encoding MlsPlaintext")
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
            let handshake_bytes = hex_to_bytes(&handshake.ciphertext);
            let mls_ciphertext_handshake =
                MlsCiphertext::tls_deserialize(&mut handshake_bytes.as_slice())
                    .expect("Error parsing MlsCiphertext");
            *group.epoch_secrets_mut().sender_data_secret_mut() = SenderDataSecret::from_slice(
                hex_to_bytes(&test_vector.sender_data_secret).as_slice(),
                ProtocolVersion::default(),
                ciphersuite,
            );

            // Decrypt and check message
            let mls_plaintext_handshake = mls_ciphertext_handshake
                .to_plaintext(ciphersuite, group.epoch_secrets(), &mut secret_tree)
                .expect("Error decrypting MlsCiphertext");
            if hex_to_bytes(&handshake.plaintext)
                != mls_plaintext_handshake
                    .tls_serialize_detached()
                    .expect("Error encoding MlsPlaintext")
            {
                if cfg!(test) {
                    panic!("Decrypted handshake message mismatch");
                }
                return Err(EncTestVectorError::DecryptedHandshakeMessageMismatch);
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
                return Err(EncTestVectorError::HandshakeSecretKeyMismatch);
            }
            if hex_to_bytes(&handshake.nonce) != handshake_secret_nonce.as_slice() {
                return Err(EncTestVectorError::HandshakeSecretNonceMismatch);
            }

            // Setup group
            let handshake_bytes = hex_to_bytes(&handshake.ciphertext);
            let mls_ciphertext_handshake =
                MlsCiphertext::tls_deserialize(&mut handshake_bytes.as_slice())
                    .expect("Error parsing MLSCiphertext");
            let mut group = receiver_group(ciphersuite, &mls_ciphertext_handshake.group_id);
            *group.epoch_secrets_mut().sender_data_secret_mut() = SenderDataSecret::from_slice(
                &hex_to_bytes(&test_vector.sender_data_secret),
                ProtocolVersion::default(),
                ciphersuite,
            );

            // Decrypt and check message
            let mls_plaintext_handshake = mls_ciphertext_handshake
                .to_plaintext(ciphersuite, group.epoch_secrets(), &mut secret_tree)
                .expect("Error decrypting MLSCiphertext");
            if hex_to_bytes(&handshake.plaintext)
                != mls_plaintext_handshake
                    .tls_serialize_detached()
                    .expect("Error encoding MLSPlaintext")
            {
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

    // mlspp test vectors
    let tv_files = [
        /* mlspp test vectors are not compatible for now
        "test_vectors/mlspp/mlspp_encryption_1_10.json",
        "test_vectors/mlspp/mlspp_encryption_2_10.json",
        "test_vectors/mlspp/mlspp_encryption_3_10.json",
        */
    ];
    for &tv_file in tv_files.iter() {
        let tv: EncryptionTestVector = read(tv_file);
        run_test_vector(tv).expect("Error while checking key schedule test vector.");
    }

    log::trace!("Finished test vector verification");
}

#[cfg(any(feature = "test-utils", test))]
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
