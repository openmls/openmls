//! # Known Answer Tests for encrypting to tree nodes
//!
//! See <https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md>
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
    ciphersuite::Secret, messages::proposals::RemoveProposal, tree::index::SecretTreeLeafIndex,
};
use crate::{
    credentials::{CredentialBundle, CredentialType},
    framing::*,
    group::*,
    key_packages::KeyPackageBundle,
    messages::proposals::Proposal,
    prelude_test::hash_ref::KeyPackageRef,
    schedule::{EncryptionSecret, MembershipKey, SenderDataSecret},
    test_utils::*,
    tree::{
        secret_tree::{SecretTree, SecretType},
        sender_ratchet::SenderRatchetConfiguration,
    },
    utils::random_u64,
    versions::ProtocolVersion,
};

use openmls_traits::{types::SignatureScheme, OpenMlsCryptoProvider};

use itertools::izip;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{self, Deserialize, Serialize};
use std::convert::TryFrom;
use thiserror::Error;

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
fn group(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (CoreGroup, CredentialBundle) {
    let credential_bundle = CredentialBundle::new(
        "Kreator".into(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite),
        backend,
    )
    .expect("An unexpected error occurred.");
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &credential_bundle, backend, Vec::new())
            .expect("An unexpected error occurred.");
    (
        CoreGroup::builder(GroupId::random(backend), key_package_bundle)
            .build(backend)
            .expect("Error creating CoreGroup"),
        credential_bundle,
    )
}

#[cfg(any(feature = "test-utils", test))]
fn receiver_group(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    group_id: &GroupId,
) -> CoreGroup {
    let credential_bundle = CredentialBundle::new(
        "Receiver".into(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite),
        backend,
    )
    .expect("An unexpected error occurred.");
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &credential_bundle, backend, Vec::new())
            .expect("An unexpected error occurred.");
    CoreGroup::builder(group_id.clone(), key_package_bundle)
        .build(backend)
        .expect("Error creating CoreGroup")
}

// XXX: we could be more creative in generating these messages.
#[cfg(any(feature = "test-utils", test))]
fn build_handshake_messages(
    leaf: &KeyPackageRef,
    sender_index: SecretTreeLeafIndex,
    group: &mut CoreGroup,
    credential_bundle: &CredentialBundle,
    backend: &impl OpenMlsCryptoProvider,
) -> (Vec<u8>, Vec<u8>) {
    use openmls_traits::random::OpenMlsRand;
    use tls_codec::Serialize;

    let epoch = random_u64();
    group.context_mut().set_epoch(epoch.into());
    let membership_key = MembershipKey::from_secret(
        Secret::random(group.ciphersuite(), backend, None /* MLS version */)
            .expect("Not enough randomness."),
    );
    let framing_parameters = FramingParameters::new(&[1, 2, 3, 4], WireFormat::MlsCiphertext);
    let mut plaintext = MlsPlaintext::member_proposal(
        framing_parameters,
        leaf,
        Proposal::Remove(RemoveProposal {
            removed: KeyPackageRef::from_slice(
                &backend
                    .rand()
                    .random_vec(16)
                    .expect("Error getting randomness"),
            ),
        }),
        credential_bundle,
        group.context(),
        &membership_key,
        backend,
    )
    .expect("An unexpected error occurred.");
    plaintext.remove_membership_tag();
    let ciphertext = MlsCiphertext::try_from_plaintext(
        &plaintext,
        group.ciphersuite(),
        backend,
        MlsMessageHeader {
            group_id: group.group_id().clone(),
            epoch: group.context().epoch(),
            sender: sender_index,
        },
        group.message_secrets_test_mut(),
        0,
    )
    .expect("Could not create MlsCiphertext");
    (
        plaintext
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
        ciphertext
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
    )
}

#[cfg(any(feature = "test-utils", test))]
fn build_application_messages(
    leaf: &KeyPackageRef,
    sender_index: SecretTreeLeafIndex,
    group: &mut CoreGroup,
    credential_bundle: &CredentialBundle,
    backend: &impl OpenMlsCryptoProvider,
) -> (Vec<u8>, Vec<u8>) {
    use tls_codec::Serialize;

    let epoch = random_u64();
    group.context_mut().set_epoch(epoch.into());
    let membership_key = MembershipKey::from_secret(
        Secret::random(group.ciphersuite(), backend, None /* MLS version */)
            .expect("Not enough randomness."),
    );
    let mut plaintext = MlsPlaintext::new_application(
        leaf,
        &[1, 2, 3],
        &[4, 5, 6],
        credential_bundle,
        group.context(),
        &membership_key,
        backend,
    )
    .expect("An unexpected error occurred.");
    plaintext.remove_membership_tag();
    let ciphertext = match MlsCiphertext::try_from_plaintext(
        &plaintext,
        group.ciphersuite(),
        backend,
        MlsMessageHeader {
            group_id: group.group_id().clone(),
            epoch: group.context().epoch(),
            sender: sender_index,
        },
        group.message_secrets_test_mut(),
        0,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Could not create MlsCiphertext {}", e),
    };
    (
        plaintext
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
        ciphertext
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
    )
}

#[cfg(any(feature = "test-utils", test))]
pub fn generate_test_vector(
    n_generations: u32,
    n_leaves: u32,
    ciphersuite: Ciphersuite,
) -> EncryptionTestVector {
    use openmls_traits::random::OpenMlsRand;

    let ciphersuite_name = ciphersuite;
    let crypto = OpenMlsRustCrypto::default();
    let encryption_secret_bytes = crypto
        .rand()
        .random_vec(ciphersuite.hash_length())
        .expect("An unexpected error occurred.");
    let sender_data_secret = SenderDataSecret::random(ciphersuite, &crypto);
    let sender_data_secret_bytes = sender_data_secret.as_slice();

    // Create sender_data_key/secret
    let ciphertext = crypto
        .rand()
        .random_vec(77)
        .expect("An unexpected error occurred.");
    let sender_data_key = sender_data_secret
        .derive_aead_key(&crypto, &ciphertext)
        .expect("Could not derive AEAD key.");
    // Derive initial nonce from the key schedule using the ciphertext.
    let sender_data_nonce = sender_data_secret
        .derive_aead_nonce(ciphersuite, &crypto, &ciphertext)
        .expect("Could not derive nonce.");
    let sender_data_info = SenderDataInfo {
        ciphertext: bytes_to_hex(&ciphertext),
        key: bytes_to_hex(sender_data_key.as_slice()),
        nonce: bytes_to_hex(sender_data_nonce.as_slice()),
    };

    let (mut group, credential_bundle) = group(ciphersuite, &crypto);
    *group.message_secrets_test_mut().sender_data_secret_mut() = SenderDataSecret::from_slice(
        sender_data_secret_bytes,
        ProtocolVersion::default(),
        ciphersuite,
    );

    let mut leaves = Vec::new();
    for leaf in 0..n_leaves {
        let sender_leaf = leaf;
        // It doesn't matter who the receiver is, as long as it's not the same
        // as the sender, so we don't get into trouble with the secret tree.
        let receiver_leaf = if leaf == 0 { 1u32 } else { 0u32 };
        let encryption_secret = EncryptionSecret::from_slice(
            &encryption_secret_bytes[..],
            ProtocolVersion::default(),
            ciphersuite,
        );
        let encryption_secret_tree =
            SecretTree::new(encryption_secret, n_leaves.into(), sender_leaf.into());
        let decryption_secret = EncryptionSecret::from_slice(
            &encryption_secret_bytes[..],
            ProtocolVersion::default(),
            ciphersuite,
        );
        let mut decryption_secret_tree =
            SecretTree::new(decryption_secret, n_leaves.into(), receiver_leaf.into());

        *group.message_secrets_test_mut().secret_tree_mut() = encryption_secret_tree;

        let mut handshake = Vec::new();
        let mut application = Vec::new();
        for generation in 0..n_generations {
            // Application
            let (application_secret_key, application_secret_nonce) = decryption_secret_tree
                .secret_for_decryption(
                    ciphersuite,
                    &crypto,
                    leaf.into(),
                    SecretType::ApplicationSecret,
                    generation,
                    &SenderRatchetConfiguration::default(),
                )
                .expect("Error getting decryption secret");
            let application_key_string = bytes_to_hex(application_secret_key.as_slice());
            let application_nonce_string = bytes_to_hex(application_secret_nonce.as_slice());
            let (application_plaintext, application_ciphertext) = build_application_messages(
                &group
                    .key_package_ref()
                    .expect("An unexpected error occurred.")
                    .clone(),
                leaf.into(),
                &mut group,
                &credential_bundle,
                &crypto,
            );
            println!("Sender Group: {:?}", group);
            application.push(RatchetStep {
                key: application_key_string,
                nonce: application_nonce_string,
                plaintext: bytes_to_hex(&application_plaintext),
                ciphertext: bytes_to_hex(&application_ciphertext),
            });

            // Handshake
            let (handshake_secret_key, handshake_secret_nonce) = decryption_secret_tree
                .secret_for_decryption(
                    ciphersuite,
                    &crypto,
                    leaf.into(),
                    SecretType::HandshakeSecret,
                    generation,
                    &SenderRatchetConfiguration::default(),
                )
                .expect("Error getting decryption secret");
            let handshake_key_string = bytes_to_hex(handshake_secret_key.as_slice());
            let handshake_nonce_string = bytes_to_hex(handshake_secret_nonce.as_slice());

            let (handshake_plaintext, handshake_ciphertext) = build_handshake_messages(
                &group
                    .key_package_ref()
                    .expect("An unexpected error occurred.")
                    .clone(),
                leaf.into(),
                &mut group,
                &credential_bundle,
                &crypto,
            );

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
    use openmls_traits::crypto::OpenMlsCrypto;
    let mut tests = Vec::new();
    const NUM_LEAVES: u32 = 7;
    const NUM_GENERATIONS: u32 = 5;

    for &ciphersuite in OpenMlsRustCrypto::default()
        .crypto()
        .supported_ciphersuites()
        .iter()
    {
        for n_leaves in 1u32..NUM_LEAVES {
            let test = generate_test_vector(NUM_GENERATIONS, n_leaves, ciphersuite);
            tests.push(test);
        }
    }

    write("test_vectors/kat_encryption_openmls-new.json", &tests);
}

#[cfg(any(feature = "test-utils", test))]
pub fn run_test_vector(
    test_vector: EncryptionTestVector,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<(), EncTestVectorError> {
    use tls_codec::{Deserialize, Serialize};

    let n_leaves = test_vector.n_leaves;
    if n_leaves != test_vector.leaves.len() as u32 {
        return Err(EncTestVectorError::LeafNumberMismatch);
    }
    let ciphersuite = Ciphersuite::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");
    log::debug!("Running test vector with {:?}", ciphersuite);

    let sender_data_secret = SenderDataSecret::from_slice(
        hex_to_bytes(&test_vector.sender_data_secret).as_slice(),
        ProtocolVersion::default(),
        ciphersuite,
    );

    let sender_data_key = sender_data_secret
        .derive_aead_key(
            backend,
            &hex_to_bytes(&test_vector.sender_data_info.ciphertext),
        )
        .expect("Could not derive AEAD key.");
    let sender_data_nonce = sender_data_secret
        .derive_aead_nonce(
            ciphersuite,
            backend,
            &hex_to_bytes(&test_vector.sender_data_info.ciphertext),
        )
        .expect("Could not derive nonce.");
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
        // It doesn't matter who the receiver is, as long as it's not the same
        // as the sender, so we don't get into trouble with the secret tree.
        let receiver_leaf = if leaf_index == 0 { 1u32 } else { 0u32 };

        let mut secret_tree = SecretTree::new(
            EncryptionSecret::from_slice(
                hex_to_bytes(&test_vector.encryption_secret).as_slice(),
                ProtocolVersion::default(),
                ciphersuite,
            ),
            n_leaves.into(),
            receiver_leaf.into(),
        );

        log::debug!("Encryption secret tree: {:?}", secret_tree);
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
        let leaf_index = leaf_index as u32;

        // We keep a fresh copy of the secret tree so we don't lose any secrets.
        let fresh_secret_tree = secret_tree.clone();

        for (generation, application, handshake) in
            izip!((0..leaf.generations), &leaf.application, &leaf.handshake,)
        {
            // Check application keys
            let (application_secret_key, application_secret_nonce) = secret_tree
                .secret_for_decryption(
                    ciphersuite,
                    backend,
                    leaf_index.into(),
                    SecretType::ApplicationSecret,
                    generation,
                    &SenderRatchetConfiguration::default(),
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
            let mut group =
                receiver_group(ciphersuite, backend, mls_ciphertext_application.group_id());
            *group.message_secrets_test_mut().sender_data_secret_mut() =
                SenderDataSecret::from_slice(
                    hex_to_bytes(&test_vector.sender_data_secret).as_slice(),
                    ProtocolVersion::default(),
                    ciphersuite,
                );

            // Note that we can't actually get an MlsPlaintext because we don't
            // have enough information. We encode the VerifiableMlsPlaintext
            // and compare it to the plaintext in the test vector instead.

            // Swap secret tree
            let _ = group
                .message_secrets_test_mut()
                .replace_secret_tree(fresh_secret_tree.clone());

            // Decrypt and check application message
            let sender_data = mls_ciphertext_application
                .sender_data(group.message_secrets_test_mut(), backend, ciphersuite)
                .expect("Unable to get sender data");
            let mls_plaintext_application = mls_ciphertext_application
                .to_plaintext(
                    ciphersuite,
                    backend,
                    group.message_secrets_test_mut(),
                    leaf_index.into(),
                    &SenderRatchetConfiguration::default(),
                    sender_data,
                )
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

            // Swap secret tree back
            let _ = group
                .message_secrets_test_mut()
                .replace_secret_tree(fresh_secret_tree.clone());

            // Check handshake keys
            let (handshake_secret_key, handshake_secret_nonce) = fresh_secret_tree
                .clone()
                .secret_for_decryption(
                    ciphersuite,
                    backend,
                    leaf_index.into(),
                    SecretType::HandshakeSecret,
                    generation,
                    &SenderRatchetConfiguration::default(),
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
            *group.message_secrets_test_mut().sender_data_secret_mut() =
                SenderDataSecret::from_slice(
                    hex_to_bytes(&test_vector.sender_data_secret).as_slice(),
                    ProtocolVersion::default(),
                    ciphersuite,
                );

            // Swap secret tree
            let _ = group
                .message_secrets_test_mut()
                .replace_secret_tree(fresh_secret_tree.clone());

            // Decrypt and check message
            let sender_data = mls_ciphertext_handshake
                .sender_data(group.message_secrets_test_mut(), backend, ciphersuite)
                .expect("Unable to get sender data");
            let mls_plaintext_handshake = mls_ciphertext_handshake
                .to_plaintext(
                    ciphersuite,
                    backend,
                    group.message_secrets_test_mut(),
                    leaf_index.into(),
                    &SenderRatchetConfiguration::default(),
                    sender_data,
                )
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

            // Swap secret tree back
            let _ = group
                .message_secrets_test_mut()
                .replace_secret_tree(fresh_secret_tree.clone());

            // Check handshake keys
            let (handshake_secret_key, handshake_secret_nonce) = fresh_secret_tree
                .clone()
                .secret_for_decryption(
                    ciphersuite,
                    backend,
                    leaf_index.into(),
                    SecretType::HandshakeSecret,
                    generation,
                    &SenderRatchetConfiguration::default(),
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
            let mut group =
                receiver_group(ciphersuite, backend, mls_ciphertext_handshake.group_id());
            *group.message_secrets_test_mut().sender_data_secret_mut() =
                SenderDataSecret::from_slice(
                    &hex_to_bytes(&test_vector.sender_data_secret),
                    ProtocolVersion::default(),
                    ciphersuite,
                );

            // Swap secret tree
            let _ = group
                .message_secrets_test_mut()
                .replace_secret_tree(fresh_secret_tree.clone());

            // Decrypt and check message
            let sender_data = mls_ciphertext_handshake
                .sender_data(group.message_secrets_test_mut(), backend, ciphersuite)
                .expect("Unable to get sender data");
            let mls_plaintext_handshake = mls_ciphertext_handshake
                .to_plaintext(
                    ciphersuite,
                    backend,
                    group.message_secrets_test_mut(),
                    leaf_index.into(),
                    &SenderRatchetConfiguration::default(),
                    sender_data,
                )
                .expect("Error decrypting MLSCiphertext");
            if hex_to_bytes(&handshake.plaintext)
                != mls_plaintext_handshake
                    .tls_serialize_detached()
                    .expect("Error encoding MLSPlaintext")
            {
                return Err(EncTestVectorError::DecryptedHandshakeMessageMismatch);
            }

            // Swap secret tree back
            let _ = group
                .message_secrets_test_mut()
                .replace_secret_tree(fresh_secret_tree.clone());
        }
        log::trace!("Finished test vector for leaf {:?}", leaf_index);
    }
    log::trace!("Finished test vector verification");
    Ok(())
}

#[apply(backends)]
fn read_test_vectors_encryption(backend: &impl OpenMlsCryptoProvider) {
    let tests: Vec<EncryptionTestVector> = read("test_vectors/kat_encryption_openmls.json");

    for test_vector in tests {
        match run_test_vector(test_vector, backend) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking encryption test vector.\n{:?}", e),
        }
    }

    // mlspp test vectors
    let tv_files = [
        /*
        mlspp test vectors are not compatible for now because thei don't implement
        the new wire_format field in framing yet. This is tracked in #495.
        "test_vectors/mlspp/mlspp_encryption_1_10.json",
        "test_vectors/mlspp/mlspp_encryption_2_10.json",
        "test_vectors/mlspp/mlspp_encryption_3_10.json",
        */
    ];
    for &tv_file in tv_files.iter() {
        let tv: EncryptionTestVector = read(tv_file);
        run_test_vector(tv, backend).expect("Error while checking key schedule test vector.");
    }

    log::trace!("Finished test vector verification");
}

#[cfg(any(feature = "test-utils", test))]
/// Encryotion test vector error
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum EncTestVectorError {
    /// The test vector does not contain as many leaves as advertised.
    #[error("The test vector does not contain as many leaves as advertised.")]
    LeafNumberMismatch,
    /// The computed sender data key doesn't match the one in the test vector.
    #[error("The computed sender data key doesn't match the one in the test vector.")]
    SenderDataKeyMismatch,
    /// The computed sender data nonce doesn't match the one in the test vector.
    #[error("The computed sender data nonce doesn't match the one in the test vector.")]
    SenderDataNonceMismatch,
    /// The number of generations in leaf sequence doesn't match the number of application messages.
    #[error("The number of generations in leaf sequence doesn't match the number of application messages.")]
    InvalidLeafSequenceApplication,
    /// The number of generations in leaf sequence doesn't match the number of handshake messages.
    #[error("The number of generations in leaf sequence doesn't match the number of handshake messages.")]
    InvalidLeafSequenceHandshake,
    /// The computed application secret key doesn't match the one in the test vector.
    #[error("The computed application secret key doesn't match the one in the test vector.")]
    ApplicationSecretKeyMismatch,
    /// The computed application secret nonce doesn't match the one in the test vector.
    #[error("The computed application secret nonce doesn't match the one in the test vector.")]
    ApplicationSecretNonceMismatch,
    /// The decrypted application message doesn't match the one in the test vector.
    #[error("The decrypted application message doesn't match the one in the test vector.")]
    DecryptedApplicationMessageMismatch,
    /// The computed handshake secret key doesn't match the one in the test vector.
    #[error("The computed handshake secret key doesn't match the one in the test vector.")]
    HandshakeSecretKeyMismatch,
    /// The computed handshake secret nonce doesn't match the one in the test vector.
    #[error("The computed handshake secret nonce doesn't match the one in the test vector.")]
    HandshakeSecretNonceMismatch,
    /// The decrypted handshake message doesn't match the one in the test vector.
    #[error("The decrypted handshake message doesn't match the one in the test vector.")]
    DecryptedHandshakeMessageMismatch,
}
