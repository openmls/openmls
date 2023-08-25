#![allow(dead_code)] // Allow dead code for now because none of this is used through test-utils right now.

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
//! * `leaves[N].handshake[j].plaintext` represents an PublicMessage containing a
//!   handshake message (Proposal or Commit) from leaf `N`
//! * `leaves[N].handshake[j].ciphertext` represents an PrivateMessage object
//!   that successfully decrypts to an PublicMessage equivalent to
//!   `leaves[N].handshake[j].plaintext` using the keys for leaf `N` and
//!   generation `j`.
//! * `leaves[N].application[j].key = application_ratchet_key_[2*N]_[j]`
//! * `leaves[N].application[j].nonce = application_ratchet_nonce_[2*N]_[j]`
//! * `leaves[N].application[j].plaintext` represents an PublicMessage containing
//!   application data from leaf `N`
//! * `leaves[N].application[j].ciphertext` represents an PrivateMessage object
//!   that successfully decrypts to an PublicMessage equivalent to
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

use itertools::izip;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{signatures::Signer, types::SignatureScheme, OpenMlsProvider};
use serde::{self, Deserialize, Serialize};
use thiserror::Error;

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    credentials::{Credential, CredentialType, CredentialWithKey},
    framing::{
        mls_auth_content::AuthenticatedContent, mls_auth_content_in::AuthenticatedContentIn,
        mls_content_in::FramedContentBodyIn, *,
    },
    group::*,
    messages::proposals::{Proposal, RemoveProposal},
    schedule::{EncryptionSecret, SenderDataSecret},
    test_utils::*,
    tree::{
        secret_tree::{SecretTree, SecretType},
        sender_ratchet::SenderRatchetConfiguration,
    },
    utils::random_u64,
    versions::ProtocolVersion,
};

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

fn generate_credential(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = Credential::new(identity, credential_type).unwrap();
    let signature_keys = SignatureKeyPair::new(signature_algorithm).unwrap();
    signature_keys.store(provider.key_store()).unwrap();

    (
        CredentialWithKey {
            credential,
            signature_key: signature_keys.to_public_vec().into(),
        },
        signature_keys,
    )
}

#[cfg(any(feature = "test-utils", test))]
fn group(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) -> (CoreGroup, CredentialWithKey, SignatureKeyPair) {
    use crate::group::config::CryptoConfig;

    let (credential_with_key, signer) = generate_credential(
        "Kreator".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        provider,
    );

    let group = CoreGroup::builder(
        GroupId::random(provider.rand()),
        CryptoConfig::with_default_version(ciphersuite),
        credential_with_key.clone(),
    )
    .build(provider, &signer)
    .unwrap();

    (group, credential_with_key, signer)
}

#[cfg(any(feature = "test-utils", test))]
fn receiver_group(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
    group_id: GroupId,
) -> (CoreGroup, CredentialWithKey, SignatureKeyPair) {
    use crate::group::config::CryptoConfig;

    let (credential_with_key, signer) = generate_credential(
        "Receiver".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        provider,
    );

    let group = CoreGroup::builder(
        group_id,
        CryptoConfig::with_default_version(ciphersuite),
        credential_with_key.clone(),
    )
    .build(provider, &signer)
    .unwrap();

    (group, credential_with_key, signer)
}

// XXX: we could be more creative in generating these messages.
#[cfg(any(feature = "test-utils", test))]
fn build_handshake_messages(
    sender_index: LeafNodeIndex,
    group: &mut CoreGroup,
    signer: &impl Signer,
    provider: &impl OpenMlsProvider,
) -> (Vec<u8>, Vec<u8>) {
    use tls_codec::Serialize;

    use crate::{prelude_test::Secret, schedule::MembershipKey};

    let epoch = random_u64();
    group.context_mut().set_epoch(epoch.into());
    let framing_parameters = FramingParameters::new(&[1, 2, 3, 4], WireFormat::PrivateMessage);
    let membership_key = MembershipKey::from_secret(
        Secret::random(
            group.ciphersuite(),
            provider.rand(),
            None, /* MLS version */
        )
        .expect("Not enough randomness."),
    );
    let content = AuthenticatedContentIn::from(
        AuthenticatedContent::member_proposal(
            framing_parameters,
            sender_index,
            Proposal::Remove(RemoveProposal {
                removed: LeafNodeIndex::new(7),
            }), // XXX: use random removed
            group.context(),
            signer,
        )
        .expect("An unexpected error occurred."),
    );
    let content = AuthenticatedContent::from(content);
    let mut plaintext: PublicMessage = content.clone().into();
    plaintext
        .set_membership_tag(
            provider.crypto(),
            &membership_key,
            &group.context().tls_serialize_detached().unwrap(),
        )
        .expect("Error setting membership tag.");
    let ciphertext = PrivateMessage::encrypt_without_check(
        &content,
        group.ciphersuite(),
        provider,
        group.message_secrets_test_mut(),
        0,
    )
    .expect("Could not create PrivateMessage");
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
    sender_index: LeafNodeIndex,
    group: &mut CoreGroup,
    signer: &impl Signer,
    provider: &impl OpenMlsProvider,
) -> (Vec<u8>, Vec<u8>) {
    use tls_codec::Serialize;

    use crate::{prelude_test::Secret, schedule::MembershipKey};

    let epoch = random_u64();
    group.context_mut().set_epoch(epoch.into());
    let membership_key = MembershipKey::from_secret(
        Secret::random(
            group.ciphersuite(),
            provider.rand(),
            None, /* MLS version */
        )
        .expect("Not enough randomness."),
    );
    let content = AuthenticatedContent::new_application(
        sender_index,
        &[1, 2, 3],
        &[4, 5, 6],
        group.context(),
        signer,
    )
    .expect("An unexpected error occurred.");
    let mut plaintext: PublicMessage = content.clone().into();
    plaintext
        .set_membership_tag(
            provider.crypto(),
            &membership_key,
            &group.context().tls_serialize_detached().unwrap(),
        )
        .expect("Error setting membership tag.");
    let ciphertext = match PrivateMessage::encrypt_without_check(
        &content,
        group.ciphersuite(),
        provider,
        group.message_secrets_test_mut(),
        0,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Could not create PrivateMessage {e}"),
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

    use crate::binary_tree::array_representation::TreeSize;

    let ciphersuite_name = ciphersuite;
    let crypto = OpenMlsRustCrypto::default();
    let encryption_secret_bytes = crypto
        .rand()
        .random_vec(ciphersuite.hash_length())
        .expect("An unexpected error occurred.");
    let sender_data_secret = SenderDataSecret::random(ciphersuite, crypto.rand());
    let sender_data_secret_bytes = sender_data_secret.as_slice();

    // Create sender_data_key/secret
    let ciphertext = crypto
        .rand()
        .random_vec(77)
        .expect("An unexpected error occurred.");
    let sender_data_key = sender_data_secret
        .derive_aead_key(crypto.crypto(), &ciphertext)
        .expect("Could not derive AEAD key.");
    // Derive initial nonce from the key schedule using the ciphertext.
    let sender_data_nonce = sender_data_secret
        .derive_aead_nonce(ciphersuite, crypto.crypto(), &ciphertext)
        .expect("Could not derive nonce.");
    let sender_data_info = SenderDataInfo {
        ciphertext: bytes_to_hex(&ciphertext),
        key: bytes_to_hex(sender_data_key.as_slice()),
        nonce: bytes_to_hex(sender_data_nonce.as_slice()),
    };

    let (mut group, _, signer) = group(ciphersuite, &crypto);
    *group.message_secrets_test_mut().sender_data_secret_mut() = SenderDataSecret::from_slice(
        sender_data_secret_bytes,
        ProtocolVersion::default(),
        ciphersuite,
    );

    let mut leaves = Vec::new();
    for leaf in 0..n_leaves {
        let sender_leaf = LeafNodeIndex::new(leaf);
        // It doesn't matter who the receiver is, as long as it's not the same
        // as the sender, so we don't get into trouble with the secret tree.
        let receiver_leaf = LeafNodeIndex::new(u32::from(leaf == 0));
        let encryption_secret = EncryptionSecret::from_slice(
            &encryption_secret_bytes[..],
            ProtocolVersion::default(),
            ciphersuite,
        );
        let size = TreeSize::from_leaf_count(n_leaves);
        let encryption_secret_tree = SecretTree::new(encryption_secret, size, sender_leaf);
        let decryption_secret = EncryptionSecret::from_slice(
            &encryption_secret_bytes[..],
            ProtocolVersion::default(),
            ciphersuite,
        );
        let mut decryption_secret_tree = SecretTree::new(decryption_secret, size, receiver_leaf);

        *group.message_secrets_test_mut().secret_tree_mut() = encryption_secret_tree;

        let mut handshake = Vec::new();
        let mut application = Vec::new();
        for generation in 0..n_generations {
            // Application
            let (application_secret_key, application_secret_nonce) = decryption_secret_tree
                .secret_for_decryption(
                    ciphersuite,
                    crypto.crypto(),
                    sender_leaf,
                    SecretType::ApplicationSecret,
                    generation,
                    &SenderRatchetConfiguration::default(),
                )
                .expect("Error getting decryption secret");
            let application_key_string = bytes_to_hex(application_secret_key.as_slice());
            let application_nonce_string = bytes_to_hex(application_secret_nonce.as_slice());
            let (application_plaintext, application_ciphertext) =
                build_application_messages(sender_leaf, &mut group, &signer, &crypto);
            println!("Sender Group: {group:?}");
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
                    crypto.crypto(),
                    sender_leaf,
                    SecretType::HandshakeSecret,
                    generation,
                    &SenderRatchetConfiguration::default(),
                )
                .expect("Error getting decryption secret");
            let handshake_key_string = bytes_to_hex(handshake_secret_key.as_slice());
            let handshake_nonce_string = bytes_to_hex(handshake_secret_nonce.as_slice());

            let (handshake_plaintext, handshake_ciphertext) =
                build_handshake_messages(sender_leaf, &mut group, &signer, &crypto);

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
    let _ = pretty_env_logger::try_init();
    use openmls_traits::crypto::OpenMlsCrypto;
    let mut tests = Vec::new();
    const NUM_LEAVES: u32 = 10;
    const NUM_GENERATIONS: u32 = 15;

    log::debug!("Generating new test vectors ...");

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
    provider: &impl OpenMlsProvider,
) -> Result<(), EncTestVectorError> {
    use tls_codec::{Deserialize, Serialize};

    use crate::{
        binary_tree::array_representation::TreeSize,
        schedule::{message_secrets::MessageSecrets, ConfirmationKey, MembershipKey},
    };

    let n_leaves = test_vector.n_leaves;
    if n_leaves != test_vector.leaves.len() as u32 {
        return Err(EncTestVectorError::LeafNumberMismatch);
    }
    let size = TreeSize::from_leaf_count(n_leaves);
    let ciphersuite = Ciphersuite::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");
    log::debug!("Running test vector with {:?}", ciphersuite);

    let sender_data_secret = SenderDataSecret::from_slice(
        hex_to_bytes(&test_vector.sender_data_secret).as_slice(),
        ProtocolVersion::default(),
        ciphersuite,
    );

    let sender_data_key = sender_data_secret
        .derive_aead_key(
            provider.crypto(),
            &hex_to_bytes(&test_vector.sender_data_info.ciphertext),
        )
        .expect("Could not derive AEAD key.");
    let sender_data_nonce = sender_data_secret
        .derive_aead_nonce(
            ciphersuite,
            provider.crypto(),
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
        log::trace!("leaf_index: {leaf_index}");
        // It doesn't matter who the receiver is, as long as it's not the same
        // as the sender, so we don't get into trouble with the secret tree.
        let receiver_leaf = LeafNodeIndex::new(u32::from(leaf_index == 0));

        let mut secret_tree = SecretTree::new(
            EncryptionSecret::from_slice(
                hex_to_bytes(&test_vector.encryption_secret).as_slice(),
                ProtocolVersion::default(),
                ciphersuite,
            ),
            size,
            receiver_leaf,
        );

        log_crypto!(debug, "Encryption secret tree: {secret_tree:?}");
        log::trace!("Running test vector for leaf {leaf_index:?}");
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
        let leaf_index = LeafNodeIndex::new(leaf_index as u32);

        // We keep a fresh copy of the secret tree so we don't lose any secrets.
        let fresh_secret_tree = secret_tree.clone();

        for (generation, application, handshake) in
            izip!((0..leaf.generations), &leaf.application, &leaf.handshake,)
        {
            // Check application keys
            let (application_secret_key, application_secret_nonce) = secret_tree
                .secret_for_decryption(
                    ciphersuite,
                    provider.crypto(),
                    leaf_index,
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
            log_crypto!(debug, "  {:?}", secret_tree);
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
            // We need to get the application message first to get the group id.
            let ctxt_bytes = hex_to_bytes(&application.ciphertext);
            let mls_ciphertext_application = PrivateMessageIn::tls_deserialize_exact(ctxt_bytes)
                .expect("Error parsing PrivateMessage");
            let (mut group, _, _) = receiver_group(
                ciphersuite,
                provider,
                mls_ciphertext_application.group_id().clone(),
            );
            *group.message_secrets_test_mut().sender_data_secret_mut() =
                SenderDataSecret::from_slice(
                    hex_to_bytes(&test_vector.sender_data_secret).as_slice(),
                    ProtocolVersion::default(),
                    ciphersuite,
                );

            // We have to take the fresh_secret_tree here because the secret_for_decryption
            // above ratcheted the tree forward.
            let mut message_secrets = MessageSecrets::new(
                sender_data_secret.clone(),
                MembershipKey::random(ciphersuite, provider.rand()), // we don't care about this value
                ConfirmationKey::random(ciphersuite, provider.rand()), // we don't care about this value
                group.context().tls_serialize_detached().unwrap(),
                fresh_secret_tree.clone(),
            );

            // Decrypt and check application message
            let sender_data = mls_ciphertext_application
                .sender_data(
                    group.message_secrets_test_mut(),
                    provider.crypto(),
                    ciphersuite,
                )
                .expect("Unable to get sender data");
            let mls_plaintext_application: AuthenticatedContentIn = mls_ciphertext_application
                .to_verifiable_content(
                    ciphersuite,
                    provider.crypto(),
                    &mut message_secrets,
                    leaf_index,
                    &SenderRatchetConfiguration::default(),
                    sender_data,
                )
                .expect("Error decrypting PrivateMessage")
                .into();
            assert!(matches!(
                mls_plaintext_application.content(),
                FramedContentBodyIn::Application(_)
            ));
            let expected_plaintext = hex_to_bytes(&application.plaintext);
            let exp = PublicMessageIn::tls_deserialize_exact(expected_plaintext).unwrap();
            if exp.content() != mls_plaintext_application.content() {
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
                    provider.crypto(),
                    leaf_index,
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
            let mls_ciphertext_handshake = PrivateMessageIn::tls_deserialize_exact(handshake_bytes)
                .expect("Error parsing PrivateMessage");
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
                .sender_data(
                    group.message_secrets_test_mut(),
                    provider.crypto(),
                    ciphersuite,
                )
                .expect("Unable to get sender data");
            let mls_plaintext_handshake: AuthenticatedContentIn = mls_ciphertext_handshake
                .to_verifiable_content(
                    ciphersuite,
                    provider.crypto(),
                    group.message_secrets_test_mut(),
                    leaf_index,
                    &SenderRatchetConfiguration::default(),
                    sender_data,
                )
                .expect("Error decrypting PrivateMessage")
                .into();

            assert!(matches!(
                mls_plaintext_handshake.content(),
                FramedContentBodyIn::Commit(_) | FramedContentBodyIn::Proposal(_)
            ));
            let expected_plaintext = hex_to_bytes(&handshake.plaintext);
            let exp = PublicMessageIn::tls_deserialize_exact(expected_plaintext).unwrap();

            if exp.content() != mls_plaintext_handshake.content() {
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
                    provider.crypto(),
                    leaf_index,
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
            let mls_ciphertext_handshake = PrivateMessageIn::tls_deserialize_exact(handshake_bytes)
                .expect("Error parsing PrivateMessage");
            let (mut group, _, _) = receiver_group(
                ciphersuite,
                provider,
                mls_ciphertext_handshake.group_id().clone(),
            );
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
                .sender_data(
                    group.message_secrets_test_mut(),
                    provider.crypto(),
                    ciphersuite,
                )
                .expect("Unable to get sender data");
            let mls_plaintext_handshake: AuthenticatedContentIn = mls_ciphertext_handshake
                .to_verifiable_content(
                    ciphersuite,
                    provider.crypto(),
                    group.message_secrets_test_mut(),
                    leaf_index,
                    &SenderRatchetConfiguration::default(),
                    sender_data,
                )
                .expect("Error decrypting PrivateMessage")
                .into();

            assert!(matches!(
                mls_plaintext_handshake.content(),
                FramedContentBodyIn::Commit(_) | FramedContentBodyIn::Proposal(_)
            ));
            let expected_plaintext = hex_to_bytes(&handshake.plaintext);
            let expected_plaintext =
                PublicMessageIn::tls_deserialize_exact(expected_plaintext).unwrap();

            if expected_plaintext.content() != mls_plaintext_handshake.content() {
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

#[apply(providers)]
fn read_test_vectors_encryption(provider: &impl OpenMlsProvider) {
    let _ = pretty_env_logger::try_init();
    log::debug!("Reading test vectors ...");

    let tests: Vec<EncryptionTestVector> = read("test_vectors/kat_encryption_openmls.json");

    for test_vector in tests {
        match run_test_vector(test_vector, provider) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking encryption test vector.\n{e:?}"),
        }
    }

    // mlspp test vectors
    let tv_files = [
        /*
        mlspp test vectors are not compatible for now because they don't implement
        the new wire_format field in framing yet. This is tracked in #495.
        "test_vectors/mlspp/mlspp_encryption_1_10.json",
        "test_vectors/mlspp/mlspp_encryption_2_10.json",
        "test_vectors/mlspp/mlspp_encryption_3_10.json",
        */
    ];
    for &tv_file in tv_files.iter() {
        let tv: EncryptionTestVector = read(tv_file);
        run_test_vector(tv, provider).expect("Error while checking key schedule test vector.");
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
