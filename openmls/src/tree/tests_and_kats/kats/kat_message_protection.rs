#![allow(dead_code)] // Allow dead code for now because none of this is used through test-utils right now.

//! ## Message Protection
//!
//! Parameters:
//! * Ciphersuite
//!
//! Format:
//!
//! ``` text
//! {
//!   "cipher_suite": /* uint16 */,
//!
//!   "group_id": /* hex-encoded binary data */,
//!   "epoch": /* uint64 */,
//!   "tree_hash": /* hex-encoded binary data */,
//!   "confirmed_transcript_hash": /* hex-encoded binary data */,
//!
//!   "signature_priv": /* hex-encoded binary data */,
//!   "signature_pub": /* hex-encoded binary data */,
//!
//!   "encryption_secret": /* hex-encoded binary data */,
//!   "sender_data_secret": /* hex-encoded binary data */,
//!   "membership_key": /* hex-encoded binary data */,
//!
//!   "proposal":  /* serialized Proposal */,
//!   "proposal_pub":  /* serialized MLSMessage(PublicMessage) */,
//!   "proposal_priv":  /* serialized MLSMessage(PrivateMessage) */,
//!
//!   "commit":  /* serialized Commit */,
//!   "commit_pub":  /* serialized MLSMessage(PublicMessage) */,
//!   "commit_priv":  /* serialized MLSMessage(PrivateMessage) */,
//!
//!   "application":  /* hex-encoded binary application data */,
//!   "application_priv":  /* serialized MLSMessage(PrivateMessage) */,
//! }
//! ```
//!
//! Verification:
//!
//! * Construct a GroupContext object with the provided `cipher_suite`, `group_id`,
//!   `epoch`, `tree_hash`, and `confirmed_transcript_hash` values, and empty
//!   `extensions`
//! * Initialize a secret tree for 2 members with the specified
//!   `encryption_secret`
//! * For each of `proposal`, `commit` and `application`:
//!   * In all of these tests, use the member with LeafIndex 1 as the sender
//!   * Verify that the `pub` message verifies with the provided `membership_key`
//!     and `signature_pub`, and produces the raw proposal / commit / application
//!     data
//!   * Verify that protecting the raw value with the provided `membership_key` and
//!     `signature_priv` produces a PublicMessage that verifies with `membership_key`
//!     and `signature_pub`
//!     * When protecting the Commit message, add the supplied confirmation tag
//!     * For the application message, instead verify that protecting as a
//!       PublicMessage fails
//!   * Verify that the `priv` message successfully unprotects using the secret tree
//!     constructed above and `signature_pub`
//!   * Verify that protecting the raw value with the secret tree,
//!     `sender_data_secret`, and `signature_priv` produces a PrivateMessage that
//!     unprotects with the secret tree, `sender_data_secret`, and `signature_pub`
//!     * When protecting the Commit message, add the supplied confirmation tag

use crate::credentials::{Credential, CredentialWithKey};
use crate::messages::proposals::RemoveProposal;
use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    credentials::CredentialType,
    framing::{mls_auth_content::AuthenticatedContent, mls_content::FramedContentBody, *},
    group::*,
    messages::proposals::Proposal,
    schedule::{EncryptionSecret, SenderDataSecret},
    test_utils::*,
    tree::{
        secret_tree::{SecretTree, SecretType},
        sender_ratchet::SenderRatchetConfiguration,
    },
    utils::random_u64,
    versions::ProtocolVersion,
};

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer, types::SignatureScheme, OpenMlsCryptoProvider};

use itertools::izip;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{self, Deserialize, Serialize};
use std::convert::TryFrom;
use thiserror::Error;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MessageProtectionTest {
    cipher_suite: u16,

    group_id: String,
    epoch: u64,
    tree_hash: String,
    confirmed_transcript_hash: String,

    signature_priv: String,
    signature_pub: String,

    encryption_secret: String,
    sender_data_secret: String,
    membership_key: String,

    proposal: String,
    proposal_pub: String,
    proposal_priv: String,

    commit: String,
    commit_pub: String,
    commit_priv: String,

    application: String,
    application_priv: String,
}

fn generate_credential(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    backend: &impl OpenMlsCryptoProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = Credential::new(identity, credential_type).unwrap();
    let signature_keys = SignatureKeyPair::new(signature_algorithm).unwrap();
    signature_keys.store(backend.key_store()).unwrap();

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
    backend: &impl OpenMlsCryptoProvider,
) -> (CoreGroup, CredentialWithKey, SignatureKeyPair) {
    use crate::group::config::CryptoConfig;

    let (credential_with_key, signer) = generate_credential(
        "Kreator".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    );

    let group = CoreGroup::builder(
        GroupId::random(backend),
        CryptoConfig::with_default_version(ciphersuite),
        credential_with_key.clone(),
    )
    .build(backend, &signer)
    .unwrap();

    (group, credential_with_key, signer)
}

#[cfg(any(feature = "test-utils", test))]
fn receiver_group(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    group_id: GroupId,
) -> (CoreGroup, CredentialWithKey, SignatureKeyPair) {
    use crate::group::config::CryptoConfig;

    let (credential_with_key, signer) = generate_credential(
        "Receiver".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    );

    let group = CoreGroup::builder(
        group_id,
        CryptoConfig::with_default_version(ciphersuite),
        credential_with_key.clone(),
    )
    .build(backend, &signer)
    .unwrap();

    (group, credential_with_key, signer)
}

#[cfg(any(feature = "test-utils", test))]
pub fn run_test_vector(
    test: MessageProtectionTest,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<(), String> {
    use openmls_traits::crypto::OpenMlsCrypto;
    use tls_codec::Deserialize;

    use crate::{
        binary_tree::array_representation::TreeSize, extensions::Extensions,
        group::config::CryptoConfig, messages::Commit,
    };

    let ciphersuite = test.cipher_suite.try_into().unwrap();
    if !backend
        .crypto()
        .supported_ciphersuites()
        .contains(&ciphersuite)
    {
        log::debug!("Skipping unsupported ciphersuite {:?}", ciphersuite);
        return Ok(());
    }

    let group_context = GroupContext::new(
        test.cipher_suite.try_into().unwrap(),
        GroupId::from_slice(&hex_to_bytes(&test.group_id)),
        test.epoch,
        hex_to_bytes(&test.tree_hash),
        hex_to_bytes(&test.confirmed_transcript_hash).into(),
        Extensions::empty(),
    );

    let encryption_secret = EncryptionSecret::from_slice(
        &hex_to_bytes(&test.encryption_secret),
        group_context.protocol_version(),
        group_context.ciphersuite(),
    );
    let own_index = LeafNodeIndex::new(0);
    let secret_tree = SecretTree::new(encryption_secret, TreeSize::from_leaf_count(2), own_index);

    let sender = LeafNodeIndex::new(1);

    // Set up the group, unfortunately we can't do without.
    let credential =
        Credential::new(b"This is not needed".to_vec(), CredentialType::Basic).unwrap();
    let credential_with_key = CredentialWithKey {
        credential,
        signature_key: hex_to_bytes(&test.signature_pub).into(),
    };
    let signature_private_key = match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            let mut private = hex_to_bytes(&test.signature_priv);
            private.append(&mut hex_to_bytes(&test.signature_pub));
            private
        }
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => hex_to_bytes(&test.signature_priv),
        _ => unimplemented!(),
    };
    let signer = SignatureKeyPair::from_raw(
        group_context.ciphersuite().signature_algorithm(),
        signature_private_key,
        credential_with_key.signature_key.as_slice().to_vec(),
    );
    let mut group = CoreGroup::builder(
        group_context.group_id().clone(),
        CryptoConfig::with_default_version(group_context.ciphersuite()),
        credential_with_key,
    )
    .build(backend, &signer)
    .unwrap();

    group.set_group_context(group_context.clone());

    // Proposal
    {
        let proposal =
            Proposal::tls_deserialize(&mut hex_to_bytes(&test.proposal).as_slice()).unwrap();
        let proposal_pub =
            MlsMessageIn::tls_deserialize(&mut hex_to_bytes(&test.proposal_pub).as_slice())
                .unwrap();
        let proposal_priv =
            MlsMessageIn::tls_deserialize(&mut hex_to_bytes(&test.proposal_priv).as_slice())
                .unwrap();

        // decrypt private message
        let protocol_msg = proposal_priv.into_protocol_message().unwrap();

        let sender_ratchet_config = SenderRatchetConfiguration::new(0, 0);
        let proposal_store = ProposalStore::default();
        let processed_message = group
            .process_message(
                backend,
                protocol_msg,
                &sender_ratchet_config,
                &proposal_store,
                &[],
            )
            .unwrap();
    }

    // Commit
    {
        let commit = Commit::tls_deserialize(&mut hex_to_bytes(&test.commit).as_slice()).unwrap();
        let commit_pub =
            MlsMessageIn::tls_deserialize(&mut hex_to_bytes(&test.commit_pub).as_slice()).unwrap();
        let commit_priv =
            MlsMessageIn::tls_deserialize(&mut hex_to_bytes(&test.commit_priv).as_slice()).unwrap();
    }

    // Application
    {
        eprintln!("application_priv: {}", test.application_priv);
        let application = hex_to_bytes(&test.application);
        let application_priv =
            MlsMessageIn::tls_deserialize(&mut hex_to_bytes(&test.application_priv).as_slice())
                .unwrap();
    }

    log::trace!("Finished test verification");

    Ok(())
}

#[apply(backends)]
fn read_test_vectors_mp(backend: &impl OpenMlsCryptoProvider) {
    let _ = pretty_env_logger::try_init();
    log::debug!("Reading test vectors ...");

    let tests: Vec<MessageProtectionTest> = read("test_vectors/message-protection.json");

    for test_vector in tests {
        match run_test_vector(test_vector, backend) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking message protection test vector.\n{e:?}"),
        }
    }
    log::trace!("Finished test vector verification");
}
