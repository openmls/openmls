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

use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;
use serde::{self, Deserialize, Serialize};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    framing::{mls_auth_content::AuthenticatedContent, mls_content::FramedContentBody, *},
    group::*,
    schedule::{EncryptionSecret, SenderDataSecret},
    test_utils::*,
    tree::{secret_tree::SecretTree, sender_ratchet::SenderRatchetConfiguration},
    versions::ProtocolVersion,
};

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

#[cfg(test)]
pub fn run_test_vector(
    test: MessageProtectionTest,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<(), String> {
    use openmls_traits::crypto::OpenMlsCrypto;
    use tls_codec::{Deserialize, Serialize};

    use crate::{
        binary_tree::array_representation::TreeSize,
        extensions::Extensions,
        group::config::CryptoConfig,
        messages::{proposals_in::ProposalIn, CommitIn},
        prelude::KeyPackageBundle,
        prelude_test::Secret,
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
    log::debug!("Testing tv with ciphersuite {:?}", ciphersuite);

    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::from_slice(&hex_to_bytes(&test.group_id)),
        test.epoch,
        hex_to_bytes(&test.tree_hash),
        hex_to_bytes(&test.confirmed_transcript_hash),
        Extensions::empty(),
    );

    let encryption_secret = EncryptionSecret::from_slice(
        &hex_to_bytes(&test.encryption_secret),
        group_context.protocol_version(),
        ciphersuite,
    );
    let own_index = LeafNodeIndex::new(0);
    let secret_tree = SecretTree::new(encryption_secret, TreeSize::new(2), own_index);

    // Set up the group, unfortunately we can't do without.
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

    let random_own_credential =
        SignatureKeyPair::new(ciphersuite.signature_algorithm(), "KeyOwner".into()).unwrap();
    let random_own_signature_key = random_own_credential.public();
    let credential = SignatureKeyPair::from_raw(
        ciphersuite.signature_algorithm(),
        signature_private_key,
        random_own_signature_key.to_vec(),
        "KeyOwner with tv private key".into(),
    );

    let mut group = CoreGroup::builder(
        group_context.group_id().clone(),
        CryptoConfig::with_default_version(ciphersuite),
    )
    .build(backend, &credential, &credential)
    .unwrap();

    // Make the group think it has two members.
    {
        let mut credential =
            SignatureKeyPair::new(ciphersuite.signature_algorithm(), "Fake user".into()).unwrap();
        // inject the public key from the tv.
        credential.set_public_key(hex_to_bytes(&test.signature_pub));

        let bob_key_package_bundle =
            KeyPackageBundle::new(backend, &credential, ciphersuite, &credential);
        let bob_key_package = bob_key_package_bundle.key_package();
        let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);
        let bob_add_proposal = group
            .create_add_proposal(framing_parameters, bob_key_package.clone(), &credential)
            .expect("Could not create proposal.");

        let proposal_store = ProposalStore::from_queued_proposal(
            QueuedProposal::from_authenticated_content_by_ref(
                ciphersuite,
                backend,
                bob_add_proposal,
            )
            .expect("Could not create QueuedProposal."),
        );

        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .proposal_store(&proposal_store)
            .force_self_update(false)
            .build();
        let create_commit_result = group
            .create_commit(params, backend, &credential, None)
            .expect("Error creating Commit");

        group
            .merge_commit(backend, create_commit_result.staged_commit)
            .expect("error merging pending commit");
    }

    fn inject(
        group: &mut CoreGroup,
        group_context: GroupContext,
        secret_tree: SecretTree,
        sender_data_secret: Vec<u8>,
        membership_key: Vec<u8>,
        ciphersuite: Ciphersuite,
    ) {
        // Inject the test values into the group
        let serialized_group_context = group_context.tls_serialize_detached().unwrap();
        group.set_group_context(group_context);

        let message_secrets = group.message_secrets_test_mut();
        message_secrets.replace_secret_tree(secret_tree);
        message_secrets.set_serialized_context(serialized_group_context);
        *message_secrets.sender_data_secret_mut() =
            SenderDataSecret::from_slice(&sender_data_secret, ProtocolVersion::Mls10, ciphersuite);
        message_secrets.set_membership_key(Secret::from_slice(
            &membership_key,
            ProtocolVersion::Mls10,
            ciphersuite,
        ));
    }

    inject(
        &mut group,
        group_context.clone(),
        secret_tree.clone(),
        hex_to_bytes(&test.sender_data_secret),
        hex_to_bytes(&test.membership_key),
        ciphersuite,
    );

    // Proposal
    {
        let proposal = ProposalIn::tls_deserialize_exact(hex_to_bytes(&test.proposal)).unwrap();
        let proposal_pub =
            MlsMessageIn::tls_deserialize_exact(hex_to_bytes(&test.proposal_pub)).unwrap();
        let proposal_priv =
            MlsMessageIn::tls_deserialize_exact(hex_to_bytes(&test.proposal_priv)).unwrap();

        // Group stuff we need for openmls
        let sender_ratchet_config = SenderRatchetConfiguration::new(0, 0);
        let proposal_store = ProposalStore::default();

        // TODO: wrap `proposal` into a `PrivateMessage`.
        // TODO: wrap `proposal` into a `PublicMessage`.

        // check that the proposal in proposal_pub == proposal
        let decrypted_message = group
            .decrypt_message(
                backend,
                proposal_pub.into_protocol_message().unwrap(),
                &sender_ratchet_config,
            )
            .unwrap();

        let processed_unverified_message = group
            .public_group()
            .parse_message(decrypted_message, group.message_secrets_store())
            .unwrap();
        let processed_message: AuthenticatedContent =
            processed_unverified_message.verify(backend).unwrap().0;
        match processed_message.content().to_owned() {
            FramedContentBody::Proposal(p) => assert_eq!(proposal, p.into()),
            _ => panic!("Wrong processed message content"),
        }

        // decrypt private message
        let processed_message = group
            .process_message(
                backend,
                proposal_priv.into_protocol_message().unwrap(),
                &sender_ratchet_config,
                &proposal_store,
                &[],
            )
            .unwrap();

        // check that proposal == processed_message
        match processed_message.content().to_owned() {
            ProcessedMessageContent::ProposalMessage(p) => {
                assert_eq!(proposal, p.proposal().to_owned().into())
            }
            _ => panic!("Wrong processed message content"),
        }
    }

    // Reset the state
    inject(
        &mut group,
        group_context,
        secret_tree,
        hex_to_bytes(&test.sender_data_secret),
        hex_to_bytes(&test.membership_key),
        ciphersuite,
    );

    // Commit
    {
        let commit = CommitIn::tls_deserialize_exact(hex_to_bytes(&test.commit)).unwrap();
        let commit_pub =
            MlsMessageIn::tls_deserialize_exact(hex_to_bytes(&test.commit_pub)).unwrap();
        let commit_priv =
            MlsMessageIn::tls_deserialize_exact(hex_to_bytes(&test.commit_priv)).unwrap();

        // Group stuff we need for openmls
        let sender_ratchet_config = SenderRatchetConfiguration::new(10, 10);

        // TODO: wrap `commit` into a `PrivateMessage`.
        // TODO: wrap `commit` into a `PublicMessage`.

        // check that the proposal in proposal_pub == proposal
        let decrypted_message = group
            .decrypt_message(
                backend,
                commit_pub.into_protocol_message().unwrap(),
                &sender_ratchet_config,
            )
            .unwrap();

        let processed_unverified_message = group
            .public_group()
            .parse_message(decrypted_message, group.message_secrets_store())
            .unwrap();
        let processed_message: AuthenticatedContent =
            processed_unverified_message.verify(backend).unwrap().0;
        match processed_message.content().to_owned() {
            FramedContentBody::Commit(c) => {
                assert_eq!(commit, CommitIn::from(c))
            }
            _ => panic!("Wrong processed message content"),
        }

        // check that the proposal in proposal_priv == proposal
        let decrypted_message = group
            .decrypt_message(
                backend,
                commit_priv.into_protocol_message().unwrap(),
                &sender_ratchet_config,
            )
            .unwrap();

        let processed_unverified_message = group
            .public_group()
            .parse_message(decrypted_message, group.message_secrets_store())
            .unwrap();
        let processed_message: AuthenticatedContent =
            processed_unverified_message.verify(backend).unwrap().0;
        match processed_message.content().to_owned() {
            FramedContentBody::Commit(c) => {
                assert_eq!(commit, CommitIn::from(c))
            }
            _ => panic!("Wrong processed message content"),
        }
    }

    // Application
    {
        eprintln!("application_priv: {}", test.application_priv);
        let application = hex_to_bytes(&test.application);
        let application_priv =
            MlsMessageIn::tls_deserialize_exact(hex_to_bytes(&test.application_priv)).unwrap();

        // Group stuff we need for openmls
        let sender_ratchet_config = SenderRatchetConfiguration::new(0, 0);
        let proposal_store = ProposalStore::default();

        // TODO: wrap `application` into a `PrivateMessage`.

        // check that the proposal in proposal_pub == proposal
        let processed_message = group
            .process_message(
                backend,
                application_priv.into_ciphertext().unwrap(),
                &sender_ratchet_config,
                &proposal_store,
                &[],
            )
            .unwrap();
        match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(a) => {
                assert_eq!(application, a.into_bytes())
            }
            _ => panic!("Wrong processed message content"),
        }
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
