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
use serde::{self, Deserialize, Serialize};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    credentials::{BasicCredential, CredentialWithKey},
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
    provider: &impl crate::storage::OpenMlsProvider,
) -> Result<(), String> {
    use openmls_traits::crypto::OpenMlsCrypto;
    use tls_codec::{Deserialize, Serialize};

    use crate::{
        binary_tree::array_representation::TreeSize,
        extensions::Extensions,
        messages::{proposals_in::ProposalIn, CommitIn, ConfirmationTag},
        prelude::KeyPackageBundle,
        prelude_test::{Mac, Secret},
    };

    let ciphersuite = test.cipher_suite.try_into().unwrap();
    if !provider
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

    let sender_index = LeafNodeIndex::new(1);

    // Set up the group, unfortunately we can't do without.
    let signature_private_key = hex_to_bytes(&test.signature_priv);
    let random_own_signature_key =
        SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let random_own_signature_key = random_own_signature_key.public();
    let signer = SignatureKeyPair::from_raw(
        ciphersuite.signature_algorithm(),
        signature_private_key,
        random_own_signature_key.to_vec(),
    );

    // Make the group think it has two members.
    fn setup_group(
        provider: &impl crate::storage::OpenMlsProvider,
        ciphersuite: Ciphersuite,
        test: &MessageProtectionTest,
        sender: bool,
    ) -> MlsGroup {
        let group_context = GroupContext::new(
            ciphersuite,
            GroupId::from_slice(&hex_to_bytes(&test.group_id)),
            test.epoch,
            hex_to_bytes(&test.tree_hash),
            hex_to_bytes(&test.confirmed_transcript_hash),
            Extensions::empty(),
        );

        // Set up the group, unfortunately we can't do without.
        let credential = BasicCredential::new(b"This is not needed".to_vec());
        let signature_private_key = hex_to_bytes(&test.signature_priv);
        let random_own_signature_key =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        let random_own_signature_key = random_own_signature_key.public();
        let signer = SignatureKeyPair::from_raw(
            ciphersuite.signature_algorithm(),
            signature_private_key,
            random_own_signature_key.to_vec(),
        );

        let mut group = MlsGroup::builder()
            .ciphersuite(ciphersuite)
            .with_wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build(
                provider,
                &signer,
                CredentialWithKey {
                    credential: credential.into(),
                    signature_key: random_own_signature_key.into(),
                },
            )
            .unwrap();

        let credential = BasicCredential::new("Fake user".into());
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        let bob_key_package_bundle = KeyPackageBundle::generate(
            provider,
            &signature_keys,
            ciphersuite,
            CredentialWithKey {
                credential: credential.into(),
                signature_key: hex_to_bytes(&test.signature_pub).into(),
            },
        );
        let bob_key_package = bob_key_package_bundle.key_package();
        let (_commit, _welcome, _) = group
            .add_members(provider, &signature_keys, &[bob_key_package.clone()])
            .unwrap();
        group.merge_pending_commit(provider).unwrap();

        // Inject the test values into the group

        let encryption_secret =
            EncryptionSecret::from_slice(&hex_to_bytes(&test.encryption_secret));
        let own_index = LeafNodeIndex::new(0);
        let sender_index = LeafNodeIndex::new(1);
        let secret_tree = SecretTree::new(encryption_secret.clone(), TreeSize::new(2), own_index);
        let sender_secret_tree = SecretTree::new(encryption_secret, TreeSize::new(2), sender_index);

        let serialized_group_context = group_context.tls_serialize_detached().unwrap();
        group.set_group_context(group_context);

        if sender {
            // Force the sender index
            group.set_own_leaf_index(sender_index);
        }

        let message_secrets = group.message_secrets_test_mut();
        if sender {
            message_secrets.replace_secret_tree(sender_secret_tree);
        } else {
            message_secrets.replace_secret_tree(secret_tree);
        }
        message_secrets.set_serialized_context(serialized_group_context);
        *message_secrets.sender_data_secret_mut() =
            SenderDataSecret::from_slice(&hex_to_bytes(&test.sender_data_secret));
        message_secrets.set_membership_key(Secret::from_slice(&hex_to_bytes(&test.membership_key)));

        group
    }

    // Proposal
    {
        let proposal = ProposalIn::tls_deserialize_exact(hex_to_bytes(&test.proposal)).unwrap();
        let proposal_pub =
            MlsMessageIn::tls_deserialize_exact(hex_to_bytes(&test.proposal_pub)).unwrap();
        let proposal_priv =
            MlsMessageIn::tls_deserialize_exact(hex_to_bytes(&test.proposal_priv)).unwrap();

        fn test_proposal_pub(
            mut group: MlsGroup,
            provider: &impl crate::storage::OpenMlsProvider,
            proposal: ProposalIn,
            proposal_pub: MlsMessageIn,
        ) {
            // check that the proposal in proposal_pub == proposal
            let processed_message = group
                .process_message(provider, proposal_pub.into_protocol_message().unwrap())
                .unwrap();
            match processed_message.content() {
                ProcessedMessageContent::ProposalMessage(p) => {
                    assert_eq!(proposal, p.proposal().to_owned().into())
                }
                _ => panic!("Wrong processed message content"),
            }
        }

        test_proposal_pub(
            setup_group(provider, ciphersuite, &test, false),
            provider,
            proposal.clone(),
            proposal_pub,
        );

        let group = setup_group(provider, ciphersuite, &test, false);
        test_proposal_pub(group, provider, proposal.clone(), proposal_priv);

        // Wrap `proposal` into a `PrivateMessage`.
        let group = setup_group(provider, ciphersuite, &test, false);
        let mut sender_group = setup_group(provider, ciphersuite, &test, true);
        let proposal_authenticated_content = AuthenticatedContent::member_proposal(
            FramingParameters::new(&[], WireFormat::PrivateMessage),
            sender_index,
            proposal.clone().into(),
            &group_context,
            &signer,
        )
        .unwrap();
        let my_proposal_priv = sender_group
            .encrypt(proposal_authenticated_content, provider)
            .unwrap();
        let my_proposal_priv_out = MlsMessageOut::from_private_message(
            my_proposal_priv,
            group.export_group_context().protocol_version(),
        );

        test_proposal_pub(
            group,
            provider,
            proposal.clone(),
            my_proposal_priv_out.into(),
        );

        // Wrap `proposal` into a `PublicMessage`.
        let group = setup_group(provider, ciphersuite, &test, false);
        let mut sender_group = setup_group(provider, ciphersuite, &test, true);
        let proposal_authenticated_content = AuthenticatedContent::member_proposal(
            FramingParameters::new(&[], WireFormat::PublicMessage),
            sender_index,
            proposal.clone().into(),
            &group_context,
            &signer,
        )
        .unwrap();
        let mut my_proposal_pub: PublicMessage = proposal_authenticated_content.into();
        my_proposal_pub
            .set_membership_tag(
                provider.crypto(),
                ciphersuite,
                &sender_group
                    .message_secrets_test_mut()
                    .membership_key()
                    .clone(),
                sender_group.message_secrets_test_mut().serialized_context(),
            )
            .expect("error setting membership tag");
        let my_proposal_pub_out: MlsMessageOut = my_proposal_pub.into();

        test_proposal_pub(group, provider, proposal, my_proposal_pub_out.into());
    }

    // Commit
    {
        let commit = CommitIn::tls_deserialize_exact(hex_to_bytes(&test.commit)).unwrap();
        let commit_pub =
            MlsMessageIn::tls_deserialize_exact(hex_to_bytes(&test.commit_pub)).unwrap();
        let commit_priv =
            MlsMessageIn::tls_deserialize_exact(hex_to_bytes(&test.commit_priv)).unwrap();

        fn test_commit_pub(
            mut group: MlsGroup,
            provider: &impl crate::storage::OpenMlsProvider,
            ciphersuite: Ciphersuite,
            commit: CommitIn,
            commit_pub: MlsMessageIn,
        ) {
            // Group stuff we need for openmls
            let sender_ratchet_config = SenderRatchetConfiguration::new(10, 10);

            // check that the commit in commit_pub == commit
            let decrypted_message = group
                .decrypt_message(
                    provider.crypto(),
                    commit_pub.into_protocol_message().unwrap(),
                    &sender_ratchet_config,
                )
                .unwrap();

            let processed_unverified_message = group
                .public_group()
                .parse_message(decrypted_message, group.message_secrets_store())
                .unwrap();
            let processed_message: AuthenticatedContent = processed_unverified_message
                .verify(ciphersuite, provider.crypto(), ProtocolVersion::Mls10)
                .unwrap()
                .0;
            match processed_message.content().to_owned() {
                FramedContentBody::Commit(c) => {
                    assert_eq!(commit, CommitIn::from(c))
                }
                _ => panic!("Wrong processed message content"),
            }
        }

        test_commit_pub(
            setup_group(provider, ciphersuite, &test, false),
            provider,
            ciphersuite,
            commit.clone(),
            commit_pub,
        );

        test_commit_pub(
            setup_group(provider, ciphersuite, &test, false),
            provider,
            ciphersuite,
            commit.clone(),
            commit_priv,
        );

        // Wrap `commit` into a `PrivateMessage`.
        let group = setup_group(provider, ciphersuite, &test, false);
        let mut sender_group = setup_group(provider, ciphersuite, &test, true);
        let mut commit_authenticated_content = AuthenticatedContent::commit(
            FramingParameters::new(&[], WireFormat::PrivateMessage),
            Sender::Member(sender_index),
            commit.clone().into(),
            &group_context,
            &signer,
        )
        .unwrap();
        commit_authenticated_content.set_confirmation_tag(ConfirmationTag(Mac {
            mac_value: vec![0; 32].into(), // Set a fake mac, we don't check it.
        }));
        let my_commit_pub = sender_group
            .encrypt(commit_authenticated_content, provider)
            .unwrap();
        let my_commit_priv_out = MlsMessageOut::from_private_message(
            my_commit_pub,
            group.export_group_context().protocol_version(),
        );

        test_commit_pub(
            group,
            provider,
            ciphersuite,
            commit.clone(),
            my_commit_priv_out.into(),
        );

        // Wrap `commit` into a `PublicMessage`.
        let group = setup_group(provider, ciphersuite, &test, false);
        let mut sender_group = setup_group(provider, ciphersuite, &test, true);
        let mut commit_authenticated_content = AuthenticatedContent::commit(
            FramingParameters::new(&[], WireFormat::PublicMessage),
            Sender::Member(sender_index),
            commit.clone().into(),
            &group_context,
            &signer,
        )
        .unwrap();
        commit_authenticated_content.set_confirmation_tag(ConfirmationTag(Mac {
            mac_value: vec![0; 32].into(), // Set a fake mac, we don't check it.
        }));
        let mut my_commit_pub_msg: PublicMessage = commit_authenticated_content.into();
        my_commit_pub_msg
            .set_membership_tag(
                provider.crypto(),
                ciphersuite,
                &sender_group
                    .message_secrets_test_mut()
                    .membership_key()
                    .clone(),
                sender_group.message_secrets_test_mut().serialized_context(),
            )
            .expect("error setting membership tag");
        let my_commit_pub_out: MlsMessageOut = my_commit_pub_msg.into();

        test_commit_pub(
            group,
            provider,
            ciphersuite,
            commit,
            my_commit_pub_out.into(),
        );
    }

    // Application
    {
        let application = hex_to_bytes(&test.application);
        let application_priv =
            MlsMessageIn::tls_deserialize_exact(hex_to_bytes(&test.application_priv)).unwrap();

        fn test_application_priv(
            mut group: MlsGroup,
            provider: &impl crate::storage::OpenMlsProvider,
            application: Vec<u8>,
            application_priv: MlsMessageIn,
        ) {
            // check that the proposal in proposal_pub == proposal
            let processed_message = group
                .process_message(provider, application_priv.into_protocol_message().unwrap())
                .unwrap();
            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(a) => {
                    assert_eq!(application, a.into_bytes())
                }
                _ => panic!("Wrong processed message content"),
            }
        }

        test_application_priv(
            setup_group(provider, ciphersuite, &test, false),
            provider,
            application.clone(),
            application_priv,
        );

        // Wrap `application` into a `PrivateMessage`.
        let mut sender_group = setup_group(provider, ciphersuite, &test, true);
        let private_message = sender_group
            .create_message(provider, &signer, &application)
            .unwrap();

        test_application_priv(
            setup_group(provider, ciphersuite, &test, false),
            provider,
            application.clone(),
            private_message.into(),
        );
    }

    log::trace!("Finished test verification");

    Ok(())
}

#[openmls_test::openmls_test]
fn read_test_vectors_mp(provider: &impl crate::storage::OpenMlsProvider) {
    let _ = pretty_env_logger::try_init();
    log::debug!("Reading test vectors ...");

    let tests: Vec<MessageProtectionTest> =
        read_json!("../../../../test_vectors/message-protection.json");

    for test_vector in tests {
        match run_test_vector(test_vector, provider) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking message protection test vector.\n{e:?}"),
        }
    }
    log::trace!("Finished test vector verification");
}
