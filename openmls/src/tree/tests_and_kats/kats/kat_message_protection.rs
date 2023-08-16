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
use openmls_traits::{types::SignatureScheme, OpenMlsProvider};
use serde::{self, Deserialize, Serialize};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    credentials::{Credential, CredentialType, CredentialWithKey},
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

#[cfg(test)]
pub fn run_test_vector(
    test: MessageProtectionTest,
    provider: &impl OpenMlsProvider,
) -> Result<(), String> {
    use openmls_traits::crypto::OpenMlsCrypto;
    use tls_codec::{Deserialize, Serialize};

    use crate::{
        binary_tree::array_representation::TreeSize,
        extensions::Extensions,
        group::config::CryptoConfig,
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
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        test: &MessageProtectionTest,
        sender: bool,
    ) -> CoreGroup {
        let group_context = GroupContext::new(
            ciphersuite,
            GroupId::from_slice(&hex_to_bytes(&test.group_id)),
            test.epoch,
            hex_to_bytes(&test.tree_hash),
            hex_to_bytes(&test.confirmed_transcript_hash),
            Extensions::empty(),
        );

        // Set up the group, unfortunately we can't do without.
        let credential =
            Credential::new(b"This is not needed".to_vec(), CredentialType::Basic).unwrap();
        let signature_private_key = hex_to_bytes(&test.signature_priv);
        let random_own_signature_key =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        let random_own_signature_key = random_own_signature_key.public();
        let signer = SignatureKeyPair::from_raw(
            ciphersuite.signature_algorithm(),
            signature_private_key,
            random_own_signature_key.to_vec(),
        );

        let mut group = CoreGroup::builder(
            group_context.group_id().clone(),
            CryptoConfig::with_default_version(ciphersuite),
            CredentialWithKey {
                credential,
                signature_key: random_own_signature_key.into(),
            },
        )
        .build(provider, &signer)
        .unwrap();

        let credential = Credential::new("Fake user".into(), CredentialType::Basic).unwrap();
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        let bob_key_package_bundle = KeyPackageBundle::new(
            provider,
            &signature_keys,
            ciphersuite,
            CredentialWithKey {
                credential,
                signature_key: hex_to_bytes(&test.signature_pub).into(),
            },
        );
        let bob_key_package = bob_key_package_bundle.key_package();
        let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);
        let bob_add_proposal = group
            .create_add_proposal(framing_parameters, bob_key_package.clone(), &signer)
            .expect("Could not create proposal.");

        let proposal_store = ProposalStore::from_queued_proposal(
            QueuedProposal::from_authenticated_content_by_ref(
                ciphersuite,
                provider.crypto(),
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
            .create_commit(params, provider, &signer)
            .expect("Error creating Commit");

        group
            .merge_commit(provider, create_commit_result.staged_commit)
            .expect("error merging pending commit");

        // Inject the test values into the group

        let encryption_secret = EncryptionSecret::from_slice(
            &hex_to_bytes(&test.encryption_secret),
            group_context.protocol_version(),
            ciphersuite,
        );
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
        *message_secrets.sender_data_secret_mut() = SenderDataSecret::from_slice(
            &hex_to_bytes(&test.sender_data_secret),
            ProtocolVersion::Mls10,
            ciphersuite,
        );
        message_secrets.set_membership_key(Secret::from_slice(
            &hex_to_bytes(&test.membership_key),
            ProtocolVersion::Mls10,
            ciphersuite,
        ));

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
            mut group: CoreGroup,
            provider: &impl OpenMlsProvider,
            ciphersuite: Ciphersuite,
            proposal: ProposalIn,
            proposal_pub: MlsMessageIn,
        ) {
            // Group stuff we need for openmls
            let sender_ratchet_config = SenderRatchetConfiguration::new(0, 0);

            // check that the proposal in proposal_pub == proposal
            let decrypted_message = group
                .decrypt_message(
                    provider.crypto(),
                    proposal_pub.into_protocol_message().unwrap(),
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
                FramedContentBody::Proposal(p) => assert_eq!(proposal, p.into()),
                _ => panic!("Wrong processed message content"),
            }
        }

        test_proposal_pub(
            setup_group(provider, ciphersuite, &test, false),
            provider,
            ciphersuite,
            proposal.clone(),
            proposal_pub,
        );

        fn test_proposal_priv(
            mut group: CoreGroup,
            provider: &impl OpenMlsProvider,
            proposal: ProposalIn,
            proposal_priv: MlsMessageIn,
        ) {
            // Group stuff we need for openmls
            let sender_ratchet_config = SenderRatchetConfiguration::new(0, 0);
            let proposal_store = ProposalStore::default();

            // decrypt private message
            let processed_message = group
                .process_message(
                    provider,
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

        let group = setup_group(provider, ciphersuite, &test, false);
        test_proposal_priv(group, provider, proposal.clone(), proposal_priv);

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
            .encrypt(proposal_authenticated_content, 0, provider)
            .unwrap();
        let my_proposal_priv_out =
            MlsMessageOut::from_private_message(my_proposal_priv, group.version());

        test_proposal_priv(
            group,
            provider,
            proposal.clone(),
            my_proposal_priv_out.into(),
        );

        // Wrap `proposal` into a `PublicMessage`.
        let group = setup_group(provider, ciphersuite, &test, false);
        let sender_group = setup_group(provider, ciphersuite, &test, true);
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
                sender_group.message_secrets().membership_key(),
                sender_group.message_secrets().serialized_context(),
            )
            .expect("error setting membership tag");
        let my_proposal_pub_out: MlsMessageOut = my_proposal_pub.into();

        test_proposal_pub(
            group,
            provider,
            ciphersuite,
            proposal,
            my_proposal_pub_out.into(),
        );
    }

    // Commit
    {
        let commit = CommitIn::tls_deserialize_exact(hex_to_bytes(&test.commit)).unwrap();
        let commit_pub =
            MlsMessageIn::tls_deserialize_exact(hex_to_bytes(&test.commit_pub)).unwrap();
        let commit_priv =
            MlsMessageIn::tls_deserialize_exact(hex_to_bytes(&test.commit_priv)).unwrap();

        fn test_commit_pub(
            mut group: CoreGroup,
            provider: &impl OpenMlsProvider,
            ciphersuite: Ciphersuite,
            commit: CommitIn,
            commit_pub: MlsMessageIn,
        ) {
            // Group stuff we need for openmls
            let sender_ratchet_config = SenderRatchetConfiguration::new(10, 10);

            // check that the proposal in proposal_pub == proposal
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

        fn test_commit_priv(
            mut group: CoreGroup,
            provider: &impl OpenMlsProvider,
            ciphersuite: Ciphersuite,
            commit: CommitIn,
            commit_priv: MlsMessageIn,
        ) {
            // Group stuff we need for openmls
            let sender_ratchet_config = SenderRatchetConfiguration::new(10, 10);

            // check that the proposal in proposal_priv == proposal
            let decrypted_message = group
                .decrypt_message(
                    provider.crypto(),
                    commit_priv.into_protocol_message().unwrap(),
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

        test_commit_priv(
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
            .encrypt(commit_authenticated_content, 0, provider)
            .unwrap();
        let my_commit_priv_out =
            MlsMessageOut::from_private_message(my_commit_pub, group.version());

        test_commit_priv(
            group,
            provider,
            ciphersuite,
            commit.clone(),
            my_commit_priv_out.into(),
        );

        // Wrap `commit` into a `PublicMessage`.
        let group = setup_group(provider, ciphersuite, &test, false);
        let sender_group = setup_group(provider, ciphersuite, &test, true);
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
                sender_group.message_secrets().membership_key(),
                sender_group.message_secrets().serialized_context(),
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
            mut group: CoreGroup,
            provider: &impl OpenMlsProvider,
            application: Vec<u8>,
            application_priv: MlsMessageIn,
        ) {
            // Group stuff we need for openmls
            let sender_ratchet_config = SenderRatchetConfiguration::new(0, 0);
            let proposal_store = ProposalStore::default();

            // check that the proposal in proposal_pub == proposal
            let processed_message = group
                .process_message(
                    provider,
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

        test_application_priv(
            setup_group(provider, ciphersuite, &test, false),
            provider,
            application.clone(),
            application_priv,
        );

        // Wrap `application` into a `PrivateMessage`.
        let mut sender_group = setup_group(provider, ciphersuite, &test, true);
        let private_message = sender_group
            .create_application_message(&[], &application, 0, provider, &signer)
            .unwrap();
        let my_application_priv_out =
            MlsMessageOut::from_private_message(private_message, sender_group.version());

        test_application_priv(
            setup_group(provider, ciphersuite, &test, false),
            provider,
            application.clone(),
            my_application_priv_out.into(),
        );
    }

    log::trace!("Finished test verification");

    Ok(())
}

#[apply(providers)]
fn read_test_vectors_mp(provider: &impl OpenMlsProvider) {
    let _ = pretty_env_logger::try_init();
    log::debug!("Reading test vectors ...");

    let tests: Vec<MessageProtectionTest> = read("test_vectors/message-protection.json");

    for test_vector in tests {
        match run_test_vector(test_vector, provider) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking message protection test vector.\n{e:?}"),
        }
    }
    log::trace!("Finished test vector verification");
}
