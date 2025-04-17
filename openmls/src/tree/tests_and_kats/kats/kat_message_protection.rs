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
use openmls_traits::random::OpenMlsRand;
use openmls_traits::{types::SignatureScheme, OpenMlsCryptoProvider};
use serde::{self, Deserialize, Serialize};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    credentials::{Credential, CredentialWithKey},
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

    #[serde(with = "hex::serde")]
    group_id: Vec<u8>,
    epoch: u64,
    #[serde(with = "hex::serde")]
    tree_hash: Vec<u8>,
    #[serde(with = "hex::serde")]
    confirmed_transcript_hash: Vec<u8>,

    #[serde(with = "hex::serde")]
    signature_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature_pub: Vec<u8>,

    #[serde(with = "hex::serde")]
    encryption_secret: Vec<u8>,
    #[serde(with = "hex::serde")]
    sender_data_secret: Vec<u8>,
    #[serde(with = "hex::serde")]
    membership_key: Vec<u8>,

    #[serde(with = "hex::serde")]
    proposal: Vec<u8>,
    #[serde(with = "hex::serde")]
    proposal_pub: Vec<u8>,
    #[serde(with = "hex::serde")]
    proposal_priv: Vec<u8>,

    #[serde(with = "hex::serde")]
    commit: Vec<u8>,
    #[serde(with = "hex::serde")]
    commit_pub: Vec<u8>,
    #[serde(with = "hex::serde")]
    commit_priv: Vec<u8>,

    #[serde(with = "hex::serde")]
    application: Vec<u8>,
    #[serde(with = "hex::serde")]
    application_priv: Vec<u8>,
}

async fn generate_credential(
    identity: Vec<u8>,
    signature_algorithm: SignatureScheme,
    backend: &impl OpenMlsCryptoProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = Credential::new_basic(identity);
    let signature_keys = SignatureKeyPair::new(
        signature_algorithm,
        &mut *backend.rand().borrow_rand().unwrap(),
    )
    .unwrap();
    signature_keys.store(backend.key_store()).await.unwrap();

    (
        CredentialWithKey {
            credential,
            signature_key: signature_keys.to_public_vec().into(),
        },
        signature_keys,
    )
}

#[cfg(any(feature = "test-utils", test))]
async fn group(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (CoreGroup, CredentialWithKey, SignatureKeyPair) {
    use crate::group::config::CryptoConfig;

    let (credential_with_key, signer) =
        generate_credential("Kreator".into(), ciphersuite.signature_algorithm(), backend).await;

    let group = CoreGroup::builder(
        GroupId::random(backend),
        CryptoConfig::with_default_version(ciphersuite),
        credential_with_key.clone(),
    )
    .build(backend, &signer)
    .await
    .unwrap();

    (group, credential_with_key, signer)
}

#[cfg(any(feature = "test-utils", test))]
async fn receiver_group(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    group_id: GroupId,
) -> (CoreGroup, CredentialWithKey, SignatureKeyPair) {
    use crate::group::config::CryptoConfig;

    let (credential_with_key, signer) = generate_credential(
        "Receiver".into(),
        ciphersuite.signature_algorithm(),
        backend,
    )
    .await;

    let group = CoreGroup::builder(
        group_id,
        CryptoConfig::with_default_version(ciphersuite),
        credential_with_key.clone(),
    )
    .build(backend, &signer)
    .await
    .unwrap();

    (group, credential_with_key, signer)
}

#[cfg(test)]
pub async fn run_test_vector(
    test: MessageProtectionTest,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<(), String> {
    use openmls_traits::crypto::OpenMlsCrypto;
    use tls_codec::{Deserialize, Serialize};

    use crate::{
        binary_tree::array_representation::TreeSize,
        extensions::Extensions,
        group::{config::CryptoConfig, group_context::GroupContext},
        messages::{proposals_in::ProposalIn, CommitIn, ConfirmationTag},
        prelude::KeyPackageBundle,
        prelude_test::{Mac, Secret},
    };

    let ciphersuite = test.cipher_suite.try_into().unwrap();
    if !backend
        .crypto()
        .supported_ciphersuites()
        .contains(&ciphersuite)
    {
        log::warn!("Skipping unsupported ciphersuite {:?}", ciphersuite);
        return Ok(());
    }
    log::info!("Testing tv with ciphersuite {:?}", ciphersuite);

    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::from_slice(&test.group_id),
        test.epoch,
        test.tree_hash.clone(),
        test.confirmed_transcript_hash.clone(),
        Extensions::empty(),
    );

    let sender_index = LeafNodeIndex::new(1);

    // Set up the group, unfortunately we can't do without.
    let signature_private_key = test.signature_priv.clone();
    let random_own_signature_key = SignatureKeyPair::new(
        ciphersuite.signature_algorithm(),
        &mut *backend.rand().borrow_rand().unwrap(),
    )
    .unwrap();
    let random_own_signature_key = random_own_signature_key.public();
    let signer = SignatureKeyPair::from_raw(
        ciphersuite.signature_algorithm(),
        signature_private_key,
        random_own_signature_key.to_vec(),
    );

    // Make the group think it has two members.
    async fn setup_group(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        test: &MessageProtectionTest,
        sender: bool,
    ) -> CoreGroup {
        let group_context = GroupContext::new(
            ciphersuite,
            GroupId::from_slice(&test.group_id),
            test.epoch,
            test.tree_hash.clone(),
            test.confirmed_transcript_hash.clone(),
            Extensions::empty(),
        );

        // Set up the group, unfortunately we can't do without.
        let credential = Credential::new_basic(b"This is not needed".to_vec());

        let random_own_signature_key = SignatureKeyPair::new(
            ciphersuite.signature_algorithm(),
            &mut *backend.rand().borrow_rand().unwrap(),
        )
        .unwrap();
        let random_own_signature_key = random_own_signature_key.public();
        let signer = SignatureKeyPair::from_raw(
            ciphersuite.signature_algorithm(),
            test.signature_priv.clone(),
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
        .build(backend, &signer)
        .await
        .unwrap();

        let credential = Credential::new_basic("Fake user".into());
        let signature_keys = SignatureKeyPair::new(
            ciphersuite.signature_algorithm(),
            &mut *backend.rand().borrow_rand().unwrap(),
        )
        .unwrap();
        let bob_key_package_bundle = KeyPackageBundle::new(
            backend,
            &signature_keys,
            ciphersuite,
            CredentialWithKey {
                credential,
                signature_key: test.signature_pub.clone().into(),
            },
        )
        .await;
        let bob_key_package = bob_key_package_bundle.key_package();
        let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);
        let bob_add_proposal = group
            .create_add_proposal(framing_parameters, bob_key_package.clone(), &signer)
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
            .create_commit(params, backend, &signer)
            .await
            .expect("Error creating Commit");

        group
            .merge_commit(backend, create_commit_result.staged_commit)
            .await
            .expect("error merging pending commit");

        // Inject the test values into the group

        let encryption_secret = EncryptionSecret::from_slice(
            &test.encryption_secret,
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
            &test.sender_data_secret,
            ProtocolVersion::Mls10,
            ciphersuite,
        );
        message_secrets.set_membership_key(Secret::from_slice(
            &test.membership_key,
            ProtocolVersion::Mls10,
            ciphersuite,
        ));

        group
    }

    // Proposal
    {
        let proposal = ProposalIn::tls_deserialize_exact(&test.proposal).unwrap();
        let proposal_pub = MlsMessageIn::tls_deserialize_exact(&test.proposal_pub).unwrap();
        let proposal_priv = MlsMessageIn::tls_deserialize_exact(&test.proposal_priv).unwrap();

        async fn test_proposal_pub(
            mut group: CoreGroup,
            backend: &impl OpenMlsCryptoProvider,
            ciphersuite: Ciphersuite,
            proposal: ProposalIn,
            proposal_pub: MlsMessageIn,
        ) {
            // Group stuff we need for openmls
            let sender_ratchet_config = SenderRatchetConfiguration::new(0, 0);

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
            let processed_message: AuthenticatedContent = processed_unverified_message
                .verify(
                    ciphersuite,
                    backend,
                    ProtocolVersion::Mls10,
                    group.public_group(),
                )
                .await
                .unwrap()
                .0;
            match processed_message.content().to_owned() {
                FramedContentBody::Proposal(p) => assert_eq!(proposal, p.into()),
                _ => panic!("Wrong processed message content"),
            }
        }

        test_proposal_pub(
            setup_group(backend, ciphersuite, &test, false).await,
            backend,
            ciphersuite,
            proposal.clone(),
            proposal_pub,
        )
        .await;

        async fn test_proposal_priv(
            mut group: CoreGroup,
            backend: &impl OpenMlsCryptoProvider,
            proposal: ProposalIn,
            proposal_priv: MlsMessageIn,
        ) {
            // Group stuff we need for openmls
            let sender_ratchet_config = SenderRatchetConfiguration::new(0, 0);
            let proposal_store = ProposalStore::default();

            // decrypt private message
            let processed_message = group
                .process_message(
                    backend,
                    proposal_priv.into_protocol_message().unwrap(),
                    &sender_ratchet_config,
                    &proposal_store,
                    &[],
                )
                .await
                .unwrap();

            // check that proposal == processed_message
            match processed_message.content().to_owned() {
                ProcessedMessageContent::ProposalMessage(p) => {
                    assert_eq!(proposal, p.proposal().to_owned().into())
                }
                _ => panic!("Wrong processed message content"),
            }
        }

        let group = setup_group(backend, ciphersuite, &test, false).await;
        test_proposal_priv(group, backend, proposal.clone(), proposal_priv).await;

        // Wrap `proposal` into a `PrivateMessage`.
        let group = setup_group(backend, ciphersuite, &test, false).await;
        let mut sender_group = setup_group(backend, ciphersuite, &test, true).await;
        let proposal_authenticated_content = AuthenticatedContent::member_proposal(
            FramingParameters::new(&[], WireFormat::PrivateMessage),
            sender_index,
            proposal.clone().into(),
            &group_context,
            &signer,
        )
        .unwrap();
        let my_proposal_priv = sender_group
            .encrypt(proposal_authenticated_content, 0, backend)
            .unwrap();
        let my_proposal_priv_out =
            MlsMessageOut::from_private_message(my_proposal_priv, group.version());

        test_proposal_priv(
            group,
            backend,
            proposal.clone(),
            my_proposal_priv_out.into(),
        )
        .await;

        // Wrap `proposal` into a `PublicMessage`.
        let group = setup_group(backend, ciphersuite, &test, false).await;
        let sender_group = setup_group(backend, ciphersuite, &test, true).await;
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
                backend,
                sender_group.message_secrets().membership_key(),
                sender_group.message_secrets().serialized_context(),
            )
            .expect("error setting membership tag");
        let my_proposal_pub_out: MlsMessageOut = my_proposal_pub.into();

        test_proposal_pub(
            group,
            backend,
            ciphersuite,
            proposal,
            my_proposal_pub_out.into(),
        )
        .await;
    }

    // Commit
    {
        let commit = CommitIn::tls_deserialize_exact(&test.commit).unwrap();
        let commit_pub = MlsMessageIn::tls_deserialize_exact(&test.commit_pub).unwrap();
        let commit_priv = MlsMessageIn::tls_deserialize_exact(&test.commit_priv).unwrap();

        async fn test_commit_pub(
            mut group: CoreGroup,
            backend: &impl OpenMlsCryptoProvider,
            ciphersuite: Ciphersuite,
            commit: CommitIn,
            commit_pub: MlsMessageIn,
        ) {
            // Group stuff we need for openmls
            let sender_ratchet_config = SenderRatchetConfiguration::new(10, 10);

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
            let processed_message: AuthenticatedContent = processed_unverified_message
                .verify(
                    ciphersuite,
                    backend,
                    ProtocolVersion::Mls10,
                    group.public_group(),
                )
                .await
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
            setup_group(backend, ciphersuite, &test, false).await,
            backend,
            ciphersuite,
            commit.clone(),
            commit_pub,
        )
        .await;

        async fn test_commit_priv(
            mut group: CoreGroup,
            backend: &impl OpenMlsCryptoProvider,
            ciphersuite: Ciphersuite,
            commit: CommitIn,
            commit_priv: MlsMessageIn,
        ) {
            // Group stuff we need for openmls
            let sender_ratchet_config = SenderRatchetConfiguration::new(10, 10);

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
            let processed_message: AuthenticatedContent = processed_unverified_message
                .verify(
                    ciphersuite,
                    backend,
                    ProtocolVersion::Mls10,
                    group.public_group(),
                )
                .await
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
            setup_group(backend, ciphersuite, &test, false).await,
            backend,
            ciphersuite,
            commit.clone(),
            commit_priv,
        )
        .await;

        // Wrap `commit` into a `PrivateMessage`.
        let group = setup_group(backend, ciphersuite, &test, false).await;
        let mut sender_group = setup_group(backend, ciphersuite, &test, true).await;
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
            .encrypt(commit_authenticated_content, 0, backend)
            .unwrap();
        let my_commit_priv_out =
            MlsMessageOut::from_private_message(my_commit_pub, group.version());

        test_commit_priv(
            group,
            backend,
            ciphersuite,
            commit.clone(),
            my_commit_priv_out.into(),
        )
        .await;

        // Wrap `commit` into a `PublicMessage`.
        let group = setup_group(backend, ciphersuite, &test, false).await;
        let sender_group = setup_group(backend, ciphersuite, &test, true).await;
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
                backend,
                sender_group.message_secrets().membership_key(),
                sender_group.message_secrets().serialized_context(),
            )
            .expect("error setting membership tag");
        let my_commit_pub_out: MlsMessageOut = my_commit_pub_msg.into();

        test_commit_pub(
            group,
            backend,
            ciphersuite,
            commit,
            my_commit_pub_out.into(),
        )
        .await;
    }

    // Application
    {
        let application = &test.application;
        let application_priv = MlsMessageIn::tls_deserialize_exact(&test.application_priv).unwrap();

        async fn test_application_priv(
            mut group: CoreGroup,
            backend: &impl OpenMlsCryptoProvider,
            application: Vec<u8>,
            application_priv: MlsMessageIn,
        ) {
            // Group stuff we need for openmls
            let sender_ratchet_config = SenderRatchetConfiguration::new(0, 0);
            let proposal_store = ProposalStore::default();

            // check that the proposal in proposal_pub == proposal
            let processed_message = group
                .process_message(
                    backend,
                    application_priv.into_ciphertext().unwrap(),
                    &sender_ratchet_config,
                    &proposal_store,
                    &[],
                )
                .await
                .unwrap();
            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(a) => {
                    assert_eq!(application, a.into_bytes())
                }
                _ => panic!("Wrong processed message content"),
            }
        }

        test_application_priv(
            setup_group(backend, ciphersuite, &test, false).await,
            backend,
            application.clone(),
            application_priv,
        )
        .await;

        // Wrap `application` into a `PrivateMessage`.
        let mut sender_group = setup_group(backend, ciphersuite, &test, true).await;
        let private_message = sender_group
            .create_application_message(&[], application, 0, backend, &signer)
            .unwrap();
        let my_application_priv_out =
            MlsMessageOut::from_private_message(private_message, sender_group.version());

        test_application_priv(
            setup_group(backend, ciphersuite, &test, false).await,
            backend,
            application.clone(),
            my_application_priv_out.into(),
        )
        .await;
    }

    log::info!("Finished test verification");

    Ok(())
}

#[apply(backends)]
async fn read_test_vectors_mp(backend: &impl OpenMlsCryptoProvider) {
    Box::pin(async {
        let _ = pretty_env_logger::try_init();
        log::info!("Reading test vectors ...");

        let tests: Vec<MessageProtectionTest> = read("test_vectors/message-protection.json");

        for test_vector in tests.into_iter() {
            run_test_vector(test_vector, backend).await.unwrap();
        }
        log::info!("Finished test vector verification");
    })
    .await
}
