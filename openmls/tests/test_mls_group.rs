use openmls::{
    prelude::{config::CryptoConfig, test_utils::new_credential, *},
    test_utils::*,
    *,
};

use openmls_traits::{key_store::OpenMlsKeyStore, signatures::Signer, OpenMlsProvider};

fn generate_key_package<KeyStore: OpenMlsKeyStore>(
    ciphersuite: Ciphersuite,
    extensions: Extensions,
    provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
    credential_with_key: CredentialWithKey,
    signer: &impl Signer,
) -> KeyPackage {
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            provider,
            signer,
            credential_with_key,
        )
        .unwrap()
}

/// This test simulates various group operations like Add, Update, Remove in a
/// small group
///  - Alice creates a group
///  - Alice adds Bob
///  - Alice sends a message to Bob
///  - Bob updates and commits
///  - Alice updates and commits
///  - Bob adds Charlie
///  - Charlie sends a message to the group
///  - Charlie updates and commits
///  - Charlie removes Bob
///  - Alice removes Charlie and adds Bob
///  - Bob leaves
///  - Test saving the group state
#[apply(ciphersuites_and_providers)]
fn mls_group_operations(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    for wire_format_policy in WIRE_FORMAT_POLICIES.iter() {
        let group_id = GroupId::from_slice(b"Test Group");

        // Generate credentials with keys
        let (alice_credential, alice_signer) = new_credential(
            provider,
            b"Alice",
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
        );

        let (bob_credential, bob_signer) = new_credential(
            provider,
            b"Bob",
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
        );

        let (charlie_credential, charlie_signer) = new_credential(
            provider,
            b"Charlie",
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
        );

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            bob_credential.clone(),
            &bob_signer,
        );

        // Define the MlsGroup configuration

        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(*wire_format_policy)
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            provider,
            &alice_signer,
            &mls_group_config,
            group_id.clone(),
            alice_credential.clone(),
        )
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let welcome = match alice_group.add_members(provider, &alice_signer, &[bob_key_package]) {
            Ok((_, welcome, _)) => welcome,
            Err(e) => panic!("Could not add member to group: {e:?}"),
        };

        // Check that we received the correct proposals
        if let Some(staged_commit) = alice_group.pending_commit() {
            let add = staged_commit
                .add_proposals()
                .next()
                .expect("Expected a proposal.");
            // Check that Bob was added
            assert_eq!(
                add.add_proposal().key_package().leaf_node().credential(),
                &bob_credential.credential
            );
            // Check that Alice added Bob
            assert!(
                matches!(add.sender(), Sender::Member(member) if *member == alice_group.own_leaf_index())
            );
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        alice_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        // Check that the group now has two members
        assert_eq!(alice_group.members().count(), 2);

        // Check that Alice & Bob are the members of the group
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");
        assert_eq!(members[1].credential.identity(), b"Bob");

        let mut bob_group = MlsGroup::new_from_welcome(
            provider,
            &mls_group_config,
            welcome.into_welcome().expect("Unexpected message type."),
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("Error creating group from Welcome");

        // Make sure that both groups have the same members
        assert!(alice_group.members().eq(bob_group.members()));

        // Make sure that both groups have the same epoch authenticator
        assert_eq!(
            alice_group.epoch_authenticator().as_slice(),
            bob_group.epoch_authenticator().as_slice()
        );

        // === Alice sends a message to Bob ===
        let message_alice = b"Hi, I'm Alice!";
        let queued_message = alice_group
            .create_message(provider, &alice_signer, message_alice)
            .expect("Error creating application message");

        let processed_message = bob_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");
        let sender = processed_message.credential().clone();

        // Check that we received the correct message
        if let ProcessedMessageContent::ApplicationMessage(application_message) =
            processed_message.into_content()
        {
            // Check the message
            assert_eq!(application_message.into_bytes(), message_alice);
            // Check that Alice sent the message
            assert_eq!(
                &sender,
                alice_group
                    .credential()
                    .expect("An unexpected error occurred.")
            );
        } else {
            unreachable!("Expected an ApplicationMessage.");
        }

        // === Bob updates and commits ===
        let (queued_message, welcome_option, _group_info) =
            bob_group.self_update(provider, &bob_signer).unwrap();

        let alice_processed_message = alice_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");

        // Check that we received the correct message
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            alice_processed_message.into_content()
        {
            // Merge staged Commit
            alice_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        bob_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        // Check we didn't receive a Welcome message
        assert!(welcome_option.is_none());

        // Check that both groups have the same state
        assert_eq!(
            alice_group.export_secret(provider.crypto(), "", &[], 32),
            bob_group.export_secret(provider.crypto(), "", &[], 32)
        );

        // Make sure that both groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            bob_group.export_ratchet_tree()
        );

        // === Alice updates and commits ===
        let (queued_message, _) = alice_group
            .propose_self_update(provider, &alice_signer, None)
            .unwrap();

        let bob_processed_message = bob_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");

        // Check that we received the correct proposals
        if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
            bob_processed_message.into_content()
        {
            if let Proposal::Update(ref update_proposal) = staged_proposal.proposal() {
                // Check that Alice updated
                assert_eq!(
                    update_proposal.leaf_node().credential(),
                    &alice_credential.credential
                );
                // Store proposal
                alice_group.store_pending_proposal(*staged_proposal.clone());
            } else {
                unreachable!("Expected a Proposal.");
            }

            // Check that Alice sent the proposal.
            assert!(matches!(
                staged_proposal.sender(),
                Sender::Member(member) if *member == alice_group.own_leaf_index()
            ));

            bob_group.store_pending_proposal(*staged_proposal);
        } else {
            unreachable!("Expected a QueuedProposal.");
        }

        let (queued_message, _welcome_option, _group_info) = alice_group
            .commit_to_pending_proposals(provider, &alice_signer)
            .unwrap();

        let bob_processed_message = bob_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");

        // Check that we received the correct message
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            bob_processed_message.into_content()
        {
            bob_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        alice_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        // Check that both groups have the same state
        assert_eq!(
            alice_group.export_secret(provider.crypto(), "", &[], 32),
            bob_group.export_secret(provider.crypto(), "", &[], 32)
        );

        // Make sure that both groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            bob_group.export_ratchet_tree()
        );

        // === Bob adds Charlie ===
        let charlie_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            charlie_credential,
            &charlie_signer,
        );

        let (queued_message, welcome, _group_info) = bob_group
            .add_members(provider, &bob_signer, &[charlie_key_package])
            .unwrap();

        let alice_processed_message = alice_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");
        bob_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        // Merge Commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            alice_processed_message.into_content()
        {
            alice_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        let mut charlie_group = MlsGroup::new_from_welcome(
            provider,
            &mls_group_config,
            welcome.into_welcome().expect("Unexpected message type."),
            Some(bob_group.export_ratchet_tree().into()),
        )
        .expect("Error creating group from Welcome");

        // Make sure that all groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            bob_group.export_ratchet_tree(),
        );
        assert_eq!(
            alice_group.export_ratchet_tree(),
            charlie_group.export_ratchet_tree()
        );

        // Check that Alice, Bob & Charlie are the members of the group
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");
        assert_eq!(members[1].credential.identity(), b"Bob");
        assert_eq!(members[2].credential.identity(), b"Charlie");

        // === Charlie sends a message to the group ===
        let message_charlie = b"Hi, I'm Charlie!";
        let queued_message = charlie_group
            .create_message(provider, &charlie_signer, message_charlie)
            .expect("Error creating application message");

        let _alice_processed_message = alice_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");
        let _bob_processed_message = bob_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");

        // === Charlie updates and commits ===
        let (queued_message, welcome_option, _group_info) = charlie_group
            .self_update(provider, &charlie_signer)
            .unwrap();

        let alice_processed_message = alice_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");
        let bob_processed_message = bob_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");
        charlie_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        // Merge Commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            alice_processed_message.into_content()
        {
            alice_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Merge Commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            bob_processed_message.into_content()
        {
            bob_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Check we didn't receive a Welcome message
        assert!(welcome_option.is_none());

        // Check that all groups have the same state
        assert_eq!(
            alice_group.export_secret(provider.crypto(), "", &[], 32),
            bob_group.export_secret(provider.crypto(), "", &[], 32)
        );
        assert_eq!(
            alice_group.export_secret(provider.crypto(), "", &[], 32),
            charlie_group.export_secret(provider.crypto(), "", &[], 32)
        );

        // Make sure that all groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            bob_group.export_ratchet_tree(),
        );
        assert_eq!(
            alice_group.export_ratchet_tree(),
            charlie_group.export_ratchet_tree()
        );

        // === Charlie removes Bob ===
        println!(" >>> Charlie is removing bob");
        let (queued_message, welcome_option, _group_info) = charlie_group
            .remove_members(provider, &charlie_signer, &[bob_group.own_leaf_index()])
            .expect("Could not remove member from group.");

        // Check that Bob's group is still active
        assert!(bob_group.is_active());

        let alice_processed_message = alice_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");
        let bob_processed_message = bob_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");
        charlie_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        // Check that we receive the correct proposal for Alice
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            alice_processed_message.into_content()
        {
            let remove = staged_commit
                .remove_proposals()
                .next()
                .expect("Expected a proposal.");
            // Check that Bob was removed
            assert_eq!(remove.remove_proposal().removed(), members[1].index);
            // Check that Charlie removed Bob
            assert!(
                matches!(remove.sender(), Sender::Member(member) if *member == members[2].index)
            );

            // Merge staged Commit
            alice_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Check that we receive the correct proposal for Alice
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            bob_processed_message.into_content()
        {
            let remove = staged_commit
                .remove_proposals()
                .next()
                .expect("Expected a proposal.");
            // Check that Bob was removed
            assert_eq!(remove.remove_proposal().removed(), members[1].index);
            // Check that Charlie removed Bob
            assert!(
                matches!(remove.sender(), Sender::Member(member) if *member == members[2].index)
            );

            // Merge staged Commit
            bob_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Check we didn't receive a Welcome message
        assert!(welcome_option.is_none());

        // Check that Bob's group is no longer active
        assert!(!bob_group.is_active());

        // Make sure that all groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            charlie_group.export_ratchet_tree()
        );

        // Make sure the group only contains two members
        assert_eq!(alice_group.members().count(), 2);

        // Check that Alice & Charlie are the members of the group
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");
        assert_eq!(members[1].credential.identity(), b"Charlie");

        // Check that Bob can no longer send messages
        assert!(bob_group
            .create_message(provider, &bob_signer, b"Should not go through")
            .is_err());

        // === Alice removes Charlie and re-adds Bob ===

        // Create a new KeyPackageBundle for Bob
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            bob_credential.clone(),
            &bob_signer,
        );

        // Create RemoveProposal and process it
        let (queued_message, _) = alice_group
            .propose_remove_member(provider, &alice_signer, charlie_group.own_leaf_index())
            .expect("Could not create proposal to remove Charlie");

        let charlie_processed_message = charlie_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");

        // Check that we received the correct proposals
        if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
            charlie_processed_message.into_content()
        {
            if let Proposal::Remove(ref remove_proposal) = staged_proposal.proposal() {
                // Check that Charlie was removed
                assert_eq!(remove_proposal.removed(), members[1].index);
                // Store proposal
                charlie_group.store_pending_proposal(*staged_proposal.clone());
            } else {
                unreachable!("Expected a Proposal.");
            }

            // Check that Alice removed Charlie
            assert!(matches!(
                staged_proposal.sender(),
                Sender::Member(member) if *member == members[0].index
            ));
        } else {
            unreachable!("Expected a QueuedProposal.");
        }

        // Create AddProposal and process it
        let (queued_message, _) = alice_group
            .propose_add_member(provider, &alice_signer, &bob_key_package)
            .expect("Could not create proposal to add Bob");

        let charlie_processed_message = charlie_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");

        // Check that we received the correct proposals
        if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
            charlie_processed_message.into_content()
        {
            if let Proposal::Add(add_proposal) = staged_proposal.proposal() {
                // Check that Bob was added
                assert_eq!(
                    add_proposal.key_package().leaf_node().credential(),
                    &bob_credential.credential
                );
            } else {
                unreachable!("Expected an AddProposal.");
            }

            // Check that Alice added Bob
            assert!(matches!(
                staged_proposal.sender(),
                Sender::Member(member) if *member == members[0].index
            ));
            // Store proposal
            charlie_group.store_pending_proposal(*staged_proposal);
        } else {
            unreachable!("Expected a QueuedProposal.");
        }

        // Commit to the proposals and process it
        let (queued_message, welcome_option, _group_info) = alice_group
            .commit_to_pending_proposals(provider, &alice_signer)
            .expect("Could not flush proposals");

        let charlie_processed_message = charlie_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");

        // Merge Commit
        alice_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        // Merge Commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            charlie_processed_message.into_content()
        {
            charlie_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Make sure the group contains two members
        assert_eq!(alice_group.members().count(), 2);

        // Check that Alice & Bob are the members of the group
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");
        assert_eq!(members[1].credential.identity(), b"Bob");

        // Bob creates a new group
        let mut bob_group = MlsGroup::new_from_welcome(
            provider,
            &mls_group_config,
            welcome_option
                .expect("Welcome was not returned")
                .into_welcome()
                .expect("Unexpected message type."),
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("Error creating group from Welcome");

        // Make sure the group contains two members
        assert_eq!(alice_group.members().count(), 2);

        // Check that Alice & Bob are the members of the group
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");
        assert_eq!(members[1].credential.identity(), b"Bob");

        // Make sure the group contains two members
        assert_eq!(bob_group.members().count(), 2);

        // Check that Alice & Bob are the members of the group
        let members = bob_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");
        assert_eq!(members[1].credential.identity(), b"Bob");

        // === Alice sends a message to the group ===
        let message_alice = b"Hi, I'm Alice!";
        let queued_message = alice_group
            .create_message(provider, &alice_signer, message_alice)
            .expect("Error creating application message");

        let bob_processed_message = bob_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");
        let sender = bob_processed_message.credential().clone();

        // Check that we received the correct message
        if let ProcessedMessageContent::ApplicationMessage(application_message) =
            bob_processed_message.into_content()
        {
            // Check the message
            assert_eq!(application_message.into_bytes(), message_alice);
            // Check that Alice sent the message
            assert_eq!(
                &sender,
                alice_group.credential().expect("Expected a credential")
            );
        } else {
            unreachable!("Expected an ApplicationMessage.");
        }

        // === Bob leaves the group ===

        let queued_message = bob_group
            .leave_group(provider, &bob_signer)
            .expect("Could not leave group");

        let alice_processed_message = alice_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");

        // Store proposal
        if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
            alice_processed_message.into_content()
        {
            // Store proposal
            alice_group.store_pending_proposal(*staged_proposal);
        } else {
            unreachable!("Expected a QueuedProposal.");
        }

        // Should fail because you cannot remove yourself from a group
        assert_eq!(
            bob_group.commit_to_pending_proposals(provider, &bob_signer),
            Err(CommitToPendingProposalsError::CreateCommitError(
                CreateCommitError::CannotRemoveSelf
            ))
        );

        let (queued_message, _welcome_option, _group_info) = alice_group
            .commit_to_pending_proposals(provider, &alice_signer)
            .expect("Could not commit to proposals.");

        // Check that Bob's group is still active
        assert!(bob_group.is_active());

        // Check that we received the correct proposals
        let bob_leaf_index = bob_group.own_leaf_index();
        if let Some(staged_commit) = alice_group.pending_commit() {
            let remove = staged_commit
                .remove_proposals()
                .next()
                .expect("Expected a proposal.");
            // Check that Bob was removed
            assert_eq!(remove.remove_proposal().removed(), bob_leaf_index);
            // Check that Bob removed himself
            assert!(matches!(remove.sender(), Sender::Member(member) if *member == bob_leaf_index));

            // Merge staged Commit
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        alice_group
            .merge_pending_commit(provider)
            .expect("Could not merge Commit.");

        let bob_processed_message = bob_group
            .process_message(
                provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");

        // Check that we received the correct proposals
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            bob_processed_message.into_content()
        {
            let remove = staged_commit
                .remove_proposals()
                .next()
                .expect("Expected a proposal.");
            // Check that Bob was removed
            assert_eq!(remove.remove_proposal().removed(), bob_leaf_index);
            // Check that Bob removed himself
            assert!(matches!(remove.sender(), Sender::Member(member) if *member == bob_leaf_index));

            assert!(staged_commit.self_removed());
            // Merge staged Commit
            bob_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Check that Bob's group is no longer active
        assert!(!bob_group.is_active());

        // Make sure the group contains one member
        assert_eq!(alice_group.members().count(), 1);

        // Check that Alice is the only member of the group
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[0].credential.identity(), b"Alice");

        // === Save the group state ===

        // Create a new KeyPackageBundle for Bob
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            bob_credential,
            &bob_signer,
        );

        // Add Bob to the group
        let (_queued_message, welcome, _group_info) = alice_group
            .add_members(provider, &alice_signer, &[bob_key_package])
            .expect("Could not add Bob");

        // Test saving & loading the group state when there is a pending commit
        alice_group
            .save(provider.key_store())
            .expect("Could not save group state.");

        let _test_group = MlsGroup::load(&group_id, provider.key_store())
            .expect("Could not load the group state.");

        // Merge Commit
        alice_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        let mut bob_group = MlsGroup::new_from_welcome(
            provider,
            &mls_group_config,
            welcome.into_welcome().expect("Unexpected message type."),
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("Could not create group from Welcome");

        assert_eq!(
            alice_group.export_secret(provider.crypto(), "before load", &[], 32),
            bob_group.export_secret(provider.crypto(), "before load", &[], 32)
        );

        // Check that the state flag gets reset when saving
        assert_eq!(bob_group.state_changed(), InnerState::Changed);

        bob_group
            .save(provider.key_store())
            .expect("Could not write group state to file");

        // Check that the state flag gets reset when saving
        assert_eq!(bob_group.state_changed(), InnerState::Persisted);

        let bob_group = MlsGroup::load(&group_id, provider.key_store())
            .expect("Could not load group from file");

        // Make sure the state is still the same
        assert_eq!(
            alice_group.export_secret(provider.crypto(), "after load", &[], 32),
            bob_group.export_secret(provider.crypto(), "after load", &[], 32)
        );
    }
}

#[apply(ciphersuites_and_providers)]
fn addition_order(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    for wire_format_policy in WIRE_FORMAT_POLICIES.iter() {
        let group_id = GroupId::from_slice(b"Test Group");
        // Generate credentials with keys
        let (alice_credential, alice_signer) = new_credential(
            provider,
            b"Alice",
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
        );

        let (bob_credential, bob_signer) = new_credential(
            provider,
            b"Bob",
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
        );

        let (charlie_credential, charlie_signer) = new_credential(
            provider,
            b"Charlie",
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
        );

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            bob_credential.clone(),
            &bob_signer,
        );
        let charlie_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            charlie_credential.clone(),
            &charlie_signer,
        );

        // Define the MlsGroup configuration

        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(*wire_format_policy)
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            provider,
            &alice_signer,
            &mls_group_config,
            group_id.clone(),
            alice_credential.clone(),
        )
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let _welcome = match alice_group.add_members(
            provider,
            &alice_signer,
            &[bob_key_package, charlie_key_package],
        ) {
            Ok((_, welcome, _)) => welcome,
            Err(e) => panic!("Could not add member to group: {e:?}"),
        };

        // Check that the proposals are in the right order in the staged commit.
        if let Some(staged_commit) = alice_group.pending_commit() {
            let mut add_proposals = staged_commit.add_proposals();
            let add_bob = add_proposals.next().expect("Expected a proposal.");
            // Check that Bob is first
            assert_eq!(
                add_bob
                    .add_proposal()
                    .key_package()
                    .leaf_node()
                    .credential(),
                &bob_credential.credential
            );
            let add_charlie = add_proposals.next().expect("Expected a proposal.");
            // Check that Charlie is second
            assert_eq!(
                add_charlie
                    .add_proposal()
                    .key_package()
                    .leaf_node()
                    .credential(),
                &charlie_credential.credential
            );
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        alice_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        // Check that the members got added in the same order as the KeyPackages
        // in the original API call. After merging, bob should be at index 1 and
        // charlie at index 2.
        let members = alice_group.members().collect::<Vec<Member>>();
        assert_eq!(members[1].credential.identity(), b"Bob");
        assert_eq!(members[1].index, LeafNodeIndex::new(1));
        assert_eq!(members[2].credential.identity(), b"Charlie");
        assert_eq!(members[2].index, LeafNodeIndex::new(2));
    }
}

#[apply(ciphersuites_and_providers)]
fn test_empty_input_errors(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credentials with keys
    let (alice_credential, alice_signer) = new_credential(
        provider,
        b"Alice",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_config,
        group_id,
        alice_credential,
    )
    .expect("An unexpected error occurred.");

    assert_eq!(
        alice_group
            .add_members(provider, &alice_signer, &[])
            .expect_err("No EmptyInputError when trying to pass an empty slice to `add_members`."),
        AddMembersError::EmptyInput(EmptyInputError::AddMembers)
    );
    assert_eq!(
        alice_group
            .remove_members(provider, &alice_signer, &[])
            .expect_err(
                "No EmptyInputError when trying to pass an empty slice to `remove_members`."
            ),
        RemoveMembersError::EmptyInput(EmptyInputError::RemoveMembers)
    );
}

// This tests the ratchet tree extension usage flag in the configuration
#[apply(ciphersuites_and_providers)]
fn mls_group_ratchet_tree_extension(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    for wire_format_policy in WIRE_FORMAT_POLICIES.iter() {
        let group_id = GroupId::from_slice(b"Test Group");

        // === Positive case: using the ratchet tree extension ===

        // Generate credentials
        let (alice_credential, alice_signer) = new_credential(
            provider,
            b"Alice",
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
        );

        let (bob_credential, bob_signer) = new_credential(
            provider,
            b"Bob",
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
        );

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            bob_credential,
            &bob_signer,
        );

        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(*wire_format_policy)
            .use_ratchet_tree_extension(true)
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            provider,
            &alice_signer,
            &mls_group_config,
            group_id.clone(),
            alice_credential.clone(),
        )
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let (_queued_message, welcome, _group_info) = alice_group
            .add_members(provider, &alice_signer, &[bob_key_package.clone()])
            .unwrap();

        // === Bob joins using the ratchet tree extension ===
        let _bob_group = MlsGroup::new_from_welcome(
            provider,
            &mls_group_config,
            welcome.into_welcome().expect("Unexpected message type."),
            None,
        )
        .expect("Error creating group from Welcome");

        // === Negative case: not using the ratchet tree extension ===

        // Generate credentials with keys
        let (alice_credential, alice_signer) = new_credential(
            provider,
            b"Alice",
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
        );

        let (bob_credential, bob_signer) = new_credential(
            provider,
            b"Bob",
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
        );

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            bob_credential,
            &bob_signer,
        );

        let mls_group_config = MlsGroupConfig::test_default(ciphersuite);

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            provider,
            &alice_signer,
            &mls_group_config,
            group_id,
            alice_credential.clone(),
        )
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let (_queued_message, welcome, _group_info) = alice_group
            .add_members(provider, &alice_signer, &[bob_key_package])
            .unwrap();

        // === Bob tries to join without the ratchet tree extension ===
        let error = MlsGroup::new_from_welcome(
            provider,
            &mls_group_config,
            welcome.into_welcome().expect("Unexpected message type."),
            None,
        )
        .expect_err("Could join a group without a ratchet tree");

        assert_eq!(error, WelcomeError::MissingRatchetTree);
    }
}
