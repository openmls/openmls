use openmls::{prelude::*, test_utils::*, *};

use lazy_static::lazy_static;
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme, OpenMlsCryptoProvider};
use std::fs::File;

lazy_static! {
    static ref TEMP_DIR: tempfile::TempDir =
        tempfile::tempdir().expect("Error creating temp directory");
}

fn generate_credential_bundle(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<Credential, CredentialError> {
    let cb = CredentialBundle::new(identity, credential_type, signature_algorithm, backend)?;
    let credential = cb.credential().clone();
    backend
        .key_store()
        .store(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
            &cb,
        )
        .expect("An unexpected error occurred.");
    Ok(credential)
}

fn generate_key_package_bundle(
    ciphersuites: &[Ciphersuite],
    credential: &Credential,
    extensions: Vec<Extension>,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<KeyPackage, KeyPackageBundleNewError> {
    let credential_bundle = backend
        .key_store()
        .read(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
        )
        .expect("An unexpected error occurred.");
    let kpb = KeyPackageBundle::new(ciphersuites, &credential_bundle, backend, extensions)?;
    let kp = kpb.key_package().clone();
    backend
        .key_store()
        .store(
            kp.hash_ref(backend.crypto())
                .expect("Could not hash KeyPackage.")
                .as_slice(),
            &kpb,
        )
        .expect("An unexpected error occurred.");
    Ok(kp)
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
#[apply(ciphersuites_and_backends)]
fn mls_group_operations(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for wire_format_policy in WIRE_FORMAT_POLICIES.iter() {
        let group_id = GroupId::from_slice(b"Test Group");

        // Generate credential bundles
        let alice_credential = generate_credential_bundle(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("An unexpected error occurred.");

        let bob_credential = generate_credential_bundle(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("An unexpected error occurred.");

        let charlie_credential = generate_credential_bundle(
            "Charlie".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("An unexpected error occurred.");

        // Generate KeyPackages
        let alice_key_package =
            generate_key_package_bundle(&[ciphersuite], &alice_credential, vec![], backend)
                .expect("An unexpected error occurred.");

        let bob_key_package =
            generate_key_package_bundle(&[ciphersuite], &bob_credential, vec![], backend)
                .expect("An unexpected error occurred.");

        // Define the MlsGroup configuration

        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(*wire_format_policy)
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            backend,
            &mls_group_config,
            group_id,
            LifetimeExtension::default(),
            alice_key_package
                .hash_ref(backend.crypto())
                .expect("Could not hash KeyPackage.")
                .as_slice(),
        )
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let (_queued_message, welcome) = match alice_group.add_members(backend, &[bob_key_package])
        {
            Ok((qm, welcome)) => (qm, welcome),
            Err(e) => panic!("Could not add member to group: {:?}", e),
        };

        // Check that we received the correct proposals
        if let Some(staged_commit) = alice_group.pending_commit() {
            let add = staged_commit
                .add_proposals()
                .next()
                .expect("Expected a proposal.");
            // Check that Bob was added
            assert_eq!(
                add.add_proposal().key_package().credential(),
                &bob_credential
            );
            // Check that Alice added Bob
            assert!(
                matches!(add.sender(), Sender::Member(member) if *member == alice_group.own_leaf_index())
            );
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        alice_group
            .merge_pending_commit()
            .expect("error merging pending commit");

        // Check that the group now has two members
        assert_eq!(
            alice_group
                .members()
                .expect("Library error getting group member list")
                .len(),
            2
        );

        // Check that Alice & Bob are the members of the group
        let members = alice_group
            .members()
            .expect("Library error getting group member list");
        assert_eq!(members[0].identity, b"Alice");
        assert_eq!(members[1].identity, b"Bob");

        let mut bob_group = MlsGroup::new_from_welcome(
            backend,
            &mls_group_config,
            welcome,
            Some(alice_group.export_ratchet_tree()),
        )
        .expect("Error creating group from Welcome");

        // Make sure that both groups have the same members
        assert_eq!(
            alice_group
                .members()
                .expect("Library error getting group member list"),
            bob_group
                .members()
                .expect("Library error getting group member list")
        );

        // Make sure that both groups have the same epoch authenticator
        assert_eq!(
            alice_group.epoch_authenticator().as_slice(),
            bob_group.epoch_authenticator().as_slice()
        );

        // === Alice sends a message to Bob ===
        let message_alice = b"Hi, I'm Alice!";
        let queued_message = alice_group
            .create_message(backend, message_alice)
            .expect("Error creating application message");

        let processed_message = bob_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");
        let sender = processed_message
            .credential()
            .expect("Expected a credential.")
            .clone();

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
        let (queued_message, welcome_option) = match bob_group.self_update(backend, None) {
            Ok(qm) => qm,
            Err(e) => panic!("Error performing self-update: {:?}", e),
        };

        let alice_processed_message = alice_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");

        // Check that we received the correct message
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            alice_processed_message.into_content()
        {
            let update_kp = staged_commit
                .commit_update_key_package()
                .expect("Expected a KeyPackage.")
                .clone();
            // Check that Bob updated
            assert_eq!(update_kp.credential(), &bob_credential);

            // Merge staged Commit
            alice_group
                .merge_staged_commit(*staged_commit)
                .expect("Could not merge Commit.");

            // Check Bob's new key package
            let members = alice_group
                .members()
                .expect("Library error getting group member list");
            assert_eq!(
                &members[1].signature_key,
                update_kp.credential().signature_key().as_slice()
            );
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        bob_group
            .merge_pending_commit()
            .expect("error merging pending commit");

        // Check we didn't receive a Welcome message
        assert!(welcome_option.is_none());

        // Check that both groups have the same state
        assert_eq!(
            alice_group.export_secret(backend, "", &[], 32),
            bob_group.export_secret(backend, "", &[], 32)
        );

        // Make sure that both groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            bob_group.export_ratchet_tree()
        );

        // === Alice updates and commits ===
        let queued_message = match alice_group.propose_self_update(backend, None) {
            Ok(qm) => qm,
            Err(e) => panic!("Error performing self-update: {:?}", e),
        };

        let bob_processed_message = bob_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");

        // Check that we received the correct proposals
        if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
            bob_processed_message.into_content()
        {
            if let Proposal::Update(ref update_proposal) = staged_proposal.proposal() {
                // Check that Alice updated
                assert_eq!(update_proposal.leaf_node().credential(), &alice_credential);
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

        let (queued_message, _welcome_option) =
            match alice_group.commit_to_pending_proposals(backend) {
                Ok(qm) => qm,
                Err(e) => panic!("Error performing self-update: {:?}", e),
            };

        let bob_processed_message = bob_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");

        // Check that we received the correct message
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            bob_processed_message.into_content()
        {
            let update_kp = staged_commit
                .commit_update_key_package()
                .expect("Expected a KeyPackage.")
                .clone();
            // Check that Alice updated
            assert_eq!(update_kp.credential(), &alice_credential);

            bob_group
                .merge_staged_commit(*staged_commit)
                .expect("Could not merge StagedCommit");

            // Check Alice's new key package
            let members = bob_group
                .members()
                .expect("Library error getting group member list");
            assert_eq!(
                &members[0].signature_key,
                update_kp.credential().signature_key().as_slice()
            );
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        alice_group
            .merge_pending_commit()
            .expect("error merging pending commit");

        // Check that both groups have the same state
        assert_eq!(
            alice_group.export_secret(backend, "", &[], 32),
            bob_group.export_secret(backend, "", &[], 32)
        );

        // Make sure that both groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            bob_group.export_ratchet_tree()
        );

        // === Bob adds Charlie ===
        let charlie_key_package =
            generate_key_package_bundle(&[ciphersuite], &charlie_credential, vec![], backend)
                .expect("An unexpected error occurred.");

        let (queued_message, welcome) = match bob_group.add_members(backend, &[charlie_key_package])
        {
            Ok((qm, welcome)) => (qm, welcome),
            Err(e) => panic!("Could not add member to group: {:?}", e),
        };

        let alice_processed_message = alice_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");
        bob_group
            .merge_pending_commit()
            .expect("error merging pending commit");

        // Merge Commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            alice_processed_message.into_content()
        {
            alice_group
                .merge_staged_commit(*staged_commit)
                .expect("Could not merge StagedCommit");
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        let mut charlie_group = MlsGroup::new_from_welcome(
            backend,
            &mls_group_config,
            welcome,
            Some(bob_group.export_ratchet_tree()),
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
        let members = alice_group
            .members()
            .expect("Library error getting group member list");
        assert_eq!(members[0].identity, b"Alice");
        assert_eq!(members[1].identity, b"Bob");
        assert_eq!(members[2].identity, b"Charlie");

        // === Charlie sends a message to the group ===
        let message_charlie = b"Hi, I'm Charlie!";
        let queued_message = charlie_group
            .create_message(backend, message_charlie)
            .expect("Error creating application message");

        let _alice_processed_message = alice_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");
        let _bob_processed_message = bob_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");

        // === Charlie updates and commits ===
        let (queued_message, welcome_option) = match charlie_group.self_update(backend, None) {
            Ok(qm) => qm,
            Err(e) => panic!("Error performing self-update: {:?}", e),
        };

        let alice_processed_message = alice_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");
        let bob_processed_message = bob_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");
        charlie_group
            .merge_pending_commit()
            .expect("error merging pending commit");

        // Merge Commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            alice_processed_message.into_content()
        {
            alice_group
                .merge_staged_commit(*staged_commit)
                .expect("Could not merge StagedCommit");
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Merge Commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            bob_processed_message.into_content()
        {
            bob_group
                .merge_staged_commit(*staged_commit)
                .expect("Could not merge StagedCommit");
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Check we didn't receive a Welcome message
        assert!(welcome_option.is_none());

        // Check that all groups have the same state
        assert_eq!(
            alice_group.export_secret(backend, "", &[], 32),
            bob_group.export_secret(backend, "", &[], 32)
        );
        assert_eq!(
            alice_group.export_secret(backend, "", &[], 32),
            charlie_group.export_secret(backend, "", &[], 32)
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
        let (queued_message, welcome_option) = charlie_group
            .remove_members(backend, &[bob_group.own_leaf_index()])
            .expect("Could not remove member from group.");

        // Check that Bob's group is still active
        assert!(bob_group.is_active());

        let alice_processed_message = alice_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");
        let bob_processed_message = bob_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");
        charlie_group
            .merge_pending_commit()
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
                .merge_staged_commit(*staged_commit)
                .expect("Could not merge Commit.");
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
                .merge_staged_commit(*staged_commit)
                .expect("Could not merge Commit.");
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
        assert_eq!(
            alice_group
                .members()
                .expect("Library error getting group member list")
                .len(),
            2
        );

        // Check that Alice & Charlie are the members of the group
        let members = alice_group
            .members()
            .expect("Library error getting group member list");
        assert_eq!(members[0].identity, b"Alice");
        assert_eq!(members[1].identity, b"Charlie");

        // Check that Bob can no longer send messages
        assert!(bob_group
            .create_message(backend, b"Should not go through")
            .is_err());

        // === Alice removes Charlie and re-adds Bob ===

        // Create a new KeyPackageBundle for Bob
        let bob_key_package =
            generate_key_package_bundle(&[ciphersuite], &bob_credential, vec![], backend)
                .expect("An unexpected error occurred.");

        // Create RemoveProposal and process it
        let queued_message = alice_group
            .propose_remove_member(backend, charlie_group.own_leaf_index())
            .expect("Could not create proposal to remove Charlie");

        let charlie_processed_message = charlie_group
            .process_message(backend, queued_message.clone().into())
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
        let queued_message = alice_group
            .propose_add_member(backend, &bob_key_package)
            .expect("Could not create proposal to add Bob");

        let charlie_processed_message = charlie_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");

        // Check that we received the correct proposals
        if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
            charlie_processed_message.into_content()
        {
            if let Proposal::Add(add_proposal) = staged_proposal.proposal() {
                // Check that Bob was added
                assert_eq!(add_proposal.key_package().credential(), &bob_credential);
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
        let (queued_message, welcome_option) = alice_group
            .commit_to_pending_proposals(backend)
            .expect("Could not flush proposals");

        let charlie_processed_message = charlie_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");

        // Merge Commit
        alice_group
            .merge_pending_commit()
            .expect("error merging pending commit");

        // Merge Commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            charlie_processed_message.into_content()
        {
            charlie_group
                .merge_staged_commit(*staged_commit)
                .expect("Could not merge StagedCommit");
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Make sure the group contains two members
        assert_eq!(
            alice_group
                .members()
                .expect("Library error getting group member list")
                .len(),
            2
        );

        // Check that Alice & Bob are the members of the group
        let members = alice_group
            .members()
            .expect("Library error getting group member list");
        assert_eq!(members[0].identity, b"Alice");
        assert_eq!(members[1].identity, b"Bob");

        // Bob creates a new group
        let mut bob_group = MlsGroup::new_from_welcome(
            backend,
            &mls_group_config,
            welcome_option.expect("Welcome was not returned"),
            Some(alice_group.export_ratchet_tree()),
        )
        .expect("Error creating group from Welcome");

        // Make sure the group contains two members
        assert_eq!(
            alice_group
                .members()
                .expect("Library error getting group member list")
                .len(),
            2
        );

        // Check that Alice & Bob are the members of the group
        let members = alice_group
            .members()
            .expect("Library error getting group member list");
        assert_eq!(members[0].identity, b"Alice");
        assert_eq!(members[1].identity, b"Bob");

        // Make sure the group contains two members
        assert_eq!(
            bob_group
                .members()
                .expect("Library error getting group member list")
                .len(),
            2
        );

        // Check that Alice & Bob are the members of the group
        let members = bob_group
            .members()
            .expect("Library error getting group member list");
        assert_eq!(members[0].identity, b"Alice");
        assert_eq!(members[1].identity, b"Bob");

        // === Alice sends a message to the group ===
        let message_alice = b"Hi, I'm Alice!";
        let queued_message = alice_group
            .create_message(backend, message_alice)
            .expect("Error creating application message");

        let bob_processed_message = bob_group
            .process_message(backend, queued_message.clone().into())
            .expect("Could not process message.");
        let sender = bob_processed_message
            .credential()
            .expect("Expected a credential.")
            .clone();

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
            .leave_group(backend)
            .expect("Could not leave group");

        let alice_processed_message = alice_group
            .process_message(backend, queued_message.clone().into())
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
            bob_group.commit_to_pending_proposals(backend,),
            Err(CommitToPendingProposalsError::CreateCommitError(
                CreateCommitError::CannotRemoveSelf
            ))
        );

        let (queued_message, _welcome_option) = alice_group
            .commit_to_pending_proposals(backend)
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
            .merge_pending_commit()
            .expect("Could not merge Commit.");

        let bob_processed_message = bob_group
            .process_message(backend, queued_message.clone().into())
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
                .merge_staged_commit(*staged_commit)
                .expect("Could not merge Commit.");
        } else {
            unreachable!("Expected a StagedCommit.");
        }

        // Check that Bob's group is no longer active
        assert!(!bob_group.is_active());

        // Make sure the group contains one member
        assert_eq!(
            alice_group
                .members()
                .expect("Library error getting group member list")
                .len(),
            1
        );

        // Check that Alice is the only member of the group
        let members = alice_group
            .members()
            .expect("Library error getting group member list");
        assert_eq!(members[0].identity, b"Alice");

        // === Save the group state ===

        // Create a new KeyPackageBundle for Bob
        let bob_key_package =
            generate_key_package_bundle(&[ciphersuite], &bob_credential, vec![], backend)
                .expect("An unexpected error occurred.");

        // Add Bob to the group
        let (_queued_message, welcome) = alice_group
            .add_members(backend, &[bob_key_package])
            .expect("Could not add Bob");

        // Merge Commit
        alice_group
            .merge_pending_commit()
            .expect("error merging pending commit");

        let mut bob_group = MlsGroup::new_from_welcome(
            backend,
            &mls_group_config,
            welcome,
            Some(alice_group.export_ratchet_tree()),
        )
        .expect("Could not create group from Welcome");

        assert_eq!(
            alice_group.export_secret(backend, "before load", &[], 32),
            bob_group.export_secret(backend, "before load", &[], 32)
        );

        // Check that the state flag gets reset when saving
        assert_eq!(bob_group.state_changed(), InnerState::Changed);
        //save(&mut bob_group);

        let name = bytes_to_hex(
            bob_group
                .credential()
                .expect("An unexpected error occurred.")
                .signature_key()
                .as_slice(),
        )
        .to_lowercase();
        let path = TEMP_DIR
            .path()
            .join(format!("test_mls_group_{}.json", &name));
        let out_file = &mut File::create(path.clone()).expect("Could not create file");
        bob_group
            .save(out_file)
            .expect("Could not write group state to file");

        // Check that the state flag gets reset when saving
        assert_eq!(bob_group.state_changed(), InnerState::Persisted);

        let file = File::open(path).expect("Could not open file");
        let bob_group = MlsGroup::load(file).expect("Could not load group from file");

        // Make sure the state is still the same
        assert_eq!(
            alice_group.export_secret(backend, "after load", &[], 32),
            bob_group.export_secret(backend, "after load", &[], 32)
        );
    }
}

#[apply(ciphersuites_and_backends)]
fn test_empty_input_errors(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package_bundle(&[ciphersuite], &alice_credential, vec![], backend)
            .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &mls_group_config,
        group_id,
        LifetimeExtension::default(),
        alice_key_package
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice(),
    )
    .expect("An unexpected error occurred.");

    assert_eq!(
        alice_group
            .add_members(backend, &[])
            .expect_err("No EmptyInputError when trying to pass an empty slice to `add_members`."),
        AddMembersError::EmptyInput(EmptyInputError::AddMembers)
    );
    assert_eq!(
        alice_group.remove_members(backend, &[]).expect_err(
            "No EmptyInputError when trying to pass an empty slice to `remove_members`."
        ),
        RemoveMembersError::EmptyInput(EmptyInputError::RemoveMembers)
    );
}

// This tests the ratchet tree extension usage flag in the configuration
#[apply(ciphersuites_and_backends)]
fn mls_group_ratchet_tree_extension(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    for wire_format_policy in WIRE_FORMAT_POLICIES.iter() {
        let group_id = GroupId::from_slice(b"Test Group");

        // === Positive case: using the ratchet tree extension ===

        // Generate credential bundles
        let alice_credential = generate_credential_bundle(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("An unexpected error occurred.");

        let bob_credential = generate_credential_bundle(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("An unexpected error occurred.");

        // Generate KeyPackages
        let alice_key_package =
            generate_key_package_bundle(&[ciphersuite], &alice_credential, vec![], backend)
                .expect("An unexpected error occurred.");

        let bob_key_package =
            generate_key_package_bundle(&[ciphersuite], &bob_credential, vec![], backend)
                .expect("An unexpected error occurred.");

        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(*wire_format_policy)
            .use_ratchet_tree_extension(true)
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            backend,
            &mls_group_config,
            group_id.clone(),
            LifetimeExtension::default(),
            alice_key_package
                .hash_ref(backend.crypto())
                .expect("Could not hash KeyPackage.")
                .as_slice(),
        )
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let (_queued_message, welcome) =
            match alice_group.add_members(backend, &[bob_key_package.clone()]) {
                Ok((qm, welcome)) => (qm, welcome),
                Err(e) => panic!("Could not add member to group: {:?}", e),
            };

        // === Bob joins using the ratchet tree extension ===
        let _bob_group = MlsGroup::new_from_welcome(backend, &mls_group_config, welcome, None)
            .expect("Error creating group from Welcome");

        // === Negative case: not using the ratchet tree extension ===

        // Generate credential bundles
        let alice_credential = generate_credential_bundle(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("An unexpected error occurred.");

        let bob_credential = generate_credential_bundle(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("An unexpected error occurred.");

        // Generate KeyPackages
        let alice_key_package =
            generate_key_package_bundle(&[ciphersuite], &alice_credential, vec![], backend)
                .expect("An unexpected error occurred.");

        let bob_key_package =
            generate_key_package_bundle(&[ciphersuite], &bob_credential, vec![], backend)
                .expect("An unexpected error occurred.");

        let mls_group_config = MlsGroupConfig::test_default();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            backend,
            &mls_group_config,
            group_id,
            LifetimeExtension::default(),
            alice_key_package
                .hash_ref(backend.crypto())
                .expect("Could not hash KeyPackage.")
                .as_slice(),
        )
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let (_queued_message, welcome) = match alice_group.add_members(backend, &[bob_key_package])
        {
            Ok((qm, welcome)) => (qm, welcome),
            Err(e) => panic!("Could not add member to group: {:?}", e),
        };

        // === Bob tries to join without the ratchet tree extension ===
        let error = MlsGroup::new_from_welcome(backend, &mls_group_config, welcome, None)
            .expect_err("Could join a group without a ratchet tree");

        assert_eq!(error, WelcomeError::MissingRatchetTree);
    }
}
