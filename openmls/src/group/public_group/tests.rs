use openmls_traits::prelude::*;

use crate::{
    binary_tree::LeafNodeIndex,
    framing::{
        public_message_in::PublicMessageIn, MlsMessageIn, MlsMessageOut, ProcessedMessage,
        ProcessedMessageContent, ProtocolMessage, Sender,
    },
    group::{
        mls_group::tests_and_kats::utils::setup_client, proposal_store::ProposalStore, GroupId,
        MlsGroup, MlsGroupCreateConfig, StagedCommit, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    messages::proposals::Proposal,
};

use super::{super::mls_group::StagedWelcome, PublicGroup};

#[openmls_test::openmls_test]
fn public_group<Provider: OpenMlsProvider>(ciphersuite: Ciphersuite, provider: &Provider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential, bob_kpb, bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);
    let (_charlie_credential, charlie_kpb, charlie_signer, _charlie_pk) =
        setup_client("Charly", ciphersuite, provider);

    // Define the MlsGroup configuration
    // Set plaintext wire format policy s.t. the public group can track changes.
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    // === Create a public group that tracks the changes throughout this test ===
    let verifiable_group_info = alice_group
        .export_group_info(provider, &alice_signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let ratchet_tree = alice_group.export_ratchet_tree();
    let (mut public_group, _extensions) = PublicGroup::from_external(
        provider.crypto(),
        provider.storage(),
        ratchet_tree.into(),
        verifiable_group_info,
        ProposalStore::new(),
    )
    .unwrap();

    // === Alice adds Bob ===
    let (message, welcome, _group_info) = alice_group
        .add_members(provider, &alice_signer, &[bob_kpb.key_package().clone()])
        .expect("Could not add member to group.");

    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    let public_message = match message.into_protocol_message().unwrap() {
        ProtocolMessage::PrivateMessage(_) => panic!("Unexpected message type."),
        ProtocolMessage::PublicMessage(public_message) => public_message,
    };
    let processed_message = public_group
        .process_message(provider.crypto(), *public_message)
        .unwrap();

    // Further inspection of the message can take place here ...
    match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(_)
        | ProcessedMessageContent::ProposalMessage(_)
        | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
            panic!("Unexpected message type.")
        }
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            // Merge the diff
            public_group
                .merge_commit(provider.storage(), *staged_commit)
                .unwrap()
        }
    };

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    // In the future, we'll use helper functions to skip the extraction steps above.

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(provider)
    .expect("Error creating group from staged join");

    // === Bob adds Charlie ===
    let (queued_messages, welcome, _group_info) = bob_group
        .add_members(provider, &bob_signer, &[charlie_kpb.key_package().clone()])
        .unwrap();

    // Alice processes
    let alice_processed_message = alice_group
        .process_message(
            provider,
            queued_messages
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process messages.");
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // The public group processes
    let ppm = public_group
        .process_message(provider.crypto(), into_public_message(queued_messages))
        .unwrap();
    public_group
        .merge_commit(provider.storage(), extract_staged_commit(ppm))
        .unwrap();

    // Bob merges
    bob_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let mut charlie_group = StagedWelcome::new_from_welcome(
        provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(bob_group.export_ratchet_tree().into()),
    )
    .expect("Error creating group from Welcome")
    .into_group(provider)
    .expect("Error creating group from Welcome");

    // === Alice removes Bob & Charlie commits ===

    let (queued_messages, _) = alice_group
        .propose_remove_member(provider, &alice_signer, LeafNodeIndex::new(1))
        .expect("Could not propose removal");

    let charlie_processed_message = charlie_group
        .process_message(
            provider,
            queued_messages
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process messages.");

    // The public group processes
    let ppm = public_group
        .process_message(provider.crypto(), into_public_message(queued_messages))
        .unwrap();
    // We have to add the proposal to the public group's proposal store.
    match ppm.into_content() {
        ProcessedMessageContent::ApplicationMessage(_)
        | ProcessedMessageContent::ExternalJoinProposalMessage(_)
        | ProcessedMessageContent::StagedCommitMessage(_) => panic!("Unexpected message type."),
        ProcessedMessageContent::ProposalMessage(p) => {
            match p.proposal() {
                Proposal::Remove(r) => assert_eq!(r.removed(), LeafNodeIndex::new(1)),
                _ => panic!("Unexpected proposal type"),
            }
            public_group.add_proposal(provider.storage(), *p).unwrap();
        }
    }

    // Check that we received the correct proposals
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        charlie_processed_message.into_content()
    {
        if let Proposal::Remove(ref remove_proposal) = staged_proposal.proposal() {
            // Check that Bob was removed
            assert_eq!(remove_proposal.removed(), LeafNodeIndex::new(1));
            // Store proposal
            charlie_group
                .store_pending_proposal(provider.storage(), *staged_proposal.clone())
                .expect("error writing to storage");
        } else {
            unreachable!("Expected a Proposal.");
        }

        // Check that Alice removed Bob
        assert!(matches!(
            staged_proposal.sender(),
            Sender::Member(member) if member.u32() == 0
        ));
    } else {
        unreachable!("Expected a QueuedProposal.");
    }

    // Charlie commits
    let (queued_messages, _welcome, _group_info) = charlie_group
        .commit_to_pending_proposals(provider, &charlie_signer)
        .expect("Could not commit proposal");

    // The public group processes
    let ppm = public_group
        .process_message(
            provider.crypto(),
            into_public_message(queued_messages.clone()),
        )
        .unwrap();
    public_group
        .merge_commit(provider.storage(), extract_staged_commit(ppm))
        .unwrap();

    // Check that we receive the correct proposal
    if let Some(staged_commit) = charlie_group.pending_commit() {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        assert_eq!(remove.remove_proposal().removed().u32(), 1);
        // Check that Alice removed Bob
        assert!(matches!(remove.sender(), Sender::Member(member) if member.u32() == 0));
    } else {
        unreachable!("Expected a StagedCommit.");
    };

    charlie_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Alice processes
    let alice_processed_message = alice_group
        .process_message(
            provider,
            queued_messages
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process messages.");
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check that the public group state matches that of all other participants
    assert_eq!(
        alice_group.export_group_context(),
        public_group.group_context()
    );
    assert_eq!(
        charlie_group.export_group_context(),
        public_group.group_context()
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        public_group.export_ratchet_tree()
    );
    assert_eq!(
        charlie_group.export_ratchet_tree(),
        public_group.export_ratchet_tree()
    );
}

// A helper function
fn into_public_message(message: MlsMessageOut) -> PublicMessageIn {
    match message.into_protocol_message().unwrap() {
        ProtocolMessage::PrivateMessage(_) => panic!("Unexpected message type."),
        ProtocolMessage::PublicMessage(public_message) => *public_message,
    }
}

fn extract_staged_commit(ppm: ProcessedMessage) -> StagedCommit {
    match ppm.into_content() {
        ProcessedMessageContent::ApplicationMessage(_)
        | ProcessedMessageContent::ProposalMessage(_)
        | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
            panic!("Unexpected message type.")
        }
        ProcessedMessageContent::StagedCommitMessage(staged_content) => *staged_content,
    }
}
