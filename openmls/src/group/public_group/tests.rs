use crate::{
    binary_tree::{array_representation::direct_path, LeafNodeIndex},
    framing::{
        public_message_in::PublicMessageIn, MlsMessageIn, MlsMessageOut, ProcessedMessage,
        ProcessedMessageContent, ProtocolMessage, Sender,
    },
    group::{
        mls_group::tests_and_kats::utils::setup_client, proposal_store::ProposalStore, GroupId,
        MlsGroup, MlsGroupCreateConfig, StagedCommit, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    messages::proposals::Proposal,
    test_utils::single_group_test_framework::{AddMemberConfig, CorePartyState, GroupState},
};

use super::{super::mls_group::StagedWelcome, PublicGroup};

#[openmls_test::openmls_test]
fn public_group() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let public_provider = &Provider::default();

    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, alice_provider);
    let (_bob_credential, bob_kpb, bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, bob_provider);
    let (_charlie_credential, charlie_kpb, charlie_signer, _charlie_pk) =
        setup_client("Charly", ciphersuite, charlie_provider);

    // Define the MlsGroup configuration
    // Set plaintext wire format policy s.t. the public group can track changes.
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    // === Create a public group that tracks the changes throughout this test ===
    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let ratchet_tree = alice_group.export_ratchet_tree();
    let (mut public_group, _extensions) = PublicGroup::from_external(
        public_provider.crypto(),
        public_provider.storage(),
        ratchet_tree.into(),
        verifiable_group_info,
        ProposalStore::new(),
    )
    .unwrap();

    // === Alice adds Bob ===
    let (message, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_kpb.key_package()),
        )
        .expect("Could not add member to group.");

    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");

    let public_message = match message.into_protocol_message().unwrap() {
        ProtocolMessage::PrivateMessage(_) => panic!("Unexpected message type."),
        ProtocolMessage::PublicMessage(public_message) => public_message,
    };
    let processed_message = public_group
        .process_message(public_provider.crypto(), *public_message)
        .unwrap();

    // Further inspection of the message can take place here ...
    match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(_)
        | ProcessedMessageContent::ProposalMessage(_)
        | ProcessedMessageContent::ExternalJoinProposalMessage(_)
        | ProcessedMessageContent::OwnPendingCommit
        | ProcessedMessageContent::OwnPrivateMessage => {
            panic!("Unexpected message type.")
        }
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            // Merge the diff
            public_group
                .merge_commit(public_provider.storage(), *staged_commit)
                .unwrap()
        }
        #[cfg(feature = "extensions-draft")]
        ProcessedMessageContent::UnresolvedAppDataCommit(_) => {
            panic!("Unexpected message type.")
        }
    };

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    // In the future, we'll use helper functions to skip the extraction steps above.

    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(bob_provider)
    .expect("Error creating group from staged join");

    // === Bob adds Charlie ===
    let (queued_messages, welcome, _group_info) = bob_group
        .add_members(
            bob_provider,
            &bob_signer,
            core::slice::from_ref(charlie_kpb.key_package()),
        )
        .unwrap();

    // Alice processes
    let alice_processed_message = alice_group
        .process_message(
            alice_provider,
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
            .merge_staged_commit(alice_provider, *staged_commit)
            .expect("Error merging commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // The public group processes
    let ppm = public_group
        .process_message(
            public_provider.crypto(),
            into_public_message(queued_messages),
        )
        .unwrap();
    public_group
        .merge_commit(public_provider.storage(), extract_staged_commit(ppm))
        .unwrap();

    // Bob merges
    bob_group
        .merge_pending_commit(bob_provider)
        .expect("error merging pending commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let mut charlie_group = StagedWelcome::new_from_welcome(
        charlie_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(bob_group.export_ratchet_tree().into()),
    )
    .expect("Error creating group from Welcome")
    .into_group(charlie_provider)
    .expect("Error creating group from Welcome");

    // === Alice removes Bob & Charlie commits ===

    let (queued_messages, _) = alice_group
        .propose_remove_member(alice_provider, &alice_signer, LeafNodeIndex::new(1))
        .expect("Could not propose removal");

    let charlie_processed_message = charlie_group
        .process_message(
            charlie_provider,
            queued_messages
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process messages.");

    // The public group processes
    let ppm = public_group
        .process_message(
            public_provider.crypto(),
            into_public_message(queued_messages),
        )
        .unwrap();
    // We have to add the proposal to the public group's proposal store.
    match ppm.into_content() {
        ProcessedMessageContent::ApplicationMessage(_)
        | ProcessedMessageContent::ExternalJoinProposalMessage(_)
        | ProcessedMessageContent::StagedCommitMessage(_)
        | ProcessedMessageContent::OwnPendingCommit
        | ProcessedMessageContent::OwnPrivateMessage => panic!("Unexpected message type."),
        #[cfg(feature = "extensions-draft")]
        ProcessedMessageContent::UnresolvedAppDataCommit(_) => {
            panic!("Unexpected message type.")
        }
        ProcessedMessageContent::ProposalMessage(p) => {
            match p.proposal() {
                Proposal::Remove(r) => assert_eq!(r.removed(), LeafNodeIndex::new(1)),
                _ => panic!("Unexpected proposal type"),
            }
            public_group
                .add_proposal(public_provider.storage(), *p)
                .unwrap();
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
                .store_pending_proposal(charlie_provider.storage(), *staged_proposal.clone())
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
        .commit_to_pending_proposals(charlie_provider, &charlie_signer)
        .expect("Could not commit proposal");

    // The public group processes
    let ppm = public_group
        .process_message(
            public_provider.crypto(),
            into_public_message(queued_messages.clone()),
        )
        .unwrap();
    public_group
        .merge_commit(public_provider.storage(), extract_staged_commit(ppm))
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
        .merge_pending_commit(charlie_provider)
        .expect("error merging pending commit");

    // Alice processes
    let alice_processed_message = alice_group
        .process_message(
            alice_provider,
            queued_messages
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process messages.");
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(alice_provider, *staged_commit)
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
        | ProcessedMessageContent::ExternalJoinProposalMessage(_)
        | ProcessedMessageContent::OwnPendingCommit
        | ProcessedMessageContent::OwnPrivateMessage => {
            panic!("Unexpected message type.")
        }
        ProcessedMessageContent::StagedCommitMessage(staged_content) => *staged_content,
        #[cfg(feature = "extensions-draft")]
        ProcessedMessageContent::UnresolvedAppDataCommit(_) => {
            panic!("Unexpected message type.")
        }
    }
}

#[openmls_test::openmls_test]
fn old_messages_with_blank_leaves() {
    let provider = &Provider::default();

    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");
    let david_party = CorePartyState::<Provider>::new("david");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
    let david_pre_group = david_party.generate_pre_group(ciphersuite);

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(1)
        .build();

    // Join config
    let mls_group_join_config = mls_group_create_config.join_config().clone();

    // Initialize the group state
    let group_id = GroupId::from_slice(b"test");
    let mut group_state =
        GroupState::new_from_party(group_id, alice_pre_group, mls_group_create_config).unwrap();

    // Alice adds Bob, Charlie and David
    // This should succeed, since all used credential types used are supported
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group, charlie_pre_group, david_pre_group],
            join_config: mls_group_join_config.clone(),
            tree: None,
        })
        .expect("Could not add member");

    let [alice_group] = group_state.members_mut(&["alice"]);

    let commit = alice_group
        .build_commit_and_stage(|builder| builder.propose_removals(vec![LeafNodeIndex::new(1)]))
        .unwrap();

    group_state.untrack_member("bob");

    group_state
        .deliver_and_apply_if(commit.into_commit().into(), |m| {
            m.party.core_state.name != "alice"
        })
        .unwrap();

    let [alice_group, charlie_group, david_group] =
        group_state.members_mut(&["alice", "charlie", "david"]);

    alice_group
        .group
        .merge_pending_commit(&alice_group.party.core_state.provider)
        .unwrap();

    // Charlie sends an application message in the epoch that still contains the blank leaf.
    let message_charlie = charlie_group
        .group
        .create_message(
            provider,
            &charlie_group.party.signer,
            b"delayed application",
        )
        .expect("could not create application message");

    // David also sends a message
    let message_david = david_group
        .group
        .create_message(provider, &david_group.party.signer, b"delayed application2")
        .expect("could not create application message");

    // Advance to the next epoch so the message becomes "old" and must use the past store which stores group members in the dense vector
    let commit = alice_group
        .build_commit_and_stage(|builder| builder.force_self_update(true))
        .unwrap();

    alice_group
        .group
        .merge_pending_commit(&alice_group.party.core_state.provider)
        .unwrap();

    group_state
        .deliver_and_apply_if(commit.into_commit().into(), |m| {
            m.party.core_state.name != "alice"
        })
        .unwrap();

    let [alice_group] = group_state.members_mut(&["alice"]);

    // DS releases Charlie's buffered message to Alice.
    let app_in = MlsMessageIn::from(message_charlie);

    alice_group
        .group
        .process_message(provider, app_in.try_into_protocol_message().unwrap())
        .expect("Alice failed to process Charlie's message after Bob was removed");

    // DS releases David's buffered message to Alice.
    let app_in = MlsMessageIn::from(message_david);

    alice_group
        .group
        .process_message(provider, app_in.try_into_protocol_message().unwrap())
        .expect("Alice failed to process David's message after Bob was removed");
}

/// Joins a group from a ratchet tree that contains a parent node whose unmerged
/// leaf sits more than one level below it, with a non-blank intermediate node in
/// between. That is the shape that makes `PublicGroup::from_ratchet_tree` look
/// up leaves in the unmerged leaf lists of intermediate nodes.
#[openmls_test::openmls_test]
fn external_join_with_nested_unmerged_leaves() {
    // A tree of 16 leaves is the smallest one in which an unmerged leaf can
    // have a non-blank intermediate node between itself and a parent node that
    // lists it. The nodes directly above a blank leaf stay blank, because they
    // are filtered out of every update path.
    const NAMES: [&str; 16] = [
        "m00", "m01", "m02", "m03", "m04", "m05", "m06", "m07", "m08", "m09", "m10", "m11", "m12",
        "m13", "m14", "m15",
    ];

    let parties: Vec<CorePartyState<Provider>> =
        NAMES.iter().map(|name| CorePartyState::new(name)).collect();
    let newcomer_party = CorePartyState::<Provider>::new("newcomer");

    let mut pre_groups = parties
        .iter()
        .map(|party| party.generate_pre_group(ciphersuite));
    let creator_pre_group = pre_groups.next().unwrap();
    let addees = pre_groups.collect();
    let newcomer_pre_group = newcomer_party.generate_pre_group(ciphersuite);

    let mls_group_create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let mls_group_join_config = mls_group_create_config.join_config().clone();

    let group_id = GroupId::from_slice(b"nested unmerged leaves");
    let mut group_state =
        GroupState::new_from_party(group_id, creator_pre_group, mls_group_create_config).unwrap();

    // The member at leaf 0 fills the tree, so that the leaves 0 to 15 are all
    // in use.
    group_state
        .add_member(AddMemberConfig {
            adder: NAMES[0],
            addees,
            join_config: mls_group_join_config.clone(),
            tree: None,
        })
        .expect("Could not add members");

    // The member at leaf 0 removes the one at leaf 5, which blanks leaf 5 and
    // its direct path.
    let commit = {
        let [committer] = group_state.members_mut(&[NAMES[0]]);
        committer
            .build_commit_and_stage(|builder| builder.propose_removals(vec![LeafNodeIndex::new(5)]))
            .unwrap()
    };
    group_state.untrack_member(NAMES[5]);
    group_state
        .deliver_and_apply_if(commit.into_commit().into(), |m| {
            m.party.core_state.name != NAMES[0]
        })
        .unwrap();
    {
        let [committer] = group_state.members_mut(&[NAMES[0]]);
        committer
            .group
            .merge_pending_commit(&committer.party.core_state.provider)
            .unwrap();
    }

    // The member at leaf 6 refreshes its direct path. That re-populates the
    // parents of the leaves 4 to 7 and of the leaves 0 to 7, both of which are
    // above the blank leaf 5.
    let commit = {
        let [committer] = group_state.members_mut(&[NAMES[6]]);
        committer
            .build_commit_and_stage(|builder| builder.force_self_update(true))
            .unwrap()
    };
    group_state
        .deliver_and_apply_if(commit.into_commit().into(), |m| {
            m.party.core_state.name != NAMES[6]
        })
        .unwrap();
    {
        let [committer] = group_state.members_mut(&[NAMES[6]]);
        committer
            .group
            .merge_pending_commit(&committer.party.core_state.provider)
            .unwrap();
    }

    // The member at leaf 8 adds the newcomer, who takes the blank leaf 5. The
    // newcomer becomes an unmerged leaf of the two parent nodes above it that
    // the committer does not refresh.
    group_state
        .add_member(AddMemberConfig {
            adder: NAMES[8],
            addees: vec![newcomer_pre_group],
            join_config: mls_group_join_config,
            tree: None,
        })
        .expect("Could not add member");

    let (ratchet_tree, verifiable_group_info) = {
        let [member] = group_state.members_mut(&[NAMES[0]]);
        let provider = &member.party.core_state.provider;
        let verifiable_group_info = member
            .group
            .export_group_info(provider.crypto(), &member.party.signer, false)
            .unwrap()
            .into_verifiable_group_info()
            .unwrap();

        (member.group.export_ratchet_tree(), verifiable_group_info)
    };

    let public_provider = &Provider::default();
    let (public_group, _group_info) = PublicGroup::from_external(
        public_provider.crypto(),
        public_provider.storage(),
        ratchet_tree.into(),
        verifiable_group_info,
        ProposalStore::new(),
    )
    .expect("Could not join the group from the ratchet tree");

    // Check that the tree has the shape we set out to build, i.e. that the
    // validation above did look at intermediate nodes. Also check the sorting
    // invariant of the unmerged leaf lists, which that lookup relies on.
    let treesync = public_group.treesync();
    let mut intermediate_nodes = 0;
    for (parent_index, parent_node) in treesync.full_parents() {
        let unmerged_leaves = parent_node.unmerged_leaves();
        assert!(
            unmerged_leaves.windows(2).all(|pair| pair[0] < pair[1]),
            "unmerged leaves are not sorted: {unmerged_leaves:?}"
        );

        for leaf_index in unmerged_leaves {
            let path = direct_path(*leaf_index, treesync.tree_size());
            let parent_offset = path
                .iter()
                .position(|index| index == &parent_index)
                .unwrap();

            for intermediate_index in &path[..parent_offset] {
                if let Some(intermediate_node) = treesync.parent(*intermediate_index) {
                    assert!(intermediate_node.unmerged_leaves().contains(leaf_index));
                    intermediate_nodes += 1;
                }
            }
        }
    }
    assert!(
        intermediate_nodes > 0,
        "the tree has no non-blank intermediate node between an unmerged leaf and its parent"
    );
}
