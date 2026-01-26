//! Tests for StagedCommit next epoch access APIs using the single group test framework

use openmls::{
    prelude::*,
    test_utils::single_group_test_framework::{AddMemberConfig, CorePartyState, GroupState},
    treesync::LeafNodeParameters,
};
use openmls_test::openmls_test;

/// Test that values from StagedCommit match MlsGroup after merge.
///
/// This test verifies that the next epoch data accessible through StagedCommit
/// methods matches the corresponding data in the MlsGroup after the commit is merged.
#[openmls_test]
fn staged_commit_next_epoch_values_match_merged_group() {
    // 1. Create parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    // 2. Generate pre-group states
    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);

    // 3. Create group config with ratchet tree extension
    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();
    let join_config = create_config.join_config().clone();

    // 4. Initialize group with Alice
    let group_id = GroupId::from_slice(b"test-group");
    let mut group_state =
        GroupState::new_from_party(group_id, alice_pre_group, create_config).unwrap();

    // 5. Add Bob using framework
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group],
            join_config,
            tree: None,
        })
        .unwrap();

    // === Manual operations to capture StagedCommit ===

    // 6. Bob performs self-update
    let [bob] = group_state.members_mut(&["bob"]);
    let (commit_msg, _, _) = bob
        .group
        .self_update(
            &bob.party.core_state.provider,
            &bob.party.signer,
            LeafNodeParameters::default(),
        )
        .unwrap()
        .into_contents();

    // 7. Bob merges his pending commit
    bob.group
        .merge_pending_commit(&bob.party.core_state.provider)
        .unwrap();

    // 8. Alice processes the commit to capture StagedCommit
    let [alice] = group_state.members_mut(&["alice"]);
    let processed = alice
        .group
        .process_message(
            &alice.party.core_state.provider,
            commit_msg.into_protocol_message().unwrap(),
        )
        .unwrap();

    let staged_commit = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(sc) => sc,
        _ => panic!("Expected StagedCommit"),
    };

    // === Capture values from StagedCommit ===
    assert!(!staged_commit.self_removed());

    let staged_epoch = staged_commit.epoch();
    let staged_auth = staged_commit.epoch_authenticator().unwrap().clone();
    let staged_psk = staged_commit.resumption_psk_secret().unwrap().clone();
    let staged_export = staged_commit
        .export_secret(
            alice.party.core_state.provider.crypto(),
            "test-label",
            b"ctx",
            32,
        )
        .unwrap();
    let staged_ctx = staged_commit.group_context().clone();
    let original_tree = alice.group.export_ratchet_tree();
    let staged_tree = staged_commit
        .export_ratchet_tree(alice.party.core_state.provider.crypto(), original_tree)
        .expect("unexpected error exporting the ratchet tree")
        .expect("there was no ratchet tree");

    // 9. Alice merges the staged commit
    alice
        .group
        .merge_staged_commit(&alice.party.core_state.provider, *staged_commit)
        .unwrap();

    // === Verify staged values match merged group values ===
    assert_eq!(staged_epoch, alice.group.epoch());
    assert_eq!(
        staged_auth.as_slice(),
        alice.group.epoch_authenticator().as_slice()
    );
    assert_eq!(
        staged_psk.as_slice(),
        alice.group.resumption_psk_secret().as_slice()
    );
    assert_eq!(
        staged_export,
        alice
            .group
            .export_secret(
                alice.party.core_state.provider.crypto(),
                "test-label",
                b"ctx",
                32
            )
            .unwrap()
    );
    assert_eq!(staged_tree, alice.group.export_ratchet_tree());
    assert_eq!(staged_ctx.ciphersuite(), alice.group.ciphersuite());
    assert_eq!(staged_ctx.group_id(), alice.group.group_id());
    assert_eq!(staged_ctx.epoch(), alice.group.epoch());
}

/// Test that StagedCommit returns None for optional methods when member is removed.
///
/// When a member processes a commit that removes them from the group, the staged
/// commit should return None for methods that require group membership.
#[openmls_test]
fn staged_commit_self_removed_returns_none() {
    // 1. Create parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    // 2. Generate pre-group states
    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);

    // 3. Create group config
    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();
    let join_config = create_config.join_config().clone();

    // 4. Initialize group with Alice and add Bob
    let group_id = GroupId::from_slice(b"test-group");
    let mut group_state =
        GroupState::new_from_party(group_id, alice_pre_group, create_config).unwrap();

    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group],
            join_config,
            tree: None,
        })
        .unwrap();

    // === Manual operations to capture StagedCommit ===

    // 5. Get Bob's leaf index
    let [bob] = group_state.members_mut(&["bob"]);
    let bob_leaf_index = bob.group.own_leaf_index();

    // 6. Alice removes Bob
    let [alice] = group_state.members_mut(&["alice"]);
    let (remove_msg, _, _) = alice
        .group
        .remove_members(
            &alice.party.core_state.provider,
            &alice.party.signer,
            &[bob_leaf_index],
        )
        .unwrap();

    // 7. Alice merges her pending commit
    alice
        .group
        .merge_pending_commit(&alice.party.core_state.provider)
        .unwrap();

    // 8. Bob processes the removal commit to capture StagedCommit
    let [bob] = group_state.members_mut(&["bob"]);
    let processed = bob
        .group
        .process_message(
            &bob.party.core_state.provider,
            remove_msg.into_protocol_message().unwrap(),
        )
        .unwrap();

    let staged_commit = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(sc) => sc,
        _ => panic!("Expected StagedCommit"),
    };

    // === Verify self_removed and None returns ===
    assert!(staged_commit.self_removed());
    assert!(staged_commit.epoch_authenticator().is_none());
    assert!(staged_commit.resumption_psk_secret().is_none());

    let original_tree = bob.group.export_ratchet_tree();
    assert!(staged_commit
        .export_ratchet_tree(bob.party.core_state.provider.crypto(), original_tree)
        .expect("when no ratchet tree is there, no exporting operations can fail")
        .is_none());

    assert!(staged_commit
        .export_secret(
            bob.party.core_state.provider.crypto(),
            "test-label",
            b"ctx",
            32
        )
        .is_err());

    // group_context and epoch are still accessible (public state)
    let _ = staged_commit.group_context();
    let _ = staged_commit.epoch();
}
