use openmls::{prelude::*, test_utils::single_group_test_framework::*};
use openmls_test::openmls_test;
use openmls_tree_health::find_self_update_candidates;

/// 4-leaf group: alice=0, bob=1, charlie=2, dana=3.
/// Remove bob (leaf 1).
///
/// XOR distances from 1:
///   alice(0):   0 XOR 1 = 1  → leading_zeros = 31  ← closest (sibling)
///   charlie(2): 2 XOR 1 = 3  → leading_zeros = 30
///   dana(3):    3 XOR 1 = 2  → leading_zeros = 30
///
/// Expected candidate: alice (leaf 0).
#[openmls_test]
fn candidate_is_sibling_of_removed() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");
    let dana_party = CorePartyState::<Provider>::new("dana");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
    let dana_pre_group = dana_party.generate_pre_group(ciphersuite);

    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let join_config = create_config.join_config().clone();

    let mut group_state = GroupState::new_from_party(
        GroupId::from_slice(b"tree-health integration"),
        alice_pre_group,
        create_config,
    )
    .unwrap();

    // alice=0, bob=1, charlie=2, dana=3
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group, charlie_pre_group, dana_pre_group],
            join_config,
            tree: None,
        })
        .unwrap();

    // Remove bob (leaf 1).
    let commit = {
        let [alice] = group_state.members_mut(&["alice"]);
        let (commit, _, _) = alice
            .group
            .remove_members(
                &alice.party.core_state.provider,
                &alice.party.signer,
                &[LeafNodeIndex::new(1)],
            )
            .unwrap();
        alice
            .group
            .merge_pending_commit(&alice.party.core_state.provider)
            .unwrap();
        commit
    };

    group_state
        .deliver_and_apply_if(commit.into(), |member| {
            matches!(member.party.core_state.name, "charlie" | "dana")
        })
        .unwrap();

    // Ask alice's view of the tree for the remaining leaves.
    let [alice] = group_state.members_mut(&["alice"]);
    let remaining_leaves = alice.group.treesync().full_leaves().map(|(idx, _)| idx);

    let candidates = find_self_update_candidates(LeafNodeIndex::new(1), remaining_leaves);

    // Alice (leaf 0) is bob's sibling — the topologically closest member.
    assert_eq!(candidates, vec![LeafNodeIndex::new(0)]);
}

/// 4-leaf group: alice=0, bob=1, charlie=2, dana=3.
/// Remove alice (leaf 0).
///
/// XOR distances from 0:
///   bob(1):     1 XOR 0 = 1  → leading_zeros = 31  ← closest (sibling)
///   charlie(2): 2 XOR 0 = 2  → leading_zeros = 30
///   dana(3):    3 XOR 0 = 3  → leading_zeros = 30
///
/// Expected candidate: bob (leaf 1).
#[openmls_test]
fn candidate_is_sibling_when_first_leaf_removed() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");
    let dana_party = CorePartyState::<Provider>::new("dana");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
    let dana_pre_group = dana_party.generate_pre_group(ciphersuite);

    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let join_config = create_config.join_config().clone();

    let mut group_state = GroupState::new_from_party(
        GroupId::from_slice(b"tree-health remove-first"),
        alice_pre_group,
        create_config,
    )
    .unwrap();

    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group, charlie_pre_group, dana_pre_group],
            join_config,
            tree: None,
        })
        .unwrap();

    // Remove alice (leaf 0) — bob does the commit.
    let commit = {
        let [bob] = group_state.members_mut(&["bob"]);
        let (commit, _, _) = bob
            .group
            .remove_members(
                &bob.party.core_state.provider,
                &bob.party.signer,
                &[LeafNodeIndex::new(0)],
            )
            .unwrap();
        bob.group
            .merge_pending_commit(&bob.party.core_state.provider)
            .unwrap();
        commit
    };

    group_state
        .deliver_and_apply_if(commit.into(), |member| {
            matches!(member.party.core_state.name, "charlie" | "dana")
        })
        .unwrap();

    let [bob] = group_state.members_mut(&["bob"]);
    let remaining_leaves = bob.group.treesync().full_leaves().map(|(idx, _)| idx);

    let candidates = find_self_update_candidates(LeafNodeIndex::new(0), remaining_leaves);

    // Bob (leaf 1) is alice's sibling.
    assert_eq!(candidates, vec![LeafNodeIndex::new(1)]);
}

/// 4-leaf group: alice=0, bob=1, charlie=2, dana=3.
/// First remove bob (leaf 1), then remove alice (leaf 0).
///
/// After both removals the remaining full leaves are charlie(2) and dana(3).
/// Bob's slot (leaf 1) — alice's sibling, the closest possible leaf — is blank,
/// so it does not appear in the iterator.
///
/// XOR distances from alice(0) among the remaining leaves:
///   charlie(2): 2 XOR 0 = 2  → leading_zeros = 30
///   dana(3):    3 XOR 0 = 3  → leading_zeros = 30
///
/// Both are equidistant, so both are returned as candidates.
#[openmls_test]
fn multiple_candidates_when_sibling_is_blank() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");
    let dana_party = CorePartyState::<Provider>::new("dana");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
    let dana_pre_group = dana_party.generate_pre_group(ciphersuite);

    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let join_config = create_config.join_config().clone();

    let mut group_state = GroupState::new_from_party(
        GroupId::from_slice(b"tree-health multi-candidate"),
        alice_pre_group,
        create_config,
    )
    .unwrap();

    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group, charlie_pre_group, dana_pre_group],
            join_config,
            tree: None,
        })
        .unwrap();

    // Step 1: charlie removes bob (leaf 1) — blanks alice's sibling slot.
    let commit = {
        let [charlie] = group_state.members_mut(&["charlie"]);
        let (commit, _, _) = charlie
            .group
            .remove_members(
                &charlie.party.core_state.provider,
                &charlie.party.signer,
                &[LeafNodeIndex::new(1)],
            )
            .unwrap();
        charlie
            .group
            .merge_pending_commit(&charlie.party.core_state.provider)
            .unwrap();
        commit
    };
    group_state
        .deliver_and_apply_if(commit.into(), |member| {
            matches!(member.party.core_state.name, "alice" | "dana")
        })
        .unwrap();

    // Step 2: charlie removes alice (leaf 0).
    let commit = {
        let [charlie] = group_state.members_mut(&["charlie"]);
        let (commit, _, _) = charlie
            .group
            .remove_members(
                &charlie.party.core_state.provider,
                &charlie.party.signer,
                &[LeafNodeIndex::new(0)],
            )
            .unwrap();
        charlie
            .group
            .merge_pending_commit(&charlie.party.core_state.provider)
            .unwrap();
        commit
    };
    group_state
        .deliver_and_apply_if(commit.into(), |member| {
            member.party.core_state.name == "dana"
        })
        .unwrap();

    // Ask charlie's view: remaining full leaves are charlie(2) and dana(3).
    let [charlie] = group_state.members_mut(&["charlie"]);
    let remaining_leaves = charlie.group.treesync().full_leaves().map(|(idx, _)| idx);

    let candidates = find_self_update_candidates(LeafNodeIndex::new(0), remaining_leaves);

    // Both charlie(2) and dana(3) are equidistant from alice's slot.
    assert_eq!(
        candidates,
        vec![LeafNodeIndex::new(2), LeafNodeIndex::new(3)]
    );
}
