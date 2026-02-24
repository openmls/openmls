use openmls::{prelude::*, test_utils::single_group_test_framework::*};
use openmls_test::openmls_test;
use openmls_tree_health::{find_update_candidates, hypothetical_root_resolution_size};

/// 4-leaf group: alice=0, bob=1, charlie=2, dana=3.
/// Best committer for removing bob (leaf 1).
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

    // Identify the best committer for removing bob before the commit is issued.
    let candidates = {
        let [alice] = group_state.members_mut(&["alice"]);
        let leaves = alice.group.treesync().full_leaves().map(|(idx, _)| idx);
        find_update_candidates(LeafNodeIndex::new(1), leaves)
    };

    // Alice (leaf 0) is bob's sibling — her update_path re-keys the most
    // shared path with the removed slot.
    assert_eq!(candidates, vec![LeafNodeIndex::new(0)]);
}

/// 4-leaf group: alice=0, bob=1, charlie=2, dana=3.
/// Best committer for removing alice (leaf 0).
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

    // Identify the best committer for removing alice before the commit is issued.
    let candidates = {
        let [bob] = group_state.members_mut(&["bob"]);
        let leaves = bob.group.treesync().full_leaves().map(|(idx, _)| idx);
        find_update_candidates(LeafNodeIndex::new(0), leaves)
    };

    // Bob (leaf 1) is alice's sibling.
    assert_eq!(candidates, vec![LeafNodeIndex::new(1)]);
}

/// 4-leaf group: alice=0, bob=1, charlie=2, dana=3.
/// Best committer for removing alice (leaf 0) after bob (leaf 1) has already
/// been removed — alice's sibling slot is now blank.
///
/// After bob is removed, the remaining full leaves are alice(0), charlie(2),
/// dana(3). Bob's slot (leaf 1) — alice's sibling — is blank and absent from
/// the iterator.
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

    // Step 2: identify the best committer for removing alice now that her
    // sibling slot is blank.
    let candidates = {
        let [charlie] = group_state.members_mut(&["charlie"]);
        let leaves = charlie.group.treesync().full_leaves().map(|(idx, _)| idx);
        find_update_candidates(LeafNodeIndex::new(0), leaves)
    };

    // Both charlie(2) and dana(3) are equidistant from alice's slot.
    assert_eq!(
        candidates,
        vec![LeafNodeIndex::new(2), LeafNodeIndex::new(3)]
    );
}

/// 8-member group built in two batches; every new member self-updates right
/// after joining.
///
/// Tree layout (perfect binary tree, 8 leaf slots):
///
/// ```text
///                         P3 (root)
///                       /           \
///                P1                   P5
///              /    \               /    \
///            P0      P2           P4      P6
///           /  \   /  \         /  \    /  \
///          L0  L1 L2  L3       L4  L5  L6  L7
///        alice bob ch dana   eve  fr grace heidi
/// ```
///
/// Batch 1: alice creates the group then adds bob(1), charlie(2), dana(3).
/// Alice's UpdatePath covers P0 → P1 → P3(root).  The three new leaves are
/// then marked unmerged on every non-blank ancestor:
///   root.unmerged_leaves = [bob(1), charlie(2), dana(3)]
///
/// Bob, charlie and dana each self-update in turn.  The first update (bob's)
/// covers P0 → P1 → P3(root) and clears root.unmerged_leaves to []; the
/// remaining two are no-ops for the root but still good hygiene.
///
/// Batch 2: alice adds eve(4), frank(5), grace(6), heidi(7).  Alice's path
/// again covers P0 → P1 → P3(root) and resets the root; the four new leaves
/// land in the right half where P4/P5/P6 are still blank, so their only
/// non-blank ancestor is the root itself:
///   root.unmerged_leaves = [eve(4), frank(5), grace(6), heidi(7)]
///
/// At this point the batch-2 members are the best self-update candidates:
/// hypothetical sizes are 4 for eve/frank/grace/heidi (they are in the
/// unmerged list) versus 5 for alice/bob/charlie/dana (they are not).
///
/// Eve, frank, grace and heidi self-update.  The first update reaches P3
/// and empties the root; subsequent ones keep it clean.
///
/// Alice then removes eve (leaf 4).  The Remove commit carries an
/// UpdatePath from alice's leaf up through P0 → P1 → P3(root), so
/// root.unmerged_leaves stays [].
///
/// After the remove every remaining leaf has hypothetical_root_resolution_size
/// = 1: the tree is fully merged and no self-update can reduce the root
/// resolution further.
#[openmls_test]
fn minimal_resolution_after_remove_when_all_self_updated() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");
    let dana_party = CorePartyState::<Provider>::new("dana");
    let eve_party = CorePartyState::<Provider>::new("eve");
    let frank_party = CorePartyState::<Provider>::new("frank");
    let grace_party = CorePartyState::<Provider>::new("grace");
    let heidi_party = CorePartyState::<Provider>::new("heidi");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
    let dana_pre_group = dana_party.generate_pre_group(ciphersuite);
    let eve_pre_group = eve_party.generate_pre_group(ciphersuite);
    let frank_pre_group = frank_party.generate_pre_group(ciphersuite);
    let grace_pre_group = grace_party.generate_pre_group(ciphersuite);
    let heidi_pre_group = heidi_party.generate_pre_group(ciphersuite);

    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let join_config = create_config.join_config().clone();

    let mut group_state = GroupState::new_from_party(
        GroupId::from_slice(b"tree-health 8member-resolution"),
        alice_pre_group,
        create_config,
    )
    .unwrap();

    // Batch 1: alice=0, bob=1, charlie=2, dana=3.
    // root.unmerged_leaves = [bob(1), charlie(2), dana(3)] after this commit.
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group, charlie_pre_group, dana_pre_group],
            join_config: join_config.clone(),
            tree: None,
        })
        .unwrap();

    // Each batch-1 member self-updates after joining.
    for name in ["bob", "charlie", "dana"] {
        let commit = {
            let [member] = group_state.members_mut(&[name]);
            let bundle = member
                .group
                .self_update(
                    &member.party.core_state.provider,
                    &member.party.signer,
                    LeafNodeParameters::default(),
                )
                .unwrap();
            let (commit, _, _) = bundle.into_contents();
            member
                .group
                .merge_pending_commit(&member.party.core_state.provider)
                .unwrap();
            commit
        };
        group_state
            .deliver_and_apply_if(commit.into(), |m| m.party.core_state.name != name)
            .unwrap();
    }

    // Batch 2: eve=4, frank=5, grace=6, heidi=7.
    // Alice's UpdatePath resets the root, then the four new leaves are marked
    // unmerged on the root (their only non-blank ancestor):
    //   root.unmerged_leaves = [eve(4), frank(5), grace(6), heidi(7)]
    // At this point eve/frank/grace/heidi are the best self-update candidates
    // (hypothetical size 4 vs 5 for the already-merged members).
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![
                eve_pre_group,
                frank_pre_group,
                grace_pre_group,
                heidi_pre_group,
            ],
            join_config,
            tree: None,
        })
        .unwrap();

    // Each batch-2 member self-updates after joining.
    for name in ["eve", "frank", "grace", "heidi"] {
        let commit = {
            let [member] = group_state.members_mut(&[name]);
            let bundle = member
                .group
                .self_update(
                    &member.party.core_state.provider,
                    &member.party.signer,
                    LeafNodeParameters::default(),
                )
                .unwrap();
            let (commit, _, _) = bundle.into_contents();
            member
                .group
                .merge_pending_commit(&member.party.core_state.provider)
                .unwrap();
            commit
        };
        group_state
            .deliver_and_apply_if(commit.into(), |m| m.party.core_state.name != name)
            .unwrap();
    }

    // Alice removes eve (leaf 4).  The Remove commit carries an UpdatePath
    // from alice's leaf up through the root, keeping root.unmerged_leaves = [].
    let commit = {
        let [alice] = group_state.members_mut(&["alice"]);
        let (commit, _, _) = alice
            .group
            .remove_members(
                &alice.party.core_state.provider,
                &alice.party.signer,
                &[LeafNodeIndex::new(4)],
            )
            .unwrap();
        alice
            .group
            .merge_pending_commit(&alice.party.core_state.provider)
            .unwrap();
        commit
    };
    group_state
        .deliver_and_apply_if(commit.into(), |m| {
            matches!(
                m.party.core_state.name,
                "bob" | "charlie" | "dana" | "frank" | "grace" | "heidi"
            )
        })
        .unwrap();

    // Query the post-remove tree state from alice's perspective.
    let (root_unmerged, remaining_leaves) = {
        let [alice] = group_state.members_mut(&["alice"]);
        let root_unmerged = alice.group.treesync().root_unmerged_leaves().to_vec();
        let remaining_leaves: Vec<LeafNodeIndex> = alice
            .group
            .treesync()
            .full_leaves()
            .map(|(idx, _)| idx)
            .collect();
        (root_unmerged, remaining_leaves)
    };

    // Every member committed an UpdatePath that reached the root at some
    // point, and the Remove commit did so too — no unmerged leaves remain.
    assert!(root_unmerged.is_empty());

    // Compute hypothetical_root_resolution_size for every remaining leaf and
    // find those that minimise it.
    let sizes: Vec<(LeafNodeIndex, usize)> = remaining_leaves
        .iter()
        .map(|&leaf| {
            (
                leaf,
                hypothetical_root_resolution_size(leaf, &root_unmerged),
            )
        })
        .collect();

    let min_size = sizes.iter().map(|(_, s)| *s).min().unwrap();
    let best_candidates: Vec<LeafNodeIndex> = sizes
        .iter()
        .filter_map(|&(leaf, s)| (s == min_size).then_some(leaf))
        .collect();

    // Tree is fully merged: minimum is 1 and every remaining leaf achieves it.
    assert_eq!(min_size, 1);
    assert_eq!(best_candidates, remaining_leaves);
}
