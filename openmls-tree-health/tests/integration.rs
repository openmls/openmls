use openmls::{prelude::*, test_utils::single_group_test_framework::*};
use openmls_test::openmls_test;
use openmls_tree_health::find_update_candidates;
use openmls_tree_health::tree_state::{CommitInfo, LeafIndex, LeafState, ParentState, TreeState};

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

/// Builds the RFC 9420 Figure 10 scenario, then validates `TreeState::simulate_all_commits`
/// against the real group.
///
/// After all five steps the tree has:
///   - alice=0, bob=1 (re-added, unmerged), charlie=2 (blank), dana=3,
///     eve=4, frank=5, grace=6 (blank), heidi=7, oscar=8.
///   - root.unmerged_leaves = [bob=1], root resolution = 2.
///
/// The model identifies heidi(7) and oscar(8) as the cheapest committers
/// (cost 4), while all other active members cost 5.
///
/// After heidi self-updates she re-keys tree[13], tree[11], tree[7], root
/// (all with unmerged=[]).  Oscar's co-path then contains tree[7] at
/// resolution 1 (was 4), so his next-round cost drops to 1.
#[openmls_test]
fn tree_state_figure10_simulate_all_commits() {
    // === Part A: build Figure 10 with real group ===

    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let new_bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");
    let dana_party = CorePartyState::<Provider>::new("dana");
    let eve_party = CorePartyState::<Provider>::new("eve");
    let frank_party = CorePartyState::<Provider>::new("frank");
    let grace_party = CorePartyState::<Provider>::new("grace");
    let heidi_party = CorePartyState::<Provider>::new("heidi");
    let oscar_party = CorePartyState::<Provider>::new("oscar");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
    let dana_pre_group = dana_party.generate_pre_group(ciphersuite);
    let eve_pre_group = eve_party.generate_pre_group(ciphersuite);
    let frank_pre_group = frank_party.generate_pre_group(ciphersuite);
    let grace_pre_group = grace_party.generate_pre_group(ciphersuite);
    let heidi_pre_group = heidi_party.generate_pre_group(ciphersuite);
    let oscar_pre_group = oscar_party.generate_pre_group(ciphersuite);

    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let join_config = create_config.join_config().clone();

    // Step 1: alice creates the group with all others (leaves 0..8).
    let mut group_state = GroupState::new_from_party(
        GroupId::from_slice(b"tree-health figure10-tree-state"),
        alice_pre_group,
        create_config,
    )
    .unwrap();

    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![
                bob_pre_group,
                charlie_pre_group,
                dana_pre_group,
                eve_pre_group,
                frank_pre_group,
                grace_pre_group,
                heidi_pre_group,
                oscar_pre_group,
            ],
            join_config: join_config.clone(),
            tree: None,
        })
        .unwrap();

    // Step 2: frank self-updates.
    {
        let commit = {
            let [frank] = group_state.members_mut(&["frank"]);
            let bundle = frank
                .group
                .self_update(
                    &frank.party.core_state.provider,
                    &frank.party.signer,
                    LeafNodeParameters::default(),
                )
                .unwrap();
            let (commit, _, _) = bundle.into_contents();
            frank
                .group
                .merge_pending_commit(&frank.party.core_state.provider)
                .unwrap();
            commit
        };
        group_state
            .deliver_and_apply_if(commit.into(), |m| m.party.core_state.name != "frank")
            .unwrap();
    }

    // Step 3: dana removes bob (leaf 1) and charlie (leaf 2).
    {
        let commit = {
            let [dana] = group_state.members_mut(&["dana"]);
            let (commit, _, _) = dana
                .group
                .remove_members(
                    &dana.party.core_state.provider,
                    &dana.party.signer,
                    &[LeafNodeIndex::new(1), LeafNodeIndex::new(2)],
                )
                .unwrap();
            dana.group
                .merge_pending_commit(&dana.party.core_state.provider)
                .unwrap();
            commit
        };
        group_state
            .deliver_and_apply_if(commit.into(), |m| {
                matches!(
                    m.party.core_state.name,
                    "alice" | "eve" | "frank" | "grace" | "heidi" | "oscar"
                )
            })
            .unwrap();
        group_state.untrack_member("bob");
        group_state.untrack_member("charlie");
    }

    // Step 4: oscar removes grace (leaf 6).
    {
        let commit = {
            let [oscar] = group_state.members_mut(&["oscar"]);
            let (commit, _, _) = oscar
                .group
                .remove_members(
                    &oscar.party.core_state.provider,
                    &oscar.party.signer,
                    &[LeafNodeIndex::new(6)],
                )
                .unwrap();
            oscar
                .group
                .merge_pending_commit(&oscar.party.core_state.provider)
                .unwrap();
            commit
        };
        group_state
            .deliver_and_apply_if(commit.into(), |m| {
                matches!(
                    m.party.core_state.name,
                    "alice" | "dana" | "eve" | "frank" | "heidi"
                )
            })
            .unwrap();
        group_state.untrack_member("grace");
    }

    // Step 5: alice re-adds bob with a partial Commit (no UpdatePath).
    let bob_new_pre_group = new_bob_party.generate_pre_group(ciphersuite);
    let bob_new_key_package = bob_new_pre_group.key_package_bundle.key_package().clone();

    let (commit, welcome) = {
        let [alice] = group_state.members_mut(&["alice"]);
        let bundle = alice
            .build_commit_and_stage(|builder| builder.propose_adds(vec![bob_new_key_package]))
            .unwrap();
        let (commit, welcome, _) = bundle.into_contents();
        alice
            .group
            .merge_pending_commit(&alice.party.core_state.provider)
            .unwrap();
        (commit, welcome.unwrap())
    };

    group_state
        .deliver_and_apply_if(commit.into(), |m| m.party.core_state.name != "alice")
        .unwrap();

    group_state
        .deliver_and_apply_welcome(bob_new_pre_group, join_config, welcome, None)
        .unwrap();

    // === Part B: cross-validate real group state ===
    {
        let [alice] = group_state.members_mut(&["alice"]);
        let root_unmerged = alice.group.treesync().root_unmerged_leaves().to_vec();
        let actual_root_resolution = alice.group.treesync().root_resolution_size();
        assert_eq!(root_unmerged, vec![LeafNodeIndex::new(1)]);
        assert_eq!(actual_root_resolution, 2);
    }

    // === Part C: construct TreeState for Figure 10 ===
    //
    // 9-leaf tree; parents[k] sits at tree-node index 2k+1:
    //   k=0 → tree[1], k=1 → tree[3], …, k=7 → root[15]
    let tree_state = TreeState::new(
        vec![
            LeafState::Occupied, // alice   (0)
            LeafState::Occupied, // bob     (1) re-added
            LeafState::Blank,    // charlie (2) removed
            LeafState::Occupied, // dana    (3)
            LeafState::Occupied, // eve     (4)
            LeafState::Occupied, // frank   (5)
            LeafState::Blank,    // grace   (6) removed
            LeafState::Occupied, // heidi   (7)
            LeafState::Occupied, // oscar   (8)
        ],
        vec![
            ParentState::Blank, // tree[1]  k=0
            ParentState::Occupied {
                unmerged_leaves: vec![LeafIndex(1)],
            }, // tree[3]  k=1
            ParentState::Blank, // tree[5]  k=2
            ParentState::Blank, // tree[7]  k=3
            ParentState::Occupied {
                unmerged_leaves: vec![],
            }, // tree[9]  k=4
            ParentState::Blank, // tree[11] k=5
            ParentState::Blank, // tree[13] k=6
            ParentState::Occupied {
                unmerged_leaves: vec![LeafIndex(1)],
            }, // root[15] k=7
        ],
    );

    // === Part D: simulate all commits with no proposals ===
    let infos = tree_state.simulate_all_commits(&[], &[]);
    let by_leaf: std::collections::HashMap<u32, &CommitInfo> =
        infos.iter().map(|i| (i.leaf.0, i)).collect();

    // All 7 occupied non-blank leaves are eligible committers.
    assert_eq!(infos.len(), 7);

    // Per-leaf commit sizes (verified from co-path resolutions above).
    assert_eq!(by_leaf[&0].commit_size, 5, "alice");
    assert_eq!(by_leaf[&1].commit_size, 5, "bob");
    assert_eq!(by_leaf[&3].commit_size, 5, "dana");
    assert_eq!(by_leaf[&4].commit_size, 5, "eve");
    assert_eq!(by_leaf[&5].commit_size, 5, "frank");
    assert_eq!(by_leaf[&7].commit_size, 4, "heidi");
    assert_eq!(by_leaf[&8].commit_size, 4, "oscar");

    let min_size = infos.iter().map(|i| i.commit_size).min().unwrap();
    assert_eq!(min_size, 4);

    // The model identifies heidi and oscar as the cheapest committers.
    let best: Vec<LeafIndex> = infos
        .iter()
        .filter(|i| i.commit_size == min_size)
        .map(|i| i.leaf)
        .collect();
    assert_eq!(best, vec![LeafIndex(7), LeafIndex(8)]);

    // === Part E: check next_commit_sizes from heidi's CommitInfo ===
    //
    // After heidi self-updates, her UpdatePath re-keys tree[13], tree[11],
    // tree[7], root (all with unmerged=[]). tree[3] (unmerged=[1]) is untouched.
    // oscar's co-path drops from tree[7](res=4) to tree[7](res=1) → cost 1.
    let heidi_next: std::collections::HashMap<u32, usize> = by_leaf[&7]
        .next_commit_sizes
        .iter()
        .map(|&(l, s)| (l.0, s))
        .collect();

    assert_eq!(heidi_next[&0], 4, "alice after heidi");
    assert_eq!(heidi_next[&1], 4, "bob after heidi");
    assert_eq!(heidi_next[&3], 4, "dana after heidi");
    assert_eq!(heidi_next[&4], 5, "eve after heidi");
    assert_eq!(heidi_next[&5], 5, "frank after heidi");
    assert_eq!(heidi_next[&7], 4, "heidi after heidi");
    assert_eq!(heidi_next[&8], 1, "oscar after heidi");

    // === Part F: have heidi self-update in the real group ===
    let commit = {
        let [heidi] = group_state.members_mut(&["heidi"]);
        let bundle = heidi
            .group
            .self_update(
                &heidi.party.core_state.provider,
                &heidi.party.signer,
                LeafNodeParameters::default(),
            )
            .unwrap();
        let (commit, _, _) = bundle.into_contents();
        heidi
            .group
            .merge_pending_commit(&heidi.party.core_state.provider)
            .unwrap();
        commit
    };
    group_state
        .deliver_and_apply_if(commit.into(), |m| m.party.core_state.name != "heidi")
        .unwrap();

    // === Part G: verify real group state after heidi's commit ===
    {
        let [alice] = group_state.members_mut(&["alice"]);
        let root_unmerged_after = alice.group.treesync().root_unmerged_leaves().to_vec();
        let root_resolution_after = alice.group.treesync().root_resolution_size();
        // Heidi's UpdatePath re-keyed root with unmerged=[] — bob is no longer unmerged.
        assert!(root_unmerged_after.is_empty());
        // root resolution = 1 (no unmerged leaves).
        assert_eq!(root_resolution_after, 1);
    }

    // === Part H: verify next_commit_sizes against a fresh simulation ===
    //
    // Construct post_heidi_state: same as tree_state except the nodes on
    // heidi's direct path (tree[13], tree[11], tree[7], root) are now
    // Occupied with unmerged=[].
    let post_heidi_state = TreeState::new(
        vec![
            LeafState::Occupied, // alice   (0)
            LeafState::Occupied, // bob     (1)
            LeafState::Blank,    // charlie (2)
            LeafState::Occupied, // dana    (3)
            LeafState::Occupied, // eve     (4)
            LeafState::Occupied, // frank   (5)
            LeafState::Blank,    // grace   (6)
            LeafState::Occupied, // heidi   (7)
            LeafState::Occupied, // oscar   (8)
        ],
        vec![
            ParentState::Blank, // tree[1]  k=0
            ParentState::Occupied {
                unmerged_leaves: vec![LeafIndex(1)],
            }, // tree[3]  k=1
            ParentState::Blank, // tree[5]  k=2
            ParentState::Occupied {
                unmerged_leaves: vec![],
            }, // tree[7]  k=3 (heidi re-keyed)
            ParentState::Occupied {
                unmerged_leaves: vec![],
            }, // tree[9]  k=4
            ParentState::Occupied {
                unmerged_leaves: vec![],
            }, // tree[11] k=5 (heidi re-keyed)
            ParentState::Occupied {
                unmerged_leaves: vec![],
            }, // tree[13] k=6 (heidi re-keyed)
            ParentState::Occupied {
                unmerged_leaves: vec![],
            }, // root[15] k=7 (heidi re-keyed)
        ],
    );

    let post_heidi_infos = post_heidi_state.simulate_all_commits(&[], &[]);
    let post_heidi_by_leaf: std::collections::HashMap<u32, usize> = post_heidi_infos
        .iter()
        .map(|i| (i.leaf.0, i.commit_size))
        .collect();

    // next_commit_sizes from heidi's CommitInfo must match the fresh simulation.
    for (l, s) in &heidi_next {
        assert_eq!(
            post_heidi_by_leaf[l], *s,
            "next_commit_sizes mismatch for leaf {l}"
        );
    }
}
