use openmls::{prelude::*, test_utils::single_group_test_framework::*};
use openmls_test::openmls_test;
use openmls_tree_health::tree_state::{CommitInfo, LeafIndex, LeafState, ParentState, TreeState};
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

/// 4-leaf group: alice=0, bob=1, charlie=2, dana=3.
///
/// Alice adds all three others with a full commit (force_self_update=true).
/// Alice's UpdatePath clears the root's unmerged_leaves per RFC §7.8.
/// Then bob, charlie, and dana each self-update, which also doesn't change
/// the fact the root is already fully merged.
///
/// After all self-updates:
///   root.unmerged_leaves = []
///   actual root resolution = 1
///   hypothetical size for every leaf = 1
#[openmls_test]
fn actual_and_model_agree_when_fully_merged() {
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
        GroupId::from_slice(b"tree-health actual-vs-model-merged"),
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

    // Each new member self-updates, clearing the root's unmerged list.
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

    let (actual_size, root_unmerged, remaining_leaves) = {
        let [alice] = group_state.members_mut(&["alice"]);
        let actual_size = alice.group.treesync().root_resolution_size();
        let root_unmerged = alice.group.treesync().root_unmerged_leaves().to_vec();
        let remaining_leaves: Vec<LeafNodeIndex> = alice
            .group
            .treesync()
            .full_leaves()
            .map(|(idx, _)| idx)
            .collect();
        (actual_size, root_unmerged, remaining_leaves)
    };

    // Tree is fully merged: no unmerged leaves remain.
    assert!(root_unmerged.is_empty());

    // Actual root resolution is 1 (just the root itself).
    assert_eq!(actual_size, 1);

    // Every remaining leaf has hypothetical size 1 — no self-update can help.
    for &leaf in &remaining_leaves {
        assert_eq!(hypothetical_root_resolution_size(leaf, &root_unmerged), 1);
    }
}

/// Reproduces the ratchet tree from RFC 9420 Figure 10.
///
/// The figure shows a subtree of a larger group.  We map A..H to leaves 0..7
/// and add one outside member (oscar, leaf 8) so that the node covering leaves
/// 0..7 (tree index 7) is an *intermediate* node, not the root.
///
/// ```text
///                        root (non-blank, unmerged=[B=1])
///                       /                       \
///                 _ (blank)                   oscar-side
///              /           \
///         X[B] (tree[3])    _ (blank, tree[11])
///         /    \             /          \
///   _ (tree[1]) _ (tree[5])  Y (tree[9])  _ (tree[13])
///    /  \        /  \        /  \          /  \
///   A    B      _    D      E    F        _    H
///  (0)  (1)    (2)  (3)   (4)  (5)      (6)  (7)
/// ```
///
/// Operations per RFC 9420 Appendix A:
///
/// 1. A (alice) creates the group with B..H and oscar.
///
/// 2. F (frank) sends a self-update Commit, setting Y (tree[9]) and its
///    ancestors tree[11], tree[7], and root.
///
/// 3. D (dana) removes B (leaf 1) and C (leaf 2) in one Commit.
///    - The Remove proposals blank B's and C's direct paths, including tree[7].
///    - D's UpdatePath re-sets X (tree[3]), tree[7], and root.
///    - tree[5] is filtered out because C's leaf is blank.
///    - tree[1] is NOT on D's direct path and stays blank.
///
/// 4. Oscar removes G (grace, leaf 6).
///    - The Remove proposal blanks G's direct path: tree[13], tree[11],
///      tree[7], and root.
///    - Oscar's UpdatePath covers tree[23] (oscar-side) and root — it does
///      NOT pass through tree[7], which stays blank.
///
/// 5. A (alice) re-adds a new member at B's slot using a *partial* Commit
///    (no UpdatePath).  A Commit with only Add proposals does not require a
///    path; the builder omits the UpdatePath.
///    - New-B is added as unmerged only at the non-blank ancestors of leaf 1:
///      X (tree[3]) and root.  tree[1] and tree[7] are blank and skipped.
///
/// Final state:  root.unmerged_leaves = [B = leaf 1].
///
/// B is the unique best self-update candidate: its hypothetical root
/// resolution size is 1, versus 2 for every other remaining leaf.
#[openmls_test]
fn figure10_unmerged_leaf_candidate() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    // Fresh party for the re-added bob: its storage has no prior group state,
    // so deliver_and_apply_welcome won't hit GroupAlreadyExists.
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
        GroupId::from_slice(b"tree-health rfc9420-figure10"),
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

    // Step 2: frank self-updates, setting Y (tree[9]) and its ancestors
    // tree[11], tree[7], and root.
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

    // Step 3: dana removes bob (leaf 1) and charlie (leaf 2) in one Commit.
    // The Remove proposals blank their direct paths (including tree[7] and root).
    // Dana's UpdatePath re-sets X (tree[3]), tree[7], and root; tree[5] is
    // filtered out because charlie's leaf (2) is blank.  tree[1] stays blank.
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
    // The Remove proposal blanks grace's direct path (tree[13], tree[11],
    // tree[7], root).  Oscar's UpdatePath covers tree[23] and root on oscar's
    // side of the full tree and does NOT reach tree[7], so tree[7] stays blank.
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

    // Step 5: alice re-adds bob using a *partial* Commit (no UpdatePath).
    // CommitBuilder::propose_adds embeds the Add proposal by value; because
    // there are no Remove/Update proposals, path_required is false and the
    // builder omits the UpdatePath.
    // New-bob (at leaf 1, the leftmost blank slot) is added as unmerged only
    // at the non-blank ancestors of leaf 1: X (tree[3]) and root.
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

    // Query the tree state from alice's perspective.
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

    // Figure 10: root.unmerged_leaves = [B = leaf 1].
    assert_eq!(root_unmerged, vec![LeafNodeIndex::new(1)]);

    // Compute hypothetical root resolution sizes for all remaining leaves.
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

    // B (leaf 1) is the unique best candidate: size 1 vs 2 for all others.
    assert_eq!(min_size, 1);
    assert_eq!(best_candidates, vec![LeafNodeIndex::new(1)]);
}

/// Same RFC 9420 Figure 10 setup as `figure10_unmerged_leaf_candidate`, but
/// also validates the actual root resolution size (via `root_resolution_size`)
/// against the model predictions.
///
/// After all five steps:
///   root.unmerged_leaves = [B = leaf 1]
///   actual root resolution = 2  (root + bob unmerged)
///
/// The tree has blank intermediate nodes (tree[1], tree[7], tree[11],
/// tree[13]), so this also exercises the recursive RFC §4.1.1 logic reaching
/// the same answer as the simple `1 + |unmerged_leaves|` formula.
///
/// Model predictions:
///   bob(1): in unmerged list → hypothetical size = 1 (best)
///   all others:              → hypothetical size = 2
///   min_size = actual - 1 = 1
#[openmls_test]
fn actual_and_model_agree_figure10() {
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
        GroupId::from_slice(b"tree-health rfc9420-figure10-actual"),
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

    // Query the tree state from alice's perspective.
    let (actual_size, root_unmerged, remaining_leaves) = {
        let [alice] = group_state.members_mut(&["alice"]);
        let actual_size = alice.group.treesync().root_resolution_size();
        let root_unmerged = alice.group.treesync().root_unmerged_leaves().to_vec();
        let remaining_leaves: Vec<LeafNodeIndex> = alice
            .group
            .treesync()
            .full_leaves()
            .map(|(idx, _)| idx)
            .collect();
        (actual_size, root_unmerged, remaining_leaves)
    };

    // Figure 10: root.unmerged_leaves = [B = leaf 1].
    assert_eq!(root_unmerged, vec![LeafNodeIndex::new(1)]);

    // Actual root resolution = 2 (root + bob unmerged).
    assert_eq!(actual_size, 2);

    // bob(1) is the unique best candidate with hypothetical size 1.
    assert_eq!(
        hypothetical_root_resolution_size(LeafNodeIndex::new(1), &root_unmerged),
        1
    );

    // All other remaining leaves have hypothetical size 2.
    for &leaf in remaining_leaves
        .iter()
        .filter(|&&l| l != LeafNodeIndex::new(1))
    {
        assert_eq!(hypothetical_root_resolution_size(leaf, &root_unmerged), 2);
    }

    // Compute min size across all remaining leaves.
    let min_size = remaining_leaves
        .iter()
        .map(|&leaf| hypothetical_root_resolution_size(leaf, &root_unmerged))
        .min()
        .unwrap();

    // The best candidate reduces the actual root resolution by exactly 1.
    assert_eq!(min_size, actual_size - 1);
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
