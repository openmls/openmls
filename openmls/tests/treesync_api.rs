use openmls::{prelude::*, test_utils::single_group_test_framework::*};
use openmls_test::openmls_test;

#[openmls_test]
fn treesync_leaf_credentials() {
    // 1. Create parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);

    // 2. Alice creates a group
    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let join_config = create_config.join_config().clone();

    let mut group_state = GroupState::new_from_party(
        GroupId::from_slice(b"treesync test"),
        alice_pre_group,
        create_config,
    )
    .unwrap();

    // 3. Alice adds Bob
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group],
            join_config,
            tree: None,
        })
        .unwrap();

    // 4. Bob inspects the tree
    let [bob] = group_state.members_mut(&["bob"]);
    let leaves: Vec<_> = bob.group.treesync().full_leaves().collect();

    // 5. Assert two members at the expected indices
    assert_eq!(leaves.len(), 2);

    let (alice_index, alice_leaf) = &leaves[0];
    let (bob_index, bob_leaf) = &leaves[1];

    assert_eq!(alice_index.u32(), 0);
    assert_eq!(bob_index.u32(), 1);

    // 6. Check credentials
    let alice_cred: BasicCredential = alice_leaf.credential().clone().try_into().unwrap();
    assert_eq!(alice_cred.identity(), b"alice");

    let bob_cred: BasicCredential = bob_leaf.credential().clone().try_into().unwrap();
    assert_eq!(bob_cred.identity(), b"bob");

    // 7. Inspect the intermediate (parent) nodes.
    // A 2-leaf binary tree has exactly 1 parent node (the root), at index 0.
    let parents: Vec<_> = bob.group.treesync().full_parents().collect();
    assert_eq!(parents.len(), 1);

    let (root_index, _root_node) = &parents[0];
    assert_eq!(root_index.u32(), 0);
}

#[openmls_test]
fn treesync_blanks_after_remove() {
    // 1. Create parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");
    let dana_party = CorePartyState::<Provider>::new("dana");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
    let dana_pre_group = dana_party.generate_pre_group(ciphersuite);

    // 2. Alice creates the group and adds bob, charlie, dana in one commit.
    //    Leaf indices will be: alice=0, bob=1, charlie=2, dana=3.
    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let join_config = create_config.join_config().clone();

    let mut group_state = GroupState::new_from_party(
        GroupId::from_slice(b"treesync blanks test"),
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

    // 3. Alice removes Bob (leaf index 1) with an update_path.
    //    Use a block so the alice borrow is dropped before deliver_and_apply_if.
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

    // Deliver to charlie and dana only; alice has already merged, bob is removed.
    group_state
        .deliver_and_apply_if(commit.into(), |member| {
            matches!(member.party.core_state.name, "charlie" | "dana")
        })
        .unwrap();

    // 4. Charlie inspects the tree.
    let [charlie] = group_state.members_mut(&["charlie"]);
    let treesync = charlie.group.treesync();

    // 5. The 4-leaf tree looks like:
    //
    //           P1/root (ParentNodeIndex 1)
    //          /                           \
    //   P0 (ParentNodeIndex 0)       P2 (ParentNodeIndex 2)
    //   /            \               /               \
    // L0(alice)   L1(bob)       L2(charlie)       L3(dana)
    //
    // P2 was never given a key: when Alice added Bob/Charlie/Dana in one
    // commit, her filtered direct path was [P0, P1] only (P2's resolution at
    // that time was {charlie, dana} — non-empty — but P2 was the *copath* of
    // P1, not a direct-path node, so it was never written).
    //
    // After Alice removes Bob (L1) with an update_path:
    //   - L1 is blanked.
    //   - blank_leaf(L1) also blanks L1's full direct path [P0, P1].
    //   - Alice's filtered direct path: P0's copath is the now-blank L1
    //     (empty resolution → P0 filtered out), leaving only [P1].
    //   - The update_path re-fills P1.
    //   - P0 stays blank (its copath was the removed member).
    //   - P2 stays blank (was never set).

    let blank_leaves: Vec<_> = treesync.blank_leaves().collect();
    assert_eq!(blank_leaves.len(), 1, "blank leaves: {blank_leaves:?}");
    assert_eq!(blank_leaves[0].u32(), 1); // Bob's slot

    let blank_parents: Vec<_> = treesync.blank_parents().collect();
    assert_eq!(blank_parents.len(), 2, "blank parents: {blank_parents:?}");
    assert_eq!(blank_parents[0].u32(), 0); // P0 — copath was the removed Bob
    assert_eq!(blank_parents[1].u32(), 2); // P2 — never written by any update_path
}
