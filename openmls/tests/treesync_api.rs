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
