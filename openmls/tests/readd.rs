use openmls::{prelude::*, test_utils::single_group_test_framework::*};
use openmls_test::openmls_test;

#[openmls_test]
fn swap() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");
    let yuk_party = CorePartyState::<Provider>::new("yuk");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
    let yuk_pre_group = yuk_party.generate_pre_group(ciphersuite);

    let group_id = GroupId::from_slice(b"Test Group");

    // Define the MlsGroup configuration
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();

    let mut group_state =
        GroupState::new_from_party(group_id.clone(), alice_pre_group, group_config.clone())
            .unwrap();

    // Generate KeyPackages
    let bob_key_package = bob_pre_group.key_package_bundle.key_package().clone();
    let charlie_key_package = charlie_pre_group.key_package_bundle.key_package().clone();
    let yuk_key_package = yuk_pre_group.key_package_bundle.key_package().clone();

    let [alice] = group_state.members_mut(&["alice"]);

    // === Alice adds Bob ===
    let (_commit, welcome, _group_info) = alice
        .group
        .add_members(
            &alice_party.provider,
            &alice.party.signer,
            &[bob_key_package, charlie_key_package, yuk_key_package],
        )
        .expect("Could not add folks");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome.into_welcome().unwrap();

    // Bob
    let staged_join = StagedWelcome::new_from_welcome(
        &bob_party.provider,
        group_config.join_config(),
        welcome.clone(),
        None,
    )
    .expect("Error constructing staged join");
    let mut bob_group = staged_join
        .into_group(&bob_party.provider)
        .expect("Error joining group from StagedWelcome");

    // Charlie
    let staged_join = StagedWelcome::new_from_welcome(
        &charlie_party.provider,
        group_config.join_config(),
        welcome.clone(),
        None,
    )
    .expect("Error constructing staged join");

    let _charlie_group = staged_join
        .into_group(&charlie_party.provider)
        .expect("Error joining group from StagedWelcome");

    // Yuk
    let staged_join = StagedWelcome::new_from_welcome(
        &yuk_party.provider,
        group_config.join_config(),
        welcome.clone(),
        None,
    )
    .expect("Error constructing staged join");

    let mut yuk_group = staged_join
        .into_group(&yuk_party.provider)
        .expect("Error joining group from StagedWelcome");

    // Bob re-adds alice and yuk
    let alice_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            &alice_party.provider,
            &alice.party.signer,
            alice.party.credential_with_key.clone(),
        )
        .unwrap();
    let yuk_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            &yuk_party.provider,
            &yuk_pre_group.signer,
            yuk_pre_group.credential_with_key.clone(),
        )
        .unwrap();

    let commit_messages = bob_group
        .swap_members(
            &bob_party.provider,
            &bob_pre_group.signer,
            &[
                LeafNodeIndex::new(0), /*Alice */
                LeafNodeIndex::new(3), /*Yuk */
            ],
            &[
                // This is the wrong order, but we ask the function to order.
                yuk_key_package.key_package().clone(),
                alice_key_package.key_package().clone(),
            ],
        )
        .unwrap();
    bob_group.merge_pending_commit(&bob_party.provider).unwrap();

    let welcome: MlsMessageIn = commit_messages.welcome.into();
    let welcome = welcome.into_welcome().unwrap();

    // New Yuk
    yuk_group.delete(yuk_party.provider.storage()).unwrap();
    let staged_join = StagedWelcome::new_from_welcome(
        &yuk_party.provider,
        group_config.join_config(),
        welcome.clone(),
        None,
    )
    .expect("Error constructing staged join");

    let yuk_group = staged_join
        .into_group(&yuk_party.provider)
        .expect("Error joining group from StagedWelcome");

    alice.group.delete(alice_party.provider.storage()).unwrap();

    // New Alice
    let staged_join = StagedWelcome::new_from_welcome(
        &alice_party.provider,
        group_config.join_config(),
        welcome.clone(),
        None,
    )
    .expect("Error constructing staged join");

    let alice_group = staged_join
        .into_group(&alice_party.provider)
        .expect("Error joining group from StagedWelcome");

    // Yuk and Alice are back in.
    assert_eq!(alice_group.confirmation_tag(), bob_group.confirmation_tag());
    assert_eq!(yuk_group.confirmation_tag(), bob_group.confirmation_tag());
}
