use std::{
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use openmls::{prelude::*, test_utils::single_group_test_framework::*};
use openmls_test::openmls_test;

#[openmls_test]
fn join_tree_with_outdated_leafnodes() {
    let setup = || {
        // The validity of the key package into the future.
        // This has to be short to keep the test run fast, but not too short to produce
        // failing tests.
        const VALIDITY: u64 = 2;

        let alice_party = CorePartyState::<Provider>::new("alice");
        let bob_party = CorePartyState::<Provider>::new("bob");
        let charlie_party = CorePartyState::<Provider>::new("charlie");

        // Create group
        let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
        let join_config = create_config.join_config().clone();
        let mut group_state = {
            let group_id = GroupId::from_slice(b"Test Group");

            let group_state = GroupState::new_from_party(
                group_id,
                alice_party.generate_pre_group(ciphersuite),
                create_config,
            )
            .unwrap();
            group_state
        };

        // Create Charlie key package
        let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
        let charlie_key_package = charlie_pre_group.key_package_bundle.key_package().clone();

        // Generate a key package for Bob that is outdated when inviting Charlie.
        // This test assumes that the setup goes through within VALIDITY seconds.
        // After that the key package is invalid already.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH!")
            .as_secs();
        let bob_pre_group = bob_party
            .pre_group_builder(ciphersuite)
            .with_lifetime(Lifetime::init(now - 60, now + VALIDITY))
            .build();
        let bob_key_package = bob_pre_group.key_package_bundle.key_package().clone();

        let [alice] = group_state.members_mut(&["alice"]);

        // Alice adds Bob
        let (_mls_message_out, _welcome, _group_info) = alice
            .group
            .add_members(
                &alice_party.provider,
                &alice.party.signer,
                &[bob_key_package],
            )
            .expect("Could not add Bob.");

        alice
            .group
            .merge_pending_commit(&alice_party.provider)
            .unwrap();

        // We don't care about Bob actually processing the Welcome.
        // Let's wait for VALIDITY seconds to ensure that the leaf node is invalid.
        thread::sleep(Duration::from_secs(VALIDITY));

        // Alice adds Charlie
        // At this point Bob's key package is outdated in the tree.
        let (_mls_message_out, welcome, _group_info) = alice
            .group
            .add_members(
                &alice_party.provider,
                &alice.party.signer,
                &[charlie_key_package],
            )
            .expect("Could not add Charlie.");

        alice
            .group
            .merge_pending_commit(&alice_party.provider)
            .unwrap();

        (welcome, charlie_party, join_config)
    };

    let (welcome, charlie_party, join_config) = setup();

    // Charlie tries to join the group
    // Here joining fails because the lifetimes are validated.
    let _error = StagedWelcome::build_from_welcome(
        &charlie_party.provider,
        &join_config,
        MlsMessageIn::from(welcome).into_welcome().unwrap(),
    )
    .unwrap()
    .build()
    .expect_err("Created group even if this should've failed.");

    let (welcome, charlie_party, join_config) = setup();

    let _error = StagedWelcome::new_from_welcome(
        &charlie_party.provider,
        &join_config,
        MlsMessageIn::from(welcome).into_welcome().unwrap(),
        None,
    )
    .expect_err("Created group even if this should've failed.");

    let (welcome, charlie_party, join_config) = setup();

    // Charlie tries to join the group
    // Here joining should succeed because lifetimes aren't validated.
    let _charlie_group = StagedWelcome::build_from_welcome(
        &charlie_party.provider,
        &join_config,
        MlsMessageIn::from(welcome).into_welcome().unwrap(),
    )
    .unwrap()
    .skip_lifetime_validation()
    .build()
    .expect("Failed to create group due to an invalid lifetime in a leaf node in the tree.")
    .into_group(&charlie_party.provider)
    .unwrap();
}
