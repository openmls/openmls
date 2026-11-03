//! Runs the test frameworks from the `test-utils` feature of OpenMLS in async
//! mode, as a downstream async application would.

use openmls::{
    prelude::*,
    test_utils::{
        single_group_test_framework::{AddMemberConfig, CorePartyState, GroupState},
        test_framework::{ActionType, CodecUse, MlsGroupTestSetup, noop_authentication_service},
    },
};
use openmls_rust_crypto::OpenMlsRustCrypto;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[tokio::test]
async fn test_framework_adds_updates_and_removes_members() {
    let setup = MlsGroupTestSetup::<OpenMlsRustCrypto>::new(
        MlsGroupCreateConfig::test_default(CIPHERSUITE),
        5,
        CodecUse::SerializedMessages,
    )
    .await;

    let group_id = setup
        .create_random_group(3, CIPHERSUITE, noop_authentication_service)
        .await
        .expect("create random group failed");
    // We work on a copy of the group, so that no lock guard of the setup is
    // held across an await in this test.
    let mut group = setup
        .groups
        .read()
        .expect("groups lock poisoned")
        .get(&group_id)
        .expect("group missing from setup")
        .clone();

    let (_, adder_id) = group.members().next().expect("group has no members");
    let new_members = setup
        .random_new_members_for_group(&group, 1)
        .expect("no client left to add");
    setup
        .add_clients(
            ActionType::Commit,
            &mut group,
            &adder_id,
            new_members,
            &noop_authentication_service,
        )
        .await
        .expect("add clients failed");

    let (_, updater_id) = group.members().nth(1).expect("group has no second member");
    setup
        .self_update(
            ActionType::Commit,
            &mut group,
            &updater_id,
            LeafNodeParameters::default(),
            &noop_authentication_service,
        )
        .await
        .expect("self update failed");

    let (_, remover_id) = group.members().nth(2).expect("group has no third member");
    let (target_index, _) = group.members().nth(3).expect("group has no fourth member");
    setup
        .remove_clients(
            ActionType::Commit,
            &mut group,
            &remover_id,
            &[LeafNodeIndex::new(target_index)],
            noop_authentication_service,
        )
        .await
        .expect("remove clients failed");

    assert_eq!(group.members.len(), 3);
    setup
        .check_group_states(&mut group, noop_authentication_service)
        .await;
}

#[tokio::test]
async fn single_group_test_framework_adds_members() {
    let alice_party = CorePartyState::<OpenMlsRustCrypto>::new("alice");
    let bob_party = CorePartyState::<OpenMlsRustCrypto>::new("bob");
    let charlie_party = CorePartyState::<OpenMlsRustCrypto>::new("charlie");

    let alice_pre_group = alice_party.generate_pre_group(CIPHERSUITE).await;
    let bob_pre_group = bob_party.generate_pre_group(CIPHERSUITE).await;
    let charlie_pre_group = charlie_party.generate_pre_group(CIPHERSUITE).await;

    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(CIPHERSUITE);
    let join_config = create_config.join_config().clone();

    let mut group_state = GroupState::new_from_party(
        GroupId::from_slice(b"async-test-utils"),
        alice_pre_group,
        create_config,
    )
    .await
    .expect("group creation failed");

    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group],
            join_config: join_config.clone(),
            tree: None,
        })
        .await
        .expect("alice adding bob failed");
    group_state.assert_membership();

    group_state
        .add_member(AddMemberConfig {
            adder: "bob",
            addees: vec![charlie_pre_group],
            join_config,
            tree: None,
        })
        .await
        .expect("bob adding charlie failed");
    group_state.assert_membership();

    let [alice, charlie] = group_state.members_mut(&["alice", "charlie"]);
    assert_eq!(alice.group.epoch(), charlie.group.epoch());
    assert!(charlie.get_storage_signature_key_pair().await.is_some());
}
