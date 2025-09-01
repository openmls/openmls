//! Test to reproduce the persistence bug in External Commits
//! This test verifies that own_leaf_index and join_group_config are correctly persisted
//! after an external commit.

use crate::group::{
    tests_and_kats::utils::generate_credential_with_key, MlsGroup, MlsGroupCreateConfig,
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
};

// Test to reproduce the external commit persistence bug
#[openmls_test::openmls_test]
fn external_commit_persistence() {
    // Separate providers for Alice and Bob (distinct storage spaces)
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Generate credentials
    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let bob_credential = generate_credential_with_key(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    // Group configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .build();

    // Alice creates a group
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_credential.signer,
        &mls_group_create_config,
        alice_credential.credential_with_key.clone(),
    )
    .unwrap();

    // Get group information for the external commit
    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_credential.signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let tree_option = alice_group.export_ratchet_tree();

    // Bob performs an external commit
    let (bob_group, _public_message_commit) = MlsGroup::external_commit_builder()
        .with_config(alice_group.configuration().clone())
        .with_ratchet_tree(tree_option.into())
        .build_group(
            bob_provider,
            verifiable_group_info,
            bob_credential.credential_with_key.clone(),
        )
        .unwrap()
        .load_psks(bob_provider.storage())
        .unwrap()
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_credential.signer,
            |_| true,
        )
        .unwrap()
        .finalize(bob_provider)
        .unwrap();

    // Verify that Bob has a valid own_leaf_index (it must be >= 0)
    let _idx = bob_group.own_leaf_index();

    // Save the group ID and Bob's index
    let group_id = bob_group.group_id().clone();
    let expected_own_leaf_index = bob_group.own_leaf_index();
    let expected_join_config = bob_group.configuration().clone();

    // Simulate memory loss (drop the group)
    drop(bob_group);

    // Attempt to reload the group from storage
    let reloaded_group = MlsGroup::load(bob_provider.storage(), &group_id);

    // The group should be reloadable
    assert!(reloaded_group.is_ok(), "Group should be loadable after external commit");
    let reloaded_group = reloaded_group.unwrap();
    assert!(reloaded_group.is_some(), "Group should exist in storage");

    let reloaded_group = reloaded_group.unwrap();

    // Verify that own_leaf_index is properly persisted
    assert_eq!(
        reloaded_group.own_leaf_index(),
        expected_own_leaf_index,
        "own_leaf_index should be persisted and match the original value"
    );

    // Verify that the group configuration is properly persisted
    assert_eq!(
        reloaded_group.configuration(),
        &expected_join_config,
        "join_group_config should be persisted and match the original value"
    );

    println!("✅ Test passed: External commit persistence works correctly");
}
