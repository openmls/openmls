//! Tests for CommitBuilder leaf node validation against required capabilities.

use openmls_test::openmls_test;

use crate::{
    extensions::{Extension, ExtensionType, Extensions, RequiredCapabilitiesExtension},
    group::{
        errors::CreateCommitError, GroupId, MlsGroupCreateConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    prelude::{LeafNodeParameters, UnknownExtension},
    test_utils::single_group_test_framework::{
        AddMemberConfig, CorePartyState, GroupError, GroupState,
    },
    treesync::{errors::LeafNodeValidationError, node::leaf_node::Capabilities},
};

/// Test that building a commit with a leaf node that doesn't support required extensions fails.
///
/// This test verifies the validation added at commit build time (valn0103):
/// 1. Create Alice and Bob with capabilities supporting extension `0xf001`
/// 2. Alice creates a group with `RequiredCapabilitiesExtension` requiring `0xf001`
/// 3. Alice adds Bob to the group
/// 4. Alice uses `CommitBuilder` with `force_self_update(true)` and `leaf_node_parameters`
///    that have capabilities NOT supporting `0xf001`
/// 5. Alice's `build_commit_and_stage()` fails with the appropriate error
#[openmls_test]
fn commit_builder_fails_when_leaf_node_capabilities_insufficient_required_capabilities() {
    // Create parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    // Create capabilities that support the required extension
    let supporting_caps = Capabilities::builder()
        .extensions(vec![ExtensionType::Unknown(0xf001)])
        .build();

    // Generate pre-group states with supporting capabilities
    let alice_pre_group = alice_party
        .pre_group_builder(ciphersuite)
        .with_leaf_node_capabilities(supporting_caps.clone())
        .build();
    let bob_pre_group = bob_party
        .pre_group_builder(ciphersuite)
        .with_leaf_node_capabilities(supporting_caps.clone())
        .build();

    // Create group with required capabilities
    let required_caps =
        RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf001)], &[], &[]);
    let gc_extensions = Extensions::single(Extension::RequiredCapabilities(required_caps))
        .expect("required capabilities extension should be considered valid in group context");

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .with_group_context_extensions(gc_extensions)
        .capabilities(supporting_caps.clone())
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let join_config = create_config.join_config().clone();

    // Initialize group with Alice
    let group_id = GroupId::from_slice(b"test-commit-builder-validation");
    let mut group_state =
        GroupState::new_from_party(group_id, alice_pre_group, create_config).unwrap();

    // Add Bob to the group
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group],
            join_config,
            tree: None,
        })
        .expect("Could not add member");

    // Create bad capabilities (without the required extension)
    let bad_caps = Capabilities::builder().build(); // No extensions supported
    let bad_params = LeafNodeParameters::builder()
        .with_capabilities(bad_caps)
        .build();

    // Build should FAIL due to validation
    let [alice] = group_state.members_mut(&["alice"]);
    let err = alice
        .build_commit_and_stage(|builder| {
            builder
                .force_self_update(true)
                .leaf_node_parameters(bad_params)
        })
        .expect_err("build should fail due to unsupported capabilities");

    // Match the correct error type
    assert!(
        matches!(
            err,
            GroupError::<Provider>::CreateCommit(CreateCommitError::LeafNodeValidation(
                LeafNodeValidationError::UnsupportedExtensions
            ))
        ),
        "Expected UnsupportedExtensions error, got {:?}",
        err
    );
}

/// Test that building a commit with a leaf node that doesn't support one of the group context
/// extensions fails.
///
/// This test verifies the validation added at commit build time (valn0103):
/// 1. Create Alice and Bob with capabilities supporting extension `0xf001`
/// 2. Alice creates a group with GroupContextExtension of type `0xf001`
/// 3. Alice adds Bob to the group
/// 4. Alice uses `CommitBuilder` with `force_self_update(true)` and `leaf_node_parameters`
///    that have capabilities NOT supporting `0xf001`
/// 5. Alice's `build_commit_and_stage()` fails with the appropriate error
#[openmls_test]
fn commit_builder_fails_when_leaf_node_capabilities_insufficient() {
    // Create parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    // Create capabilities that support the required extension
    let supporting_caps = Capabilities::builder()
        .extensions(vec![ExtensionType::Unknown(0xf001)])
        .build();

    // Generate pre-group states with supporting capabilities
    let alice_pre_group = alice_party
        .pre_group_builder(ciphersuite)
        .with_leaf_node_capabilities(supporting_caps.clone())
        .build();
    let bob_pre_group = bob_party
        .pre_group_builder(ciphersuite)
        .with_leaf_node_capabilities(supporting_caps.clone())
        .build();

    // Create group with the custom extension
    let custom_extension = UnknownExtension(b"any gce must be supported".to_vec());
    let gc_extensions = Extensions::single(Extension::Unknown(0xf001, custom_extension))
        .expect("unknown extensions should be considered valid in group context");

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .with_group_context_extensions(gc_extensions)
        .capabilities(supporting_caps.clone())
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let join_config = create_config.join_config().clone();

    // Initialize group with Alice
    let group_id = GroupId::from_slice(b"test-commit-builder-validation");
    let mut group_state =
        GroupState::new_from_party(group_id, alice_pre_group, create_config).unwrap();

    // Add Bob to the group
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group],
            join_config,
            tree: None,
        })
        .expect("Could not add member");

    // Create bad capabilities (without the required extension)
    let bad_caps = Capabilities::builder().build(); // No extensions supported
    let bad_params = LeafNodeParameters::builder()
        .with_capabilities(bad_caps)
        .build();

    // Build should FAIL due to validation
    let [alice] = group_state.members_mut(&["alice"]);
    let err = alice
        .build_commit_and_stage(|builder| {
            builder
                .force_self_update(true)
                .leaf_node_parameters(bad_params)
        })
        .expect_err("build should fail due to unsupported capabilities");

    // Match the correct error type
    assert!(
        matches!(
            err,
            GroupError::<Provider>::CreateCommit(CreateCommitError::LeafNodeValidation(
                LeafNodeValidationError::UnsupportedExtensions
            ))
        ),
        "Expected UnsupportedExtensions error, got {:?}",
        err
    );
}
