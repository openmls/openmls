//! This module tests the different values for `WireFormatPolicy`

use openmls_traits::{signatures::Signer, types::Ciphersuite};

use crate::{framing::*, group::*, treesync::LeafNodeParameters};

use crate::group::tests_and_kats::utils::{
    generate_credential_with_key, generate_key_package, CredentialWithKeyAndSigner,
};

// Creates a group with one member
fn create_group(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
    wire_format_policy: WireFormatPolicy,
) -> (MlsGroup, CredentialWithKeyAndSigner) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credentials with keys
    let credential_with_key_and_signer =
        generate_credential_with_key("Alice".into(), ciphersuite.signature_algorithm(), provider);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(wire_format_policy)
        .use_ratchet_tree_extension(true)
        .ciphersuite(ciphersuite)
        .build();

    (
        MlsGroup::new_with_group_id(
            provider,
            &credential_with_key_and_signer.signer,
            &mls_group_config,
            group_id,
            credential_with_key_and_signer.credential_with_key.clone(),
        )
        .expect("An unexpected error occurred."),
        credential_with_key_and_signer,
    )
}

// Takes an existing group, adds a new member and sends a message from the second member to the first one, returns that message
fn receive_message(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
    alice_group: &mut MlsGroup,
    alice_signer: &impl Signer,
) -> MlsMessageIn {
    // Generate credentials with keys
    let bob_credential_with_key_and_signer =
        generate_credential_with_key("Bob".into(), ciphersuite.signature_algorithm(), provider);

    // Generate KeyPackages
    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        provider,
        bob_credential_with_key_and_signer.clone(),
    );

    let (_message, welcome, _group_info) = alice_group
        .add_members(
            provider,
            alice_signer,
            &[bob_key_package.key_package().clone()],
        )
        .expect("Could not add member.");

    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    let mls_group_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(alice_group.configuration().wire_format_policy())
        .build();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let mut bob_group = StagedWelcome::new_from_welcome(provider, &mls_group_config, welcome, None)
        .expect("error creating bob's staged join from welcome")
        .into_group(provider)
        .expect("error creating bob's group from staged join");

    let (message, _welcome, _group_info) = bob_group
        .self_update(
            provider,
            &bob_credential_with_key_and_signer.signer,
            LeafNodeParameters::default(),
        )
        .expect("An unexpected error occurred.")
        .into_contents();
    message.into()
}

// Test positive cases with all valid (pure & mixed) policies
#[openmls_test::openmls_test]
fn test_wire_policy_positive(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    for wire_format_policy in WIRE_FORMAT_POLICIES.iter() {
        let (mut alice_group, alice_credential_with_key_and_signer) =
            create_group(ciphersuite, provider, *wire_format_policy);
        let message = receive_message(
            ciphersuite,
            provider,
            &mut alice_group,
            &alice_credential_with_key_and_signer.signer,
        );
        alice_group
            .process_message(provider, message.try_into_protocol_message().unwrap())
            .expect("An unexpected error occurred.");
    }
}

// Test negative cases with only icompatible policies
#[openmls_test::openmls_test]
fn test_wire_policy_negative(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // All combinations that are not part of WIRE_FORMAT_POLICIES
    let incompatible_policies = vec![
        WireFormatPolicy::new(
            OutgoingWireFormatPolicy::AlwaysPlaintext,
            IncomingWireFormatPolicy::AlwaysCiphertext,
        ),
        WireFormatPolicy::new(
            OutgoingWireFormatPolicy::AlwaysCiphertext,
            IncomingWireFormatPolicy::AlwaysPlaintext,
        ),
    ];
    for wire_format_policy in incompatible_policies.into_iter() {
        let (mut alice_group, alice_credential_with_key_and_signer) =
            create_group(ciphersuite, provider, wire_format_policy);
        let message = receive_message(
            ciphersuite,
            provider,
            &mut alice_group,
            &alice_credential_with_key_and_signer.signer,
        );
        let err = alice_group
            .process_message(provider, message.try_into_protocol_message().unwrap())
            .expect_err("An unexpected error occurred.");
        assert!(matches!(err, ProcessMessageError::IncompatibleWireFormat));
    }
}
