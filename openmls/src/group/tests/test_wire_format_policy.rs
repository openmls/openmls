//! This module tests the different values for `WireFormatPolicy`

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};

use rstest::*;
use rstest_reuse::{self, *};

use crate::{
    credentials::*,
    framing::*,
    group::{config::CryptoConfig, errors::*, *},
};

use super::utils::{generate_credential_bundle, generate_key_package};

// Creates a group with one member
fn create_group(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    wire_format_policy: WireFormatPolicy,
) -> MlsGroup {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let credential = generate_credential_bundle(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .use_ratchet_tree_extension(true)
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    MlsGroup::new_with_group_id(
        backend,
        &mls_group_config,
        group_id,
        credential.signature_key(),
    )
    .expect("An unexpected error occurred.")
}

// Takes an existing group, adds a new member and sends a message from the second member to the first one, returns that message
fn receive_message(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    alice_group: &mut MlsGroup,
) -> MlsMessageIn {
    // Generate credential bundles
    let bob_credential = generate_credential_bundle(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let bob_key_package = generate_key_package(
        &[ciphersuite],
        &bob_credential,
        Extensions::empty(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let (_message, welcome, _group_info) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(alice_group.configuration().wire_format_policy())
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome.into_welcome().expect("Unexpected message type."),
        None,
    )
    .expect("error creating bob's group from welcome");

    let (message, _welcome, _group_info) = bob_group
        .self_update(backend, None)
        .expect("An unexpected error occurred.");
    message.into()
}

// Test positive cases with all valid (pure & mixed) policies
#[apply(ciphersuites_and_backends)]
fn test_wire_policy_positive(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for wire_format_policy in WIRE_FORMAT_POLICIES.iter() {
        let mut alice_group = create_group(ciphersuite, backend, *wire_format_policy);
        let message = receive_message(ciphersuite, backend, &mut alice_group);
        alice_group
            .process_message(backend, message)
            .expect("An unexpected error occurred.");
    }
}

// Test negative cases with only icompatible policies
#[apply(ciphersuites_and_backends)]
fn test_wire_policy_negative(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
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
        let mut alice_group = create_group(ciphersuite, backend, wire_format_policy);
        let message = receive_message(ciphersuite, backend, &mut alice_group);
        let err = alice_group
            .process_message(backend, message)
            .expect_err("An unexpected error occurred.");
        assert_eq!(err, ProcessMessageError::IncompatibleWireFormat);
    }
}
