//! This module tests the different values for `WireFormatPolicy`

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{signatures::Signer, types::Ciphersuite, OpenMlsProvider};

use rstest::*;
use rstest_reuse::{self, *};

use crate::{
    framing::*,
    group::{config::CryptoConfig, *},
};

use super::utils::{
    generate_credential_with_key, generate_key_package, CredentialWithKeyAndSigner,
};

// Creates a group with one member
fn create_group(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
    wire_format_policy: WireFormatPolicy,
) -> (MlsGroup, CredentialWithKeyAndSigner) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credentials with keys
    let credential_with_key_and_signer =
        generate_credential_with_key("Alice".into(), ciphersuite.signature_algorithm(), provider);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .use_ratchet_tree_extension(true)
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
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
    provider: &impl OpenMlsProvider,
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
        .add_members(provider, alice_signer, &[bob_key_package])
        .expect("Could not add member.");

    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(alice_group.configuration().wire_format_policy())
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    let mut bob_group = MlsGroup::new_from_welcome(
        provider,
        &mls_group_config,
        welcome.into_welcome().expect("Unexpected message type."),
        None,
    )
    .expect("error creating bob's group from welcome");

    let (message, _welcome, _group_info) = bob_group
        .self_update(provider, &bob_credential_with_key_and_signer.signer)
        .expect("An unexpected error occurred.");
    message.into()
}

// Test positive cases with all valid (pure & mixed) policies
#[apply(ciphersuites_and_providers)]
fn test_wire_policy_positive(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
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
            .process_message(provider, message)
            .expect("An unexpected error occurred.");
    }
}

// Test negative cases with only icompatible policies
#[apply(ciphersuites_and_providers)]
fn test_wire_policy_negative(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
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
            .process_message(provider, message)
            .expect_err("An unexpected error occurred.");
        assert_eq!(err, ProcessMessageError::IncompatibleWireFormat);
    }
}
