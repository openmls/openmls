use super::utils::{generate_credential_bundle, generate_key_package};
use crate::{
    credentials::*,
    group::{config::CryptoConfig, *},
    test_utils::*,
    *,
};

#[apply(ciphersuites_and_backends)]
fn three_members(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let bob_credential = generate_credential_bundle(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let charlie_credential = generate_credential_bundle(
        "Charlie".into(),
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
    let charlie_key_package = generate_key_package(
        &[ciphersuite],
        &charlie_credential,
        Extensions::empty(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfigBuilder::new()
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &mls_group_config,
        group_id.clone(),
        alice_credential.signature_key(),
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob & Charlie ===

    let (_message, welcome, _group_info) = alice_group
        .add_members(backend, &[bob_key_package, charlie_key_package])
        .expect("An unexpected error occurred.");
    alice_group
        .merge_pending_commit(backend)
        .expect("error merging pending commit");

    let welcome = welcome.into_welcome().expect("Unexpected message type.");

    // === Bob and Charlie create their groups ===

    let bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome.clone(),
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    let charlie_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    // === Check that the groups have the same order of members ===

    assert_eq!(
        alice_group.own_leaf_index(),
        alice_group
            .members()
            .find(|m| &m.identity == b"Alice")
            .unwrap()
            .index
            .into()
    );
    assert_eq!(
        bob_group.own_leaf_index(),
        alice_group
            .members()
            .find(|m| &m.identity == b"Bob")
            .unwrap()
            .index
            .into()
    );
    assert_eq!(
        charlie_group.own_leaf_index(),
        alice_group
            .members()
            .find(|m| &m.identity == b"Charlie")
            .unwrap()
            .index
            .into()
    );
}
