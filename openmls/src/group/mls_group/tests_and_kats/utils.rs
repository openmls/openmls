//! Test utilities for (MLS group) tests.

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::HpkeCiphertext;

use crate::{credentials::*, group::*, key_packages::*, test_utils::*};

pub(crate) fn setup_alice_group(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) -> (
    MlsGroup,
    CredentialWithKey,
    SignatureKeyPair,
    OpenMlsSignaturePublicKey,
) {
    // Create credentials and keys
    let (alice_credential_with_key, alice_signature_keys) =
        test_utils::new_credential(provider, b"Alice", ciphersuite.signature_algorithm());
    let pk = OpenMlsSignaturePublicKey::new(
        alice_signature_keys.to_public_vec().into(),
        ciphersuite.signature_algorithm(),
    )
    .unwrap();

    // Alice creates a group
    let group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(
            provider,
            &alice_signature_keys,
            alice_credential_with_key.clone(),
        )
        .expect("Error creating group.");
    (group, alice_credential_with_key, alice_signature_keys, pk)
}

/// This function flips the last byte of the ciphertext.
pub fn flip_last_byte(ctxt: &mut HpkeCiphertext) {
    let mut last_bits = ctxt
        .ciphertext
        .pop()
        .expect("An unexpected error occurred.");
    last_bits ^= 0xff;
    ctxt.ciphertext.push(last_bits);
}

pub(crate) fn setup_alice_bob(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) -> (
    CredentialWithKey,
    SignatureKeyPair,
    KeyPackageBundle,
    SignatureKeyPair,
) {
    // Create credentials and keys
    let (alice_credential_with_key, alice_signer) =
        test_utils::new_credential(provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential_with_key, bob_signer) =
        test_utils::new_credential(provider, b"Bob", ciphersuite.signature_algorithm());

    // Generate Bob's KeyPackage
    let bob_key_package_bundle =
        KeyPackageBundle::generate(provider, &bob_signer, ciphersuite, bob_credential_with_key);

    (
        alice_credential_with_key,
        alice_signer,
        bob_key_package_bundle,
        bob_signer,
    )
}

pub(crate) fn setup_client(
    id: &str,
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) -> (
    CredentialWithKey,
    KeyPackageBundle,
    SignatureKeyPair,
    OpenMlsSignaturePublicKey,
) {
    let (credential_with_key, signature_keys) =
        test_utils::new_credential(provider, id.as_bytes(), ciphersuite.signature_algorithm());
    let pk = OpenMlsSignaturePublicKey::new(
        signature_keys.to_public_vec().into(),
        ciphersuite.signature_algorithm(),
    )
    .unwrap();

    // Generate the KeyPackage
    let key_package_bundle = KeyPackageBundle::generate(
        provider,
        &signature_keys,
        ciphersuite,
        credential_with_key.clone(),
    );
    (credential_with_key, key_package_bundle, signature_keys, pk)
}

pub(crate) fn setup_alice_bob_group<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
) -> (
    MlsGroup,
    SignatureKeyPair,
    MlsGroup,
    SignatureKeyPair,
    CredentialWithKey,
) {
    // Create credentials and keys
    let (alice_credential, alice_signature_keys) =
        test_utils::new_credential(provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signature_keys) =
        test_utils::new_credential(provider, b"Bob", ciphersuite.signature_algorithm());

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::generate(
        provider,
        &bob_signature_keys,
        ciphersuite,
        bob_credential.clone(),
    );
    let bob_key_package = bob_key_package_bundle.key_package();

    // Alice creates a group
    let mut group_alice = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(provider, &alice_signature_keys, alice_credential.clone())
        .expect("Error creating group.");

    // Alice adds Bob
    let (_commit, welcome, _group_info_option) = group_alice
        .add_members(provider, &alice_signature_keys, &[bob_key_package.clone()])
        .expect("Could not create proposal.");

    group_alice
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    let group_bob = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build(),
        welcome.into_welcome().unwrap(),
        Some(group_alice.export_ratchet_tree().into()),
    )
    .and_then(|staged_join| staged_join.into_group(provider))
    .expect("error creating group from welcome");

    (
        group_alice,
        alice_signature_keys,
        group_bob,
        bob_signature_keys,
        bob_credential,
    )
}
