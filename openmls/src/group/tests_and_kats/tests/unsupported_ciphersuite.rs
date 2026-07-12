//! Tests that the public API boundaries reject ciphersuites the crypto
//! provider does not support, with a dedicated error.

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};

use crate::{
    group::{
        errors::WelcomeError,
        tests_and_kats::utils::{generate_credential_with_key, generate_key_package},
        ExternalCommitBuilderError, MlsGroup, MlsGroupJoinConfig, NewGroupError, StagedWelcome,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    test_utils::restricted_provider::RestrictedProvider,
};

const GROUP_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// A provider that supports some ciphersuite, but not `GROUP_CIPHERSUITE`.
fn restricted_provider() -> RestrictedProvider {
    RestrictedProvider::new(vec![Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256])
}

#[test]
fn group_create_rejects_unsupported_ciphersuite() {
    let provider = restricted_provider();
    let credential = generate_credential_with_key(
        "Alice".into(),
        GROUP_CIPHERSUITE.signature_algorithm(),
        &provider,
    );

    let err = MlsGroup::builder()
        .ciphersuite(GROUP_CIPHERSUITE)
        .build(
            &provider,
            &credential.signer,
            credential.credential_with_key,
        )
        .expect_err("group creation should fail for an unsupported ciphersuite");

    assert!(matches!(
        err,
        NewGroupError::UnsupportedCiphersuite(cs) if cs == GROUP_CIPHERSUITE
    ));
}

#[test]
fn welcome_rejects_unsupported_ciphersuite() {
    let alice_provider = &OpenMlsRustCrypto::default();
    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        GROUP_CIPHERSUITE.signature_algorithm(),
        alice_provider,
    );

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(GROUP_CIPHERSUITE)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(
            alice_provider,
            &alice_credential.signer,
            alice_credential.credential_with_key.clone(),
        )
        .unwrap();

    // Bob's key package is created with the unrestricted view of his provider
    // (sharing the same storage), so only welcome processing sees the
    // restriction.
    let bob_provider = restricted_provider();
    let bob_credential = generate_credential_with_key(
        "Bob".into(),
        GROUP_CIPHERSUITE.signature_algorithm(),
        bob_provider.inner(),
    );
    let bob_key_package = generate_key_package(
        GROUP_CIPHERSUITE,
        crate::extensions::Extensions::empty(),
        bob_provider.inner(),
        bob_credential,
    );

    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_credential.signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();
    let ratchet_tree = alice_group.export_ratchet_tree();

    let err = StagedWelcome::new_from_welcome(
        &bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect_err("welcome processing should fail for an unsupported ciphersuite");

    assert!(matches!(
        err,
        WelcomeError::UnsupportedCiphersuite(cs) if cs == GROUP_CIPHERSUITE
    ));
}

#[test]
fn external_commit_rejects_unsupported_ciphersuite() {
    let alice_provider = &OpenMlsRustCrypto::default();
    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        GROUP_CIPHERSUITE.signature_algorithm(),
        alice_provider,
    );

    let alice_group = MlsGroup::builder()
        .ciphersuite(GROUP_CIPHERSUITE)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(
            alice_provider,
            &alice_credential.signer,
            alice_credential.credential_with_key.clone(),
        )
        .unwrap();

    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_credential.signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let ratchet_tree = alice_group.export_ratchet_tree();

    let bob_provider = restricted_provider();
    let bob_credential = generate_credential_with_key(
        "Bob".into(),
        GROUP_CIPHERSUITE.signature_algorithm(),
        &bob_provider,
    );

    let err = MlsGroup::external_commit_builder()
        .with_ratchet_tree(ratchet_tree.into())
        .build_group(
            &bob_provider,
            verifiable_group_info,
            bob_credential.credential_with_key,
        )
        .expect_err("external commit should fail for an unsupported ciphersuite");

    assert!(matches!(
        err,
        ExternalCommitBuilderError::UnsupportedCiphersuite(cs) if cs == GROUP_CIPHERSUITE
    ));
}
