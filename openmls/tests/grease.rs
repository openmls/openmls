//! Integration tests for GREASE (Generate Random Extensions And Sustain
//! Extensibility)
//!
//! These tests verify that GREASE values are properly handled throughout the
//! MLS protocol implementation, including in KeyPackages, capabilities,
//! proposals, and validation logic.

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::Ciphersuite;

// Helper function to create a test credential
fn create_credential(identity: &[u8]) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity.to_vec());
    let signature_keys = SignatureKeyPair::new(
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm(),
    )
    .expect("Error generating signature keys");

    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    )
}

#[test]
fn test_grease_proposals_in_capabilities() {
    // Test that GREASE proposal types in capabilities don't break validation

    let provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) = create_credential(b"Alice");
    let (bob_credential, bob_signer) = create_credential(b"Bob");

    // Create Alice's group with GREASE proposals in capabilities
    let alice_capabilities = Capabilities::builder()
        .proposals(vec![
            ProposalType::Add,
            ProposalType::Update,
            ProposalType::Remove,
            ProposalType::Grease(0x0A0A), // Add GREASE proposal
            ProposalType::Grease(0x1A1A), // Add another GREASE proposal
        ])
        .build();

    let alice_group = MlsGroup::builder()
        .with_group_id(GroupId::from_slice(b"test_group"))
        .with_capabilities(alice_capabilities)
        .build(&provider, &alice_signer, alice_credential.clone())
        .expect("Failed to create group");

    // Create Bob's KeyPackage with GREASE proposals
    let bob_capabilities = Capabilities::builder()
        .proposals(vec![
            ProposalType::Add,
            ProposalType::Update,
            ProposalType::Remove,
            ProposalType::Grease(0x2A2A), // Different GREASE values
        ])
        .build();

    let bob_key_package = KeyPackage::builder()
        .leaf_node_capabilities(bob_capabilities)
        .build(
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            &provider,
            &bob_signer,
            bob_credential,
        )
        .expect("Failed to create KeyPackage");

    // Add Bob to the group - should succeed despite different GREASE values
    let mut alice_group = alice_group;
    let (_message, _welcome, _group_info) = alice_group
        .add_members(
            &provider,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        )
        .expect("Failed to add Bob to group");

    alice_group
        .merge_pending_commit(&provider)
        .expect("Failed to merge commit");
}

#[test]
fn test_grease_extensions_in_capabilities() {
    // Test that GREASE extension types in capabilities don't break validation

    let provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) = create_credential(b"Alice");

    // Create capabilities with GREASE extensions
    let alice_capabilities = Capabilities::builder()
        .extensions(vec![
            ExtensionType::ApplicationId,
            ExtensionType::Grease(0x3A3A), // Add GREASE extension
            ExtensionType::Grease(0x4A4A), // Add another GREASE extension
        ])
        .build();

    // Create group with GREASE extensions - should succeed
    let _alice_group = MlsGroup::builder()
        .with_group_id(GroupId::from_slice(b"test_group"))
        .with_capabilities(alice_capabilities)
        .build(&provider, &alice_signer, alice_credential)
        .expect("Failed to create group with GREASE extensions");
}

#[test]
fn test_grease_credentials_in_capabilities() {
    // Test that GREASE credential types in capabilities don't break validation

    let provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) = create_credential(b"Alice");

    // Create capabilities with GREASE credentials
    let alice_capabilities = Capabilities::builder()
        .credentials(vec![
            CredentialType::Basic,
            CredentialType::Grease(0x5A5A), // Add GREASE credential
            CredentialType::Grease(0x6A6A), // Add another GREASE credential
        ])
        .build();

    // Create group with GREASE credentials - should succeed
    let _alice_group = MlsGroup::builder()
        .with_group_id(GroupId::from_slice(b"test_group"))
        .with_capabilities(alice_capabilities)
        .build(&provider, &alice_signer, alice_credential)
        .expect("Failed to create group with GREASE credentials");
}

// Note: GREASE ciphersuite test is commented out because it requires internal
// test-only APIs to set ciphersuites with GREASE values. The logic for
// filtering GREASE ciphersuites is tested through the unit tests in the
// capabilities module.
/*
#[test]
fn test_grease_ciphersuites_in_capabilities() {
    // Would test that GREASE ciphersuites in capabilities don't break validation
    // Requires test-only API to set ciphersuites
}
*/

#[test]
fn test_multiple_grease_values_filtered() {
    // Test that multiple GREASE values in the same capability list are all filtered

    let provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) = create_credential(b"Alice");
    let (bob_credential, bob_signer) = create_credential(b"Bob");

    // Create Alice with many GREASE values
    let alice_capabilities = Capabilities::builder()
        .proposals(vec![
            ProposalType::Add,
            ProposalType::Grease(0x0A0A),
            ProposalType::Grease(0x1A1A),
            ProposalType::Grease(0x2A2A),
            ProposalType::Grease(0x3A3A),
        ])
        .extensions(vec![
            ExtensionType::ApplicationId,
            ExtensionType::Grease(0x4A4A),
            ExtensionType::Grease(0x5A5A),
        ])
        .credentials(vec![
            CredentialType::Basic,
            CredentialType::Grease(0x6A6A),
            CredentialType::Grease(0x7A7A),
            CredentialType::Grease(0x8A8A),
        ])
        .build();

    let alice_group = MlsGroup::builder()
        .with_group_id(GroupId::from_slice(b"test_group"))
        .with_capabilities(alice_capabilities)
        .build(&provider, &alice_signer, alice_credential)
        .expect("Failed to create group");

    // Create Bob with completely different GREASE values
    let bob_capabilities = Capabilities::builder()
        .proposals(vec![
            ProposalType::Add,
            ProposalType::Grease(0x9A9A),
            ProposalType::Grease(0xAAAA),
        ])
        .extensions(vec![
            ExtensionType::ApplicationId,
            ExtensionType::Grease(0xBABA),
        ])
        .credentials(vec![
            CredentialType::Basic,
            CredentialType::Grease(0xCACA),
            CredentialType::Grease(0xDADA),
        ])
        .build();

    let bob_key_package = KeyPackage::builder()
        .leaf_node_capabilities(bob_capabilities)
        .build(
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            &provider,
            &bob_signer,
            bob_credential,
        )
        .expect("Failed to create KeyPackage");

    // Add Bob - should succeed despite completely different GREASE values
    let mut alice_group = alice_group;
    let (_message, _welcome, _group_info) = alice_group
        .add_members(
            &provider,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        )
        .expect("Failed to add Bob with different GREASE values");

    alice_group
        .merge_pending_commit(&provider)
        .expect("Failed to merge commit");
}

#[test]
fn test_grease_value_validation() {
    // Test the basic GREASE value detection
    use openmls::grease::is_grease_value;

    // All 15 GREASE values should be recognized
    assert!(is_grease_value(0x0A0A));
    assert!(is_grease_value(0x1A1A));
    assert!(is_grease_value(0x2A2A));
    assert!(is_grease_value(0x3A3A));
    assert!(is_grease_value(0x4A4A));
    assert!(is_grease_value(0x5A5A));
    assert!(is_grease_value(0x6A6A));
    assert!(is_grease_value(0x7A7A));
    assert!(is_grease_value(0x8A8A));
    assert!(is_grease_value(0x9A9A));
    assert!(is_grease_value(0xAAAA));
    assert!(is_grease_value(0xBABA));
    assert!(is_grease_value(0xCACA));
    assert!(is_grease_value(0xDADA));
    assert!(is_grease_value(0xEAEA));

    // Non-GREASE values should not be recognized
    assert!(!is_grease_value(0x0000));
    assert!(!is_grease_value(0x0001));
    assert!(!is_grease_value(0x0A00));
    assert!(!is_grease_value(0x00A0));
    assert!(!is_grease_value(0xFFFF));
}

#[test]
fn test_grease_type_detection() {
    // Test that is_grease() methods work correctly

    // ProposalType
    assert!(ProposalType::Grease(0x0A0A).is_grease());
    assert!(!ProposalType::Add.is_grease());
    assert!(!ProposalType::Custom(0x1234).is_grease());

    // ExtensionType
    assert!(ExtensionType::Grease(0x1A1A).is_grease());
    assert!(!ExtensionType::ApplicationId.is_grease());
    assert!(!ExtensionType::Unknown(0x1234).is_grease());

    // CredentialType
    assert!(CredentialType::Grease(0x2A2A).is_grease());
    assert!(!CredentialType::Basic.is_grease());
    assert!(!CredentialType::Other(0x1234).is_grease());

    // VerifiableCiphersuite
    use openmls_traits::types::VerifiableCiphersuite;
    assert!(VerifiableCiphersuite::new(0x3A3A).is_grease());
    assert!(!VerifiableCiphersuite::from(
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    )
    .is_grease());
}

#[test]
fn test_grease_not_automatically_injected_in_key_packages() {
    // Test that KeyPackages do NOT automatically include GREASE values
    // (library users must opt-in via with_grease())

    let provider = OpenMlsRustCrypto::default();
    let (credential, signer) = create_credential(b"Alice");

    // Create a KeyPackage without explicitly setting capabilities
    let key_package = KeyPackage::builder()
        .build(
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            &provider,
            &signer,
            credential,
        )
        .expect("Failed to create KeyPackage");

    let capabilities = key_package.key_package().leaf_node().capabilities();

    // Check that GREASE values were NOT automatically added
    let has_grease_ciphersuite = capabilities.ciphersuites().iter().any(|cs| cs.is_grease());
    let has_grease_extension = capabilities.extensions().iter().any(|ext| ext.is_grease());
    let has_grease_proposal = capabilities.proposals().iter().any(|prop| prop.is_grease());
    let has_grease_credential = capabilities
        .credentials()
        .iter()
        .any(|cred| cred.is_grease());

    assert!(
        !has_grease_ciphersuite,
        "KeyPackage should NOT automatically include GREASE ciphersuites"
    );
    assert!(
        !has_grease_extension,
        "KeyPackage should NOT automatically include GREASE extensions"
    );
    assert!(
        !has_grease_proposal,
        "KeyPackage should NOT automatically include GREASE proposals"
    );
    assert!(
        !has_grease_credential,
        "KeyPackage should NOT automatically include GREASE credentials"
    );
}

#[test]
fn test_grease_injection_via_with_grease() {
    // Test that with_grease() correctly adds GREASE values to capabilities

    let provider = OpenMlsRustCrypto::default();
    let (credential, signer) = create_credential(b"Alice");

    // Create capabilities with GREASE values using with_grease()
    let capabilities = Capabilities::builder()
        .with_grease(provider.rand())
        .build();

    // Create a KeyPackage with these capabilities
    let key_package = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            &provider,
            &signer,
            credential,
        )
        .expect("Failed to create KeyPackage");

    let capabilities = key_package.key_package().leaf_node().capabilities();

    // Check that GREASE values were added via with_grease()
    let has_grease_ciphersuite = capabilities.ciphersuites().iter().any(|cs| cs.is_grease());
    let has_grease_extension = capabilities.extensions().iter().any(|ext| ext.is_grease());
    let has_grease_proposal = capabilities.proposals().iter().any(|prop| prop.is_grease());
    let has_grease_credential = capabilities
        .credentials()
        .iter()
        .any(|cred| cred.is_grease());

    assert!(
        has_grease_ciphersuite,
        "with_grease() should add a GREASE ciphersuite"
    );
    assert!(
        has_grease_extension,
        "with_grease() should add a GREASE extension"
    );
    assert!(
        has_grease_proposal,
        "with_grease() should add a GREASE proposal"
    );
    assert!(
        has_grease_credential,
        "with_grease() should add a GREASE credential"
    );
}

#[test]
fn test_grease_not_automatically_injected_in_groups() {
    // Test that MlsGroups do NOT automatically include GREASE values
    // (library users must opt-in via with_grease())

    let provider = OpenMlsRustCrypto::default();
    let (credential, signer) = create_credential(b"Alice");

    // Create a group without explicitly setting capabilities
    let alice_group = MlsGroup::builder()
        .with_group_id(GroupId::from_slice(b"test_group"))
        .build(&provider, &signer, credential)
        .expect("Failed to create group");

    let capabilities = alice_group
        .own_leaf_node()
        .expect("Should have own leaf node")
        .capabilities();

    // Check that GREASE values were NOT automatically added
    let has_grease_ciphersuite = capabilities.ciphersuites().iter().any(|cs| cs.is_grease());
    let has_grease_extension = capabilities.extensions().iter().any(|ext| ext.is_grease());
    let has_grease_proposal = capabilities.proposals().iter().any(|prop| prop.is_grease());
    let has_grease_credential = capabilities
        .credentials()
        .iter()
        .any(|cred| cred.is_grease());

    assert!(
        !has_grease_ciphersuite,
        "MlsGroup should NOT automatically include GREASE ciphersuites"
    );
    assert!(
        !has_grease_extension,
        "MlsGroup should NOT automatically include GREASE extensions"
    );
    assert!(
        !has_grease_proposal,
        "MlsGroup should NOT automatically include GREASE proposals"
    );
    assert!(
        !has_grease_credential,
        "MlsGroup should NOT automatically include GREASE credentials"
    );
}

#[test]
fn test_grease_injection_in_groups_via_with_grease() {
    // Test that with_grease() correctly adds GREASE values to MlsGroup capabilities

    let provider = OpenMlsRustCrypto::default();
    let (credential, signer) = create_credential(b"Alice");

    // Create capabilities with GREASE values using with_grease()
    let capabilities = Capabilities::builder()
        .with_grease(provider.rand())
        .build();

    // Create a group with these capabilities
    let alice_group = MlsGroup::builder()
        .with_group_id(GroupId::from_slice(b"test_group"))
        .with_capabilities(capabilities)
        .build(&provider, &signer, credential)
        .expect("Failed to create group");

    let capabilities = alice_group
        .own_leaf_node()
        .expect("Should have own leaf node")
        .capabilities();

    // Check that GREASE values were added via with_grease()
    let has_grease_ciphersuite = capabilities.ciphersuites().iter().any(|cs| cs.is_grease());
    let has_grease_extension = capabilities.extensions().iter().any(|ext| ext.is_grease());
    let has_grease_proposal = capabilities.proposals().iter().any(|prop| prop.is_grease());
    let has_grease_credential = capabilities
        .credentials()
        .iter()
        .any(|cred| cred.is_grease());

    assert!(
        has_grease_ciphersuite,
        "with_grease() should add a GREASE ciphersuite"
    );
    assert!(
        has_grease_extension,
        "with_grease() should add a GREASE extension"
    );
    assert!(
        has_grease_proposal,
        "with_grease() should add a GREASE proposal"
    );
    assert!(
        has_grease_credential,
        "with_grease() should add a GREASE credential"
    );
}
