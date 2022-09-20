//! # Extensions Unit tests
//! Some basic unit tests for extensions
//! Proper testing is done through the public APIs.

use crate::test_utils::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

use super::*;

use crate::{
    credentials::*, framing::*, group::errors::*, group::*, key_packages::*,
    messages::proposals::ProposalType,
};

#[test]
fn capabilities() {
    // A capabilities extension with the default values for openmls.
    let extension_bytes = [
        0u8, 1, 0, 0, 0, 29, 1, 1, 6, 0, 1, 0, 2, 0, 3, 6, 0, 1, 0, 2, 0, 3, 12, 0, 1, 0, 2, 0, 3,
        0, 4, 0, 5, 0, 8,
    ];
    let mut extension_bytes_mut = &extension_bytes[..];

    let ext = Extension::Capabilities(CapabilitiesExtension::default());

    // Check that decoding works
    let capabilities_extension = Extension::tls_deserialize(&mut extension_bytes_mut)
        .expect("An unexpected error occurred.");
    assert_eq!(ext, capabilities_extension);

    // Encoding creates the expected bytes.
    assert_eq!(
        extension_bytes,
        &capabilities_extension
            .tls_serialize_detached()
            .expect("An unexpected error occurred.")[..]
    );

    // Test encoding and decoding
    let encoded = ext
        .tls_serialize_detached()
        .expect("error encoding capabilities extension");
    let ext_decoded = Extension::tls_deserialize(&mut encoded.as_slice())
        .expect("error decoding capabilities extension");

    assert_eq!(ext, ext_decoded);
}

#[test]
fn key_package_id() {
    // A key package extension with the default values for openmls.
    let data = &[0u8, 8, 1, 2, 3, 4, 5, 6, 6, 6];
    let kpi = ExternalKeyIdExtension::new(&data[2..]);

    let kpi_from_bytes = ExternalKeyIdExtension::tls_deserialize(&mut (data as &[u8]))
        .expect("An unexpected error occurred.");
    assert_eq!(kpi, kpi_from_bytes);

    let serialized_extension_struct = kpi
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    assert_eq!(&data[..], &serialized_extension_struct);
}

#[test]
fn lifetime() {
    // A freshly created extensions must be valid.
    let ext = LifetimeExtension::default();
    assert!(ext.is_valid());

    // An extension without lifetime is invalid (waiting for 1 second).
    let ext = LifetimeExtension::new(0);
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(!ext.is_valid());

    // Test (de)serializing invalid extension
    let serialized = ext
        .tls_serialize_detached()
        .expect("error encoding life time extension");
    let ext_deserialized = LifetimeExtension::tls_deserialize(&mut serialized.as_slice())
        .expect_err("Didn't get an error deserializing invalid life time extension");
    assert_eq!(
        ext_deserialized,
        tls_codec::Error::DecodingError("Invalid".to_string()),
    );
}

// This tests the ratchet tree extension to deliver the public ratcheting tree
// in-band
#[apply(ciphersuites_and_backends)]
fn ratchet_tree_extension(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    let bob_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &bob_credential_bundle, backend, Vec::new())
            .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    let config = CoreGroupConfig {
        add_ratchet_tree_extension: true,
    };

    // === Alice creates a group with the ratchet tree extension ===
    let mut alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .with_config(config)
        .build(backend)
        .expect("Error creating group.");

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");

    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend)
        .expect("Error creating commit");

    alice_group
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging commit");

    let bob_group = match CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        None,
        bob_key_package_bundle,
        backend,
    ) {
        Ok(g) => g,
        Err(e) => panic!("Could not join group with ratchet tree extension {}", e),
    };

    // Make sure the group state is the same
    assert_eq!(
        alice_group.authentication_secret(),
        bob_group.authentication_secret()
    );

    // Make sure both groups have set the flag correctly
    assert!(alice_group.use_ratchet_tree_extension());
    assert!(bob_group.use_ratchet_tree_extension());

    // === Alice creates a group without the ratchet tree extension ===

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    let bob_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &bob_credential_bundle, backend, Vec::new())
            .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    let config = CoreGroupConfig {
        add_ratchet_tree_extension: false,
    };

    let mut alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .with_config(config)
        .build(backend)
        .expect("Error creating group.");

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");

    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create staged proposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend)
        .expect("Error creating commit");

    alice_group
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging commit");

    let error = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        None,
        bob_key_package_bundle,
        backend,
    )
    .err();

    // We expect an error because the ratchet tree is missing
    assert_eq!(
        error.expect("We expected an error"),
        WelcomeError::MissingRatchetTree
    );
}

#[test]
fn required_capabilities() {
    // A required capabilities extension with the default values for openmls (none).
    let extension_bytes = vec![0u8, 6, 0, 0, 0, 2, 0, 0];
    let mut extension_bytes_mut = &extension_bytes[..];

    let ext = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::default());

    // Check that decoding works
    let required_capabilities = Extension::tls_deserialize(&mut extension_bytes_mut)
        .expect("An unexpected error occurred.");
    assert_eq!(ext, required_capabilities);

    // Encoding creates the expected bytes.
    assert_eq!(
        extension_bytes,
        &required_capabilities
            .tls_serialize_detached()
            .expect("An unexpected error occurred.")[..]
    );

    // Build one with some content.
    let required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::ExternalKeyId, ExtensionType::RatchetTree],
        &[ProposalType::Reinit],
    );
    let ext = Extension::RequiredCapabilities(required_capabilities);
    let extension_bytes = vec![0u8, 6, 0, 0, 0, 8, 4, 0, 3, 0, 5, 2, 0, 5];

    // Test encoding and decoding
    let encoded = ext
        .tls_serialize_detached()
        .expect("error encoding required capabilities extension");
    let ext_decoded = Extension::tls_deserialize(&mut encoded.as_slice())
        .expect("error decoding required capabilities extension");

    assert_eq!(ext, ext_decoded);
    assert_eq!(extension_bytes, encoded);
}
