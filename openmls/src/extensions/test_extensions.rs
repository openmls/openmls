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
fn application_id() {
    // A raw application id extension
    let data = &[8u8, 1, 2, 3, 4, 5, 6, 6, 6];
    let app_id = ApplicationIdExtension::new(&data[1..]);

    let app_id_from_bytes = ApplicationIdExtension::tls_deserialize(&mut (data as &[u8]))
        .expect("An unexpected error occurred.");
    assert_eq!(app_id, app_id_from_bytes);

    let serialized_extension_struct = app_id
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    assert_eq!(&data[..], &serialized_extension_struct);
}

// This tests the ratchet tree extension to deliver the public ratcheting tree
// in-band
#[apply(ciphersuites_and_backends)]
fn ratchet_tree_extension(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    // Create credentials and keys
    let (alice_credential_with_key, alice_signature_keys) = test_utils::new_credential(
        backend,
        b"Alice",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let (bob_credential_with_key, bob_signature_keys) = test_utils::new_credential(
        backend,
        b"Bob",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        backend,
        &bob_signature_keys,
        ciphersuite,
        bob_credential_with_key.clone(),
    );
    let bob_key_package = bob_key_package_bundle.key_package();

    let config = CoreGroupConfig {
        add_ratchet_tree_extension: true,
    };

    // === Alice creates a group with the ratchet tree extension ===
    let mut alice_group = CoreGroup::builder(
        GroupId::random(backend),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_key.clone(),
    )
    .with_config(config)
    .build(backend, &alice_signature_keys)
    .expect("Error creating group.");

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            bob_key_package.clone(),
            &alice_signature_keys,
        )
        .expect("Could not create proposal.");

    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend, &alice_signature_keys)
        .expect("Error creating commit");

    alice_group
        .merge_commit(backend, create_commit_result.staged_commit)
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
        Err(e) => panic!("Could not join group with ratchet tree extension {e}"),
    };

    // Make sure the group state is the same
    assert_eq!(
        alice_group.epoch_authenticator(),
        bob_group.epoch_authenticator()
    );

    // Make sure both groups have set the flag correctly
    assert!(alice_group.use_ratchet_tree_extension());
    assert!(bob_group.use_ratchet_tree_extension());

    // === Alice creates a group without the ratchet tree extension ===

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        backend,
        &bob_signature_keys,
        ciphersuite,
        bob_credential_with_key,
    );
    let bob_key_package = bob_key_package_bundle.key_package();

    let config = CoreGroupConfig {
        add_ratchet_tree_extension: false,
    };

    let mut alice_group = CoreGroup::builder(
        GroupId::random(backend),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_key,
    )
    .with_config(config)
    .build(backend, &alice_signature_keys)
    .expect("Error creating group.");

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            bob_key_package.clone(),
            &alice_signature_keys,
        )
        .expect("Could not create proposal.");

    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create staged proposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend, &alice_signature_keys)
        .expect("Error creating commit");

    alice_group
        .merge_commit(backend, create_commit_result.staged_commit)
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
    // A raw required capabilities extension with the default values for openmls (none).
    let extension_bytes = vec![0, 3, 3, 0, 0, 0];

    let ext = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::default());

    // Check that decoding works
    let required_capabilities = Extension::tls_deserialize(&mut extension_bytes.as_slice())
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
        &[ExtensionType::ApplicationId, ExtensionType::RatchetTree],
        &[ProposalType::Reinit],
        &[CredentialType::Basic],
    );
    let ext = Extension::RequiredCapabilities(required_capabilities);
    let extension_bytes = vec![0u8, 3, 11, 4, 0, 1, 0, 2, 2, 0, 5, 2, 0, 1];

    // Test encoding and decoding
    let encoded = ext
        .tls_serialize_detached()
        .expect("error encoding required capabilities extension");
    let ext_decoded = Extension::tls_deserialize(&mut encoded.as_slice())
        .expect("error decoding required capabilities extension");

    assert_eq!(ext, ext_decoded);
    assert_eq!(extension_bytes, encoded);
}
