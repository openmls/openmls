//! # Extensions Unit tests
//! Some basic unit tests for extensions
//! Proper testing is done through the public APIs.

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::key_store::OpenMlsKeyStore;
use tls_codec::{Deserialize, Serialize};

use super::*;
use crate::{
    credentials::*,
    framing::*,
    group::{config::CryptoConfig, errors::*, *},
    key_packages::*,
    messages::proposals::ProposalType,
    prelude::Capabilities,
    schedule::psk::store::ResumptionPskStore,
    test_utils::*,
    versions::ProtocolVersion,
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
#[apply(ciphersuites_and_providers)]
fn ratchet_tree_extension(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    // Create credentials and keys
    let (alice_credential_with_key, alice_signature_keys) = test_utils::new_credential(
        provider,
        b"Alice",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let (bob_credential_with_key, bob_signature_keys) = test_utils::new_credential(
        provider,
        b"Bob",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        provider,
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
        GroupId::random(provider.rand()),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_key.clone(),
    )
    .with_config(config)
    .build(provider, &alice_signature_keys)
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
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, provider, &alice_signature_keys)
        .expect("Error creating commit");

    alice_group
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging commit");

    let bob_group = match CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        None,
        bob_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
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
        provider,
        &bob_signature_keys,
        ciphersuite,
        bob_credential_with_key,
    );
    let bob_key_package = bob_key_package_bundle.key_package();

    let config = CoreGroupConfig {
        add_ratchet_tree_extension: false,
    };

    let mut alice_group = CoreGroup::builder(
        GroupId::random(provider.rand()),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_key,
    )
    .with_config(config)
    .build(provider, &alice_signature_keys)
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
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .expect("Could not create staged proposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, provider, &alice_signature_keys)
        .expect("Error creating commit");

    alice_group
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging commit");

    let error = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        None,
        bob_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
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
    // A raw required capabilities extension with the default values for openmls
    // (none).
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

#[apply(ciphersuites_and_providers)]
fn last_resort_extension(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let last_resort = Extension::LastResort(LastResortExtension::default());

    // Build a KeyPackage with a last resort extension
    let credential = Credential::new(b"Bob".to_vec(), CredentialType::Basic).unwrap();
    let signer =
        openmls_basic_credential::SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    let extensions = Extensions::single(last_resort);
    let crypto_config = CryptoConfig::with_default_version(ciphersuite);
    let capabilities = Capabilities::new(
        None,
        None,
        // Add last resort extension as supported extension
        Some(&[ExtensionType::LastResort]),
        None,
        None,
    );
    let kp = KeyPackage::builder()
        .key_package_extensions(extensions)
        .leaf_node_capabilities(capabilities)
        .build(
            crypto_config,
            provider,
            &signer,
            CredentialWithKey {
                credential: credential.clone(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect("error building key package with last resort extension");
    assert!(kp.last_resort());
    let encoded_kp = kp
        .tls_serialize_detached()
        .expect("error encoding key package with last resort extension");
    let decoded_kp = KeyPackageIn::tls_deserialize(&mut encoded_kp.as_slice())
        .expect("error decoding key package with last resort extension")
        .validate(provider.crypto(), ProtocolVersion::default())
        .expect("error validating key package with last resort extension");
    assert!(decoded_kp.last_resort());

    // If we join a group using a last resort KP, it shouldn't be deleted from the
    // provider.

    let alice_credential_with_key_and_signer = tests::utils::generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        provider,
    );

    let mls_group_config = MlsGroupConfigBuilder::new()
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new(
        provider,
        &alice_credential_with_key_and_signer.signer,
        &mls_group_config,
        alice_credential_with_key_and_signer.credential_with_key,
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob ===

    let (_message, welcome, _group_info) = alice_group
        .add_members(
            provider,
            &alice_credential_with_key_and_signer.signer,
            &[kp.clone()],
        )
        .expect("An unexpected error occurred.");

    alice_group.merge_pending_commit(provider).unwrap();

    let _bob_group = MlsGroup::new_from_welcome(
        provider,
        &mls_group_config,
        welcome.into_welcome().expect("Unexpected MLS message"),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("An unexpected error occurred.");

    // This should not have deleted the KP from the store
    let kp: Option<KeyPackage> = provider.key_store().read(
        kp.hash_ref(provider.crypto())
            .expect("error hashing kp")
            .as_slice(),
    );
    assert!(kp.is_some());
}
