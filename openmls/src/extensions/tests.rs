//! # Extensions Unit tests
//! Some basic unit tests for extensions
//! Proper testing is done through the public APIs.

use std::slice::from_ref;

use tls_codec::{Deserialize, Serialize};

use super::*;
use crate::{
    credentials::*,
    framing::*,
    group::{errors::*, tests_and_kats::utils::generate_credential_with_key, *},
    key_packages::*,
    messages::proposals::ProposalType,
    prelude::{Capabilities, RatchetTreeIn},
    prelude_test::HpkePublicKey,
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

// Test adding an ApplicationId extension to the leaf node extensions
// in an MlsGroupCreateConfig
#[test]
fn application_id_in_leaf_node_extensions() {
    let extensions = Extensions::single(Extension::ApplicationId(ApplicationIdExtension::new(&[])));

    let _create_config = MlsGroupCreateConfig::builder()
        .with_leaf_node_extensions(extensions)
        .unwrap()
        .build();
}

// This tests the ratchet tree extension to deliver the public ratcheting tree
// in-band
#[openmls_test::openmls_test]
fn ratchet_tree_extension() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Basic group setup.

    // Create credentials and keys
    let (alice_credential_with_key, alice_signature_keys) =
        test_utils::new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential_with_key, bob_signature_keys) =
        test_utils::new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::generate(
        bob_provider,
        &bob_signature_keys,
        ciphersuite,
        bob_credential_with_key.clone(),
    );
    let bob_key_package = bob_key_package_bundle.key_package();

    // === Alice creates a group with the ratchet tree extension ===
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build(
            alice_provider,
            &alice_signature_keys,
            alice_credential_with_key.clone(),
        )
        .expect("Error creating group.");

    // === Alice adds Bob ===
    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            alice_provider,
            &alice_signature_keys,
            from_ref(bob_key_package),
        )
        .expect("An unexpected error occurred.");

    alice_group.merge_pending_commit(alice_provider).unwrap();

    let config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        &config,
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error staging welcome")
    .into_group(bob_provider)
    .expect("Error creating group from welcome");

    // Make sure the group state is the same
    assert_eq!(
        alice_group.epoch_authenticator(),
        bob_group.epoch_authenticator()
    );

    // Make sure both groups have set the flag correctly
    assert!(alice_group.configuration().use_ratchet_tree_extension);
    assert!(bob_group.configuration().use_ratchet_tree_extension);

    // === Alice creates a group without the ratchet tree extension ===

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::generate(
        bob_provider,
        &bob_signature_keys,
        ciphersuite,
        bob_credential_with_key,
    );
    let bob_key_package = bob_key_package_bundle.key_package();

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(false)
        .build(
            alice_provider,
            &alice_signature_keys,
            alice_credential_with_key,
        )
        .expect("Error creating group.");

    // === Alice adds Bob ===
    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            alice_provider,
            &alice_signature_keys,
            from_ref(bob_key_package),
        )
        .expect("An unexpected error occurred.");

    let config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(false)
        .build();

    let error = StagedWelcome::new_from_welcome(
        bob_provider,
        &config,
        welcome.into_welcome().unwrap(),
        None,
    )
    .and_then(|staged_join| staged_join.into_group(bob_provider))
    .err();

    // We expect an error because the ratchet tree is missing
    assert!(matches!(
        error.expect("We expected an error"),
        WelcomeError::MissingRatchetTree
    ));
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

#[openmls_test::openmls_test]
fn with_group_context_extensions() {
    let provider = &Provider::default();

    // create an extension that we can check for later
    let test_extension = Extension::Unknown(0xf023, UnknownExtension(vec![0xca, 0xfe]));
    let extensions = Extensions::single(test_extension.clone());

    let alice_credential_with_key_and_signer =
        generate_credential_with_key("Alice".into(), ciphersuite.signature_algorithm(), provider);

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .with_group_context_extensions(extensions)
        .expect("failed to apply extensions at group config builder")
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let alice_group = MlsGroup::new(
        provider,
        &alice_credential_with_key_and_signer.signer,
        &mls_group_create_config,
        alice_credential_with_key_and_signer.credential_with_key,
    )
    .expect("An unexpected error occurred.");

    // === Group contains extension ===
    let found_test_extension = alice_group
        .export_group_context()
        .extensions()
        .find_by_type(ExtensionType::Unknown(0xf023))
        .expect("failed to get test extensions from group context");
    assert_eq!(found_test_extension, &test_extension);
}

#[openmls_test::openmls_test]
fn wrong_extension_with_group_context_extensions() {
    let provider = &Provider::default();

    // Extension types that are known to not be allowed here:
    // - application id
    // - external pub
    // - ratchet tree

    let alice_credential_with_key_and_signer =
        generate_credential_with_key("Alice".into(), ciphersuite.signature_algorithm(), provider);

    // create an extension that we can check for later
    let test_extension = Extension::ApplicationId(ApplicationIdExtension::new(&[0xca, 0xfe]));
    let extensions = Extensions::single(test_extension.clone());

    let err = MlsGroup::builder()
        .with_group_context_extensions(extensions.clone())
        .expect_err("builder accepted non-group-context extension");

    assert_eq!(err, InvalidExtensionError::IllegalInGroupContext);
    let err = PublicGroup::builder(
        GroupId::from_slice(&[0xbe, 0xef]),
        ciphersuite,
        alice_credential_with_key_and_signer
            .credential_with_key
            .clone(),
    )
    .with_group_context_extensions(extensions)
    .expect_err("builder accepted non-group-context extension");

    assert_eq!(err, InvalidExtensionError::IllegalInGroupContext);
    // create an extension that we can check for later
    let test_extension =
        Extension::ExternalPub(ExternalPubExtension::new(HpkePublicKey::new(vec![])));
    let extensions = Extensions::single(test_extension.clone());

    let err = MlsGroup::builder()
        .with_group_context_extensions(extensions.clone())
        .expect_err("builder accepted non-group-context extension");
    assert_eq!(err, InvalidExtensionError::IllegalInGroupContext);

    let err = PublicGroup::builder(
        GroupId::from_slice(&[0xbe, 0xef]),
        ciphersuite,
        alice_credential_with_key_and_signer
            .credential_with_key
            .clone(),
    )
    .with_group_context_extensions(extensions)
    .expect_err("builder accepted non-group-context extension");
    assert_eq!(err, InvalidExtensionError::IllegalInGroupContext);

    // create an extension that we can check for later
    let test_extension = Extension::RatchetTree(RatchetTreeExtension::new(
        RatchetTreeIn::from_nodes(vec![]).into(),
    ));
    let extensions = Extensions::single(test_extension.clone());

    let err = MlsGroup::builder()
        .with_group_context_extensions(extensions.clone())
        .expect_err("builder accepted non-group-context extension");
    assert_eq!(err, InvalidExtensionError::IllegalInGroupContext);

    let err = PublicGroup::builder(
        GroupId::from_slice(&[0xbe, 0xef]),
        ciphersuite,
        alice_credential_with_key_and_signer
            .credential_with_key
            .clone(),
    )
    .with_group_context_extensions(extensions)
    .expect_err("builder accepted non-group-context extension");
    assert_eq!(err, InvalidExtensionError::IllegalInGroupContext);
}

#[openmls_test::openmls_test]
fn last_resort_extension() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let last_resort = Extension::LastResort(LastResortExtension::default());

    // Build a KeyPackage with a last resort extension
    let credential = BasicCredential::new(b"Bob".to_vec());
    let signer =
        openmls_basic_credential::SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    let extensions = Extensions::single(last_resort);
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
            ciphersuite,
            bob_provider,
            &signer,
            CredentialWithKey {
                credential: credential.clone().into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect("error building key package with last resort extension");
    assert!(kp.key_package().last_resort());
    let encoded_kp = kp
        .key_package()
        .tls_serialize_detached()
        .expect("error encoding key package with last resort extension");
    let decoded_kp = KeyPackageIn::tls_deserialize(&mut encoded_kp.as_slice())
        .expect("error decoding key package with last resort extension")
        .validate(bob_provider.crypto(), ProtocolVersion::default())
        .expect("error validating key package with last resort extension");
    assert!(decoded_kp.last_resort());

    // If we join a group using a last resort KP, it shouldn't be deleted from the
    // provider.

    let alice_credential_with_key_and_signer = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_credential_with_key_and_signer.signer,
        &mls_group_create_config,
        alice_credential_with_key_and_signer.credential_with_key,
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob ===

    let (_message, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_credential_with_key_and_signer.signer,
            from_ref(kp.key_package()),
        )
        .expect("An unexpected error occurred.");

    alice_group.merge_pending_commit(alice_provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome.into_welcome().expect("expected a welcome");

    let _bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("An unexpected error occurred.")
    .into_group(bob_provider)
    .expect("An unexpected error occurred.");

    let _: KeyPackageBundle = bob_provider
        .storage()
        .key_package(
            &kp.key_package()
                .hash_ref(bob_provider.crypto())
                .expect("error hashing key package"),
        )
        .expect("error retrieving key package")
        .expect("key package does not exist");
}

#[cfg(feature = "extensions-draft-08")]
#[openmls_test::openmls_test]
fn app_data_dictionary_extension() {
    use crate::test_utils::single_group_test_framework::*;
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let group_id = GroupId::from_slice(b"Test Group");

    let mut group_state = GroupState::new_from_party(
        group_id,
        alice_party.generate_pre_group(ciphersuite),
        create_config.clone(),
    )
    .unwrap();

    let [alice] = group_state.members_mut(&["alice"]);

    let mut dictionary = AppDataDictionary::new();
    let _ = dictionary.insert(5, vec![]);
    let _ = dictionary.insert(0, vec![1, 2, 3]);

    let extension =
        Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary.clone()));
    // build the commit
    let message_bundle = alice
        .group
        .commit_builder()
        .propose_adds(Some(
            bob_party
                .generate_pre_group(ciphersuite)
                .key_package_bundle
                .key_package()
                .clone(),
        ))
        .load_psks(alice_party.provider.storage())
        .unwrap()
        .create_group_info_with_extensions(Some(extension))
        .unwrap()
        .build(
            alice_party.provider.rand(),
            alice_party.provider.crypto(),
            &alice.party.signer,
            |_proposal| true,
        )
        .unwrap()
        .stage_commit(&alice_party.provider)
        .unwrap();

    // process the Welcome for Bob
    let welcome = message_bundle.into_welcome().unwrap();
    let processed_welcome = ProcessedWelcome::new_from_welcome(
        &bob_party.provider,
        create_config.join_config(),
        welcome,
    )
    .unwrap();

    // retrieve the extension
    let extensions = processed_welcome.unverified_group_info().extensions();
    let extension = extensions
        .iter()
        .find(|e| e.extension_type() == ExtensionType::AppDataDictionary)
        .and_then(|e| e.as_app_data_dictionary_extension().ok())
        .unwrap();

    // check the dictionary
    assert_eq!(&dictionary, extension.dictionary());
}
