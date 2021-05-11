//! # Extensions Unit tests
//! Some basic unit tests for extensions
//! Proper testing is done through the public APIs.

use super::*;

use crate::{
    codec::{Codec, Cursor},
    prelude::*,
};

#[test]
fn capabilities() {
    // A capabilities extension with the default values for openmls.
    let extension_bytes = [
        0, 1, 0, 17, 2, 1, 200, 6, 0, 1, 0, 2, 0, 3, 6, 0, 1, 0, 2, 0, 3,
    ];

    let ext = CapabilitiesExtension::default();
    let ext_struct = ext.to_extension_struct();

    // Check that decoding works
    let capabilities_extension_struct =
        ExtensionStruct::decode(&mut Cursor::new(&extension_bytes)).unwrap();
    assert_eq!(ext_struct, capabilities_extension_struct);

    // Encoding creates the expected bytes.
    assert_eq!(
        &extension_bytes[..],
        &ext_struct.encode_detached().unwrap()[..]
    );

    // Test encoding and decoding
    let encoded = ext
        .encode_detached()
        .expect("error encoding capabilities extension");
    let ext_decoded = CapabilitiesExtension::decode_detached(&encoded)
        .expect("error decoding capabilities extension");

    assert_eq!(ext, ext_decoded);
}

#[test]
fn key_package_id() {
    // A key package extension with the default values for openmls.
    let data = [0, 8, 1, 2, 3, 4, 5, 6, 6, 6];
    let kpi = KeyIdExtension::new(&data[2..]);
    assert_eq!(ExtensionType::KeyId, kpi.extension_type());

    let kpi_from_bytes = KeyIdExtension::new_from_bytes(&data).unwrap();
    assert_eq!(kpi, kpi_from_bytes);

    let extension_struct = kpi.to_extension_struct();
    assert_eq!(ExtensionType::KeyId, extension_struct.extension_type);
    assert_eq!(&data[..], &extension_struct.extension_data[..]);
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

    // Test encoding and decoding
    let encoded = ext
        .encode_detached()
        .expect("error encoding capabilities extension");
    let ext_decoded = LifetimeExtension::decode_detached(&encoded)
        .expect("error decoding capabilities extension");

    assert_eq!(ext, ext_decoded);
}

// This tests the ratchet tree extension to deliver the public ratcheting tree
// in-band
ctest_ciphersuites!(ratchet_tree_extension, test(ciphersuite_name: CiphersuiteName) {
    println!("Testing ciphersuite {:?}", ciphersuite_name);
    let ciphersuite = Config::ciphersuite(ciphersuite_name).unwrap();

    // Basic group setup.
    let group_aad = b"Alice's test group";

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .unwrap();
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .unwrap();

    // Generate KeyPackages
    let alice_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, Vec::new())
            .unwrap();

    let bob_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, Vec::new())
            .unwrap();
    let bob_key_package = bob_key_package_bundle.key_package();

    let config = GroupConfig {
        add_ratchet_tree_extension: true,
        ..GroupConfig::default()
    };

    // === Alice creates a group with the ratchet tree extension ===
    let group_id = [1, 2, 3, 4];
    let mut alice_group = MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        alice_key_package_bundle,
        config,
        None, /* Initial PSK */
        None, /* MLS version */
        vec![], /* extensions */
    )
    .unwrap();

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(group_aad, &alice_credential_bundle, bob_key_package.clone())
        .expect("Could not create proposal.");
    let epoch_proposals = &[&bob_add_proposal];
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, _kpb_option) = alice_group
        .create_commit(
            group_aad,
            &alice_credential_bundle,
            epoch_proposals,
            &[],
            false,
            None,
        )
        .expect("Error creating commit");

    alice_group
        .apply_commit(&mls_plaintext_commit, epoch_proposals, &[], None)
        .expect("error applying commit");

    let bob_group = match MlsGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.unwrap(),
        None,
        bob_key_package_bundle,
        None,
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
    let alice_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, Vec::new())
            .unwrap();

    let bob_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, Vec::new())
            .unwrap();
    let bob_key_package = bob_key_package_bundle.key_package();

    let config = GroupConfig {
        add_ratchet_tree_extension: false,
        ..GroupConfig::default()
    };

    let group_id = [5, 6, 7, 8];
    let mut alice_group = MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        alice_key_package_bundle,
        config,
        None, /* Initial PSK */
        None, /* MLS version */
        vec![], /* extensions */
    )
    .unwrap();

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(group_aad, &alice_credential_bundle, bob_key_package.clone())
        .expect("Could not create proposal.");
    let epoch_proposals = &[&bob_add_proposal];
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, _kpb_option) = alice_group
        .create_commit(
            group_aad,
            &alice_credential_bundle,
            epoch_proposals,
            &[],
            false,
            None,
        )
        .expect("Error creating commit");

    alice_group
        .apply_commit(&mls_plaintext_commit, epoch_proposals, &[], None)
        .expect("error applying commit");

    let error = MlsGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.unwrap(),
        None,
        bob_key_package_bundle,
        None,
    )
    .err();

    // We expect an error because the ratchet tree is missing
    assert_eq!(
        error.expect("We expected an error"),
        GroupError::WelcomeError(WelcomeError::MissingRatchetTree)
    );
});
