//! # Extensions Unit tests
//! Some basic unit tests for extensions
//! Proper testing is done through the public APIs.

use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

use super::*;

use crate::{group::create_commit_params::CreateCommitParams, prelude::*};

#[test]
fn capabilities() {
    // A capabilities extension with the default values for openmls.
    let extension_bytes = [
        0u8, 1, 0, 0, 0, 17, 2, 1, 200, 6, 0, 1, 0, 2, 0, 3, 6, 0, 1, 0, 2, 0, 3,
    ];
    let mut extension_bytes_mut = &extension_bytes[..];

    let ext = Extension::Capabilities(CapabilitiesExtension::default());

    // Check that decoding works
    let capabilities_extension = Extension::tls_deserialize(&mut extension_bytes_mut).unwrap();
    assert_eq!(ext, capabilities_extension);

    // Encoding creates the expected bytes.
    assert_eq!(
        extension_bytes,
        &capabilities_extension.tls_serialize_detached().unwrap()[..]
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
    let kpi = KeyIdExtension::new(&data[2..]);

    let kpi_from_bytes = KeyIdExtension::tls_deserialize(&mut (data as &[u8])).unwrap();
    assert_eq!(kpi, kpi_from_bytes);

    let serialized_extension_struct = kpi.tls_serialize_detached().unwrap();
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
        .err()
        .expect("Didn't get an error deserializing invalid life time extension");
    assert_eq!(
        ext_deserialized,
        tls_codec::Error::DecodingError("Invalid".to_string()),
    );
}

// This tests the ratchet tree extension to deliver the public ratcheting tree
// in-band
ctest_ciphersuites!(ratchet_tree_extension, test(ciphersuite_name: CiphersuiteName) {
    let crypto = &OpenMlsRustCrypto::default();

    log::info!("Testing ciphersuite {:?}", ciphersuite_name);
    let ciphersuite = Config::ciphersuite(ciphersuite_name).unwrap();

    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        crypto,
    )
    .unwrap();
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        crypto,
    )
    .unwrap();

    // Generate KeyPackages
    let alice_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()],
            &alice_credential_bundle,
            crypto,
            Vec::new(),
        )
        .unwrap();

    let bob_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()],
            &bob_credential_bundle,
            crypto,
            Vec::new(),
        )
        .unwrap();
    let bob_key_package = bob_key_package_bundle.key_package();

    let config = MlsGroupConfig {
        add_ratchet_tree_extension: true,
        ..MlsGroupConfig::default()
    };

    // === Alice creates a group with the ratchet tree extension ===
    let group_id = [1, 2, 3, 4];
    let mut alice_group = MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        crypto,
        alice_key_package_bundle,
        config,
        None, /* Initial PSK */
        None, /* MLS version */
    )
    .unwrap();

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(framing_parameters, &alice_credential_bundle, bob_key_package.clone(), crypto)
        .expect("Could not create proposal.");

    let proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, crypto, bob_add_proposal)
            .expect("Could not create StagedProposal."),
    );

    let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(&alice_credential_bundle)
            .proposal_store(&proposal_store)
            .force_self_update(false)
            .build();
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, _kpb_option) = alice_group
        .create_commit(
            params,
            crypto,
        )
        .expect("Error creating commit");

    let staged_commit = alice_group
        .stage_commit(&mls_plaintext_commit, &proposal_store, &[], None, crypto)
        .expect("error staging commit");
    alice_group.merge_commit(staged_commit);

    let bob_group = match MlsGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.unwrap(),
        None,
        bob_key_package_bundle,
        None,
        crypto,
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
        KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, crypto, Vec::new())
            .unwrap();

    let bob_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, crypto, Vec::new())
            .unwrap();
    let bob_key_package = bob_key_package_bundle.key_package();

    let config = MlsGroupConfig {
        add_ratchet_tree_extension: false,
        ..MlsGroupConfig::default()
    };

    let group_id = [5, 6, 7, 8];
    let mut alice_group = MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        crypto,
        alice_key_package_bundle,
        config,
        None, /* Initial PSK */
        None, /* MLS version */
    )
    .unwrap();

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(framing_parameters, &alice_credential_bundle, bob_key_package.clone(), crypto)
        .expect("Could not create proposal.");

    let proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, crypto, bob_add_proposal)
            .expect("Could not create staged proposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, _kpb_option) = alice_group
        .create_commit(params, crypto)
        .expect("Error creating commit");

    let staged_commit = alice_group
        .stage_commit(&mls_plaintext_commit, &proposal_store, &[], None, crypto)
        .expect("error staging commit");
    alice_group.merge_commit(staged_commit);

    let error = MlsGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.unwrap(),
        None,
        bob_key_package_bundle,
        None,
        crypto,
    )
    .err();

    // We expect an error because the ratchet tree is missing
    assert_eq!(
        error.expect("We expected an error"),
        MlsGroupError::WelcomeError(WelcomeError::MissingRatchetTree)
    );
});
