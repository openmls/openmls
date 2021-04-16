//! # Ratchet tree extensions unit test

use super::*;

use crate::{
    ciphersuite::signable::Signable,
    codec::{Codec, CodecError},
    messages::GroupSecrets,
    prelude::*,
    schedule::KeySchedule,
};

// This tests the ratchet tree extension to test if the duplicate detection works
ctest_ciphersuites!(duplicate_ratchet_tree_extension, test(ciphersuite_name: CiphersuiteName) {
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

    let group_id = [5, 6, 7, 8];
    let mut alice_group = MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        alice_key_package_bundle,
        config,
        None, /* Initial PSK */
        None, /* MLS version */
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

    let mut welcome = welcome_bundle_alice_bob_option.expect("Expected a Welcome message");

    //  === Duplicate the ratchet tree extension ===

    // Find key_package in welcome secrets
    let egs = MlsGroup::find_key_package_from_welcome_secrets(
        bob_key_package_bundle.key_package(),
        welcome.secrets(),
    ).expect("JoinerSecret not found");

    let group_secrets_bytes = ciphersuite.hpke_open(
        &egs.encrypted_group_secrets,
        &bob_key_package_bundle.private_key(),
        &[],
        &[],
    ).expect("Could not decrypt group secrets");
    let group_secrets = GroupSecrets::decode_detached(&group_secrets_bytes).expect("Could not decode GroupSecrets").config(ciphersuite, ProtocolVersion::default());
    let joiner_secret = group_secrets.joiner_secret;

    // Create key schedule
    let presharedkeys = PreSharedKeys {
        psks: match group_secrets.psks {
            Some(psks) => psks.psks,
            None => vec![],
        },
    };

    let key_schedule = KeySchedule::init(
        ciphersuite,
        joiner_secret,
        psk_output(ciphersuite, None, &presharedkeys).expect("Could not extract PSKs"),
    );

    // Derive welcome key & noce from the key schedule
    let (welcome_key, welcome_nonce) = key_schedule
        .welcome().expect("Expected a WelcomeSecret")
        .derive_welcome_key_nonce();

    let group_info_bytes = welcome_key
        .aead_open(welcome.encrypted_group_info(), &[], &welcome_nonce)
        .map_err(|_| WelcomeError::GroupInfoDecryptionFailure).expect("Could not decrypt GroupInfo");
    let mut group_info = GroupInfo::decode_detached(&group_info_bytes).expect("Could not decode GroupInfo");

    // Dupicate extensions
    let extensions = group_info.extensions();
    let duplicate_extensions = vec![extensions[0].clone(), extensions[0].clone()];
    group_info.set_extensions(duplicate_extensions);

    // Put everything back together
    group_info.set_signature(group_info.sign(&bob_credential_bundle));

    let encrypted_group_info = welcome_key
        .aead_seal(&group_info.encode_detached().expect("Could not encode GroupInfo"), &[], &welcome_nonce)
        .unwrap();

    welcome.set_encrypted_group_info(encrypted_group_info);

    // Try to join group
    let error = MlsGroup::new_from_welcome(
        welcome,
        None,
        bob_key_package_bundle,
        None,
    )
    .err();

    // We expect an error because the ratchet tree is duplicated
    assert_eq!(
        error.expect("We expected an error"),
        GroupError::WelcomeError(WelcomeError::CodecError(CodecError::DecodingError))
    );
});
