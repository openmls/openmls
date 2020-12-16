use crate::{
    group::GroupEpoch,
    messages::{EncryptedGroupSecrets, GroupInfo},
    prelude::*,
};

#[test]
fn test_mls_group_persistence() {
    use std::fs::File;
    use std::path::Path;
    let ciphersuite = &Config::supported_ciphersuites()[0];

    // Define credential bundles
    let alice_credential_bundle =
        CredentialBundle::new("Alice".into(), CredentialType::Basic, ciphersuite.name()).unwrap();

    // Generate KeyPackages
    let alice_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, Vec::new()).unwrap();

    // Alice creates a group
    let group_id = [1, 2, 3, 4];
    let alice_group = MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        alice_key_package_bundle,
        GroupConfig::default(),
    )
    .unwrap();

    let path = Path::new("target/test_mls_group_serialization.json");
    let out_file = &mut File::create(&path).expect("Could not create file");
    alice_group
        .save(out_file)
        .expect("Could not write group state to file");

    let in_file = File::open(&path).expect("Could not open file");

    let alice_group_deserialized =
        MlsGroup::load(in_file).expect("Could not deserialize managed group");

    assert_eq!(alice_group, alice_group_deserialized);
}

#[test]
fn test_failed_groupinfo_decryption() {
    for version in Config::supported_versions() {
        for ciphersuite in Config::supported_ciphersuites() {
            let epoch = GroupEpoch(123);
            let group_id = GroupId::random();
            let tree_hash = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
            let confirmed_transcript_hash = vec![1, 1, 1];
            let extensions = Vec::new();
            let confirmation_tag = vec![6, 6, 6];
            let signer_index = LeafIndex::from(8u32);
            let group_info = GroupInfo::new(
                group_id,
                epoch,
                tree_hash,
                confirmed_transcript_hash,
                extensions,
                confirmation_tag,
                signer_index,
            );

            // Generate key and nonce for the symmetric cipher.
            let welcome_key = AeadKey::from_random(ciphersuite.aead());
            let welcome_nonce = AeadNonce::from_random();

            // Generate receiver key pair.
            let receiver_key_pair =
                ciphersuite.derive_hpke_keypair(&Secret::from([1u8, 2u8, 3u8, 4u8].to_vec()));
            let hpke_info = b"group info welcome test info";
            let hpke_aad = b"group info welcome test aad";
            let hpke_input = b"these should be the group secrets";
            let encrypted_group_secrets = ciphersuite.hpke_seal(
                receiver_key_pair.public_key(),
                hpke_info,
                hpke_aad,
                hpke_input,
            );

            let alice_credential_bundle =
                CredentialBundle::new("Alice".into(), CredentialType::Basic, ciphersuite.name())
                    .unwrap();

            let key_package_bundle =
                KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, vec![])
                    .unwrap();

            let mut egs_encoded = encrypted_group_secrets.encode_detached().unwrap();

            // Break the encrypted group secrets.
            let last_bit = egs_encoded.pop().unwrap();
            egs_encoded.push(last_bit.reverse_bits());

            let broken_egs = HpkeCiphertext::decode(&mut Cursor::new(&egs_encoded)).unwrap();

            let broken_secrets = vec![EncryptedGroupSecrets {
                key_package_hash: key_package_bundle.key_package.hash(),
                encrypted_group_secrets: broken_egs,
            }];

            // Encrypt the group info.
            let encrypted_group_info = welcome_key
                .aead_seal(&group_info.encode_detached().unwrap(), &[], &welcome_nonce)
                .unwrap();

            // Now build the welcome message.
            let broken_welcome = Welcome::new(
                version.clone(),
                ciphersuite,
                broken_secrets,
                encrypted_group_info.clone(),
            );

            let error =
                MlsGroup::new_from_welcome_internal(broken_welcome, None, key_package_bundle)
                    .expect_err("Creation of MLS group from a broken Welcome was successful.");

            assert_eq!(error, WelcomeError::GroupSecretsDecryptionFailure)
        }
    }
}
