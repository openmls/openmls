use crate::{
    ciphersuite::{signable::Signable, AeadNonce},
    group::GroupEpoch,
    messages::{Commit, ConfirmationTag, EncryptedGroupSecrets, GroupInfoPayload},
    prelude::*,
    schedule::psk::*,
    tree::{TreeError, UpdatePath, UpdatePathNode},
};

#[test]
fn test_mls_group_persistence() {
    use std::fs::File;
    use std::path::Path;
    let ciphersuite = &Config::supported_ciphersuites()[0];

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .unwrap();

    // Generate KeyPackages
    let alice_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, Vec::new()).unwrap();

    // Alice creates a group
    let group_id = [1, 2, 3, 4];
    let alice_group = MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        alice_key_package_bundle,
        MlsGroupConfig::default(),
        None, /* Initial PSK */
        None, /* MLS version */
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
            let confirmation_tag = ConfirmationTag(Mac {
                mac_value: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            });
            let signer_index = LeafIndex::from(8u32);
            let group_info = GroupInfoPayload::new(
                group_id,
                epoch,
                tree_hash,
                confirmed_transcript_hash,
                extensions,
                confirmation_tag,
                signer_index,
            );

            // Generate key and nonce for the symmetric cipher.
            let welcome_key = AeadKey::random(ciphersuite);
            let welcome_nonce = AeadNonce::random();

            // Generate receiver key pair.
            let receiver_key_pair =
                ciphersuite.derive_hpke_keypair(&Secret::random(ciphersuite, None));
            let hpke_info = b"group info welcome test info";
            let hpke_aad = b"group info welcome test aad";
            let hpke_input = b"these should be the group secrets";
            let mut encrypted_group_secrets = ciphersuite.hpke_seal(
                receiver_key_pair.public_key(),
                hpke_info,
                hpke_aad,
                hpke_input,
            );

            let alice_credential_bundle = CredentialBundle::new(
                "Alice".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
            )
            .unwrap();
            let group_info = group_info
                .sign(&alice_credential_bundle)
                .expect("Error signing group info");

            let key_package_bundle =
                KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, vec![])
                    .unwrap();

            // Mess with the ciphertext by flipping the last byte.
            encrypted_group_secrets.flip_last_byte();

            let broken_secrets = vec![EncryptedGroupSecrets {
                key_package_hash: key_package_bundle.key_package.hash(),
                encrypted_group_secrets,
            }];

            // Encrypt the group info.
            let encrypted_group_info = welcome_key
                .aead_seal(&group_info.encode_detached().unwrap(), &[], &welcome_nonce)
                .unwrap();

            // Now build the welcome message.
            let broken_welcome = Welcome::new(
                *version,
                ciphersuite,
                broken_secrets,
                encrypted_group_info.clone(),
            );

            let error =
                MlsGroup::new_from_welcome_internal(broken_welcome, None, key_package_bundle, None)
                    .expect_err("Creation of MLS group from a broken Welcome was successful.");

            assert_eq!(
                error,
                WelcomeError::GroupSecretsDecryptionFailure(CryptoError::HpkeDecryptionError)
            )
        }
    }
}

#[test]
/// Test what happens if the KEM ciphertext for the receiver in the UpdatePath
/// is broken.
fn test_update_path() {
    for ciphersuite in Config::supported_ciphersuites() {
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

        // === Alice creates a group ===
        let group_id = [1, 2, 3, 4];
        let mut alice_group = MlsGroup::new(
            &group_id,
            ciphersuite.name(),
            alice_key_package_bundle,
            MlsGroupConfig::default(),
            None, /* Initial PSK */
            None, /* MLS version */
        )
        .unwrap();

        // === Alice adds Bob ===
        let bob_add_proposal = alice_group
            .create_add_proposal(group_aad, &alice_credential_bundle, bob_key_package.clone())
            .expect("Could not create proposal.");
        let epoch_proposals = &[&bob_add_proposal];
        let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) = alice_group
            .create_commit(
                group_aad,
                &alice_credential_bundle,
                epoch_proposals,
                &[],
                false,
                None,
            )
            .expect("Error creating commit");

        let commit = match mls_plaintext_commit.content() {
            MlsPlaintextContentType::Commit(commit) => commit,
            _ => panic!("Wrong content type"),
        };
        assert!(!commit.has_path() && kpb_option.is_none());
        // Check that the function returned a Welcome message
        assert!(welcome_bundle_alice_bob_option.is_some());

        println!(
            " *** Confirmation tag: {:?}",
            mls_plaintext_commit.confirmation_tag
        );

        alice_group
            .apply_commit(&mls_plaintext_commit, epoch_proposals, &[], None)
            .expect("error applying commit");
        let ratchet_tree = alice_group.tree().public_key_tree_copy();

        let group_bob = MlsGroup::new_from_welcome(
            welcome_bundle_alice_bob_option.unwrap(),
            Some(ratchet_tree),
            bob_key_package_bundle,
            None,
        )
        .unwrap();

        // === Bob updates and commits ===
        let bob_update_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, Vec::new())
                .unwrap();

        let update_proposal_bob = group_bob
            .create_update_proposal(
                &[],
                &bob_credential_bundle,
                bob_update_key_package_bundle.key_package().clone(),
            )
            .expect("Could not create proposal.");
        let (mls_plaintext_commit, _welcome_option, _kpb_option) = group_bob
            .create_commit(
                &[],
                &bob_credential_bundle,
                &[&update_proposal_bob],
                &[],
                false, /* force self update */
                None,
            )
            .unwrap();

        // Now we break Alice's HPKE ciphertext in Bob's commit by breaking
        // apart the commit, manipulating the ciphertexts and the piecing it
        // back together.
        let commit = match &mls_plaintext_commit.content {
            MlsPlaintextContentType::Commit(commit) => commit,
            _ => panic!("Bob created a commit, which does not contain an actual commit."),
        };

        let commit = commit.clone();

        let path = commit.path.unwrap();

        // For simplicity, let's just break all the ciphertexts.
        let mut new_nodes = Vec::new();
        for node in path.nodes {
            let mut new_eps = Vec::new();
            for c in node.encrypted_path_secret {
                let mut c_copy = c.clone();
                c_copy.flip_last_byte();
                new_eps.push(c_copy);
            }
            let node = UpdatePathNode {
                public_key: node.public_key.clone(),
                encrypted_path_secret: new_eps,
            };
            new_nodes.push(node);
        }

        let broken_path = UpdatePath {
            leaf_key_package: path.leaf_key_package.clone(),
            nodes: new_nodes,
        };

        // Now let's create a new commit from out broken update path.
        let broken_commit = Commit {
            proposals: commit.proposals.clone(),
            path: Some(broken_path),
        };

        let broken_commit_content = MlsPlaintextContentType::Commit(broken_commit);

        let mut broken_plaintext = MlsPlaintext::new_from_member(
            mls_plaintext_commit.sender.to_leaf_index(),
            &mls_plaintext_commit.authenticated_data,
            broken_commit_content,
            &bob_credential_bundle,
            group_bob.context(),
        )
        .expect("Could not create plaintext.");

        broken_plaintext.confirmation_tag = mls_plaintext_commit.confirmation_tag;

        println!("Confirmation tag: {:?}", broken_plaintext.confirmation_tag);

        let serialized_context = group_bob.group_context.serialized();

        broken_plaintext
            .sign_from_member(&bob_credential_bundle, serialized_context)
            .expect("Could not sign plaintext.");
        broken_plaintext
            .add_membership_tag(serialized_context, group_bob.epoch_secrets.membership_key())
            .expect("Could not add membership key");

        assert_eq!(
            alice_group
                .apply_commit(&broken_plaintext, &[&update_proposal_bob], &[], None)
                .expect_err("Successful processing of a broken commit."),
            MlsGroupError::ApplyCommitError(ApplyCommitError::DecryptionFailure(
                TreeError::PathSecretDecryptionError(CryptoError::HpkeDecryptionError)
            ))
        );
    }
}

// Test several scenarios when PSKs are used in a group
ctest_ciphersuites!(test_psks, test(ciphersuite_name: CiphersuiteName) {
    fn psk_fetcher(psks: &PreSharedKeys, ciphersuite: &'static Ciphersuite) -> Option<Vec<Secret>> {
        let psk_id = vec![1u8, 2, 3];
        let secret = Secret::from_slice(&[6, 6, 6], ProtocolVersion::Mls10, ciphersuite);

        let psk = &psks.psks[0];
        if psk.psk_type == PskType::External {
            if let Psk::External(external_psk) = &psk.psk {
                if external_psk.psk_id() == psk_id {
                    Some(vec![secret])
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }

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

    // === Alice creates a group with a PSK ===
    let group_id = [1, 2, 3, 4];
    let psk_id = vec![1u8, 2, 3];

    let external_psk_bundle = ExternalPskBundle::new(
        ciphersuite,
        Secret::random(ciphersuite, None /* MLS version */),
        psk_id,
    );
    let preshared_key_id = external_psk_bundle.to_presharedkey_id();
    let initial_psk = PskSecret::new(
        ciphersuite,
        &[preshared_key_id.clone()],
        &[external_psk_bundle.secret().clone()],
    ).expect("Could not create PskSecret");
    let mut alice_group = MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        alice_key_package_bundle,
        MlsGroupConfig::default(),
        Some(initial_psk),
        None, /* MLS version */
    )
    .unwrap();

    // === Alice creates a PSK proposal ===
    log::info!(" >>> Creating psk proposal ...");
    let psk_proposal = alice_group
        .create_presharedkey_proposal(group_aad, &alice_credential_bundle, preshared_key_id)
        .expect("Could not create PSK proposal");

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(group_aad, &alice_credential_bundle, bob_key_package.clone())
        .expect("Could not create proposal");
    let epoch_proposals = &[&bob_add_proposal, &psk_proposal];
    log::info!(" >>> Creating commit ...");
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, _kpb_option) = alice_group
        .create_commit(
            group_aad,
            &alice_credential_bundle,
            epoch_proposals,
            &[],
            false,
            Some(psk_fetcher),
        )
        .expect("Error creating commit");

    log::info!(" >>> Applying commit ...");
    alice_group
        .apply_commit(
            &mls_plaintext_commit,
            epoch_proposals,
            &[],
            Some(psk_fetcher),
        )
        .expect("error applying commit");
    let ratchet_tree = alice_group.tree().public_key_tree_copy();

    let group_bob = MlsGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.unwrap(),
        Some(ratchet_tree),
        bob_key_package_bundle,
        Some(psk_fetcher),
    )
    .expect("Could not create new group from Welcome");

    // === Bob updates and commits ===
    let bob_update_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, Vec::new())
            .unwrap();

    let update_proposal_bob = group_bob
        .create_update_proposal(
            &[],
            &bob_credential_bundle,
            bob_update_key_package_bundle.key_package().clone(),
        )
        .expect("Could not create proposal.");
    let (_mls_plaintext_commit, _welcome_option, _kpb_option) = group_bob
        .create_commit(
            &[],
            &bob_credential_bundle,
            &[&update_proposal_bob],
            &[],
            false, /* force self update */
            None,
        )
        .unwrap();

});
