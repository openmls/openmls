use crate::tree::TreeError;
use crate::{
    group::GroupEpoch,
    messages::{Commit, ConfirmationTag, EncryptedGroupSecrets, GroupInfo},
    prelude::*,
    tree::{UpdatePath, UpdatePathNode},
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
            let confirmation_tag = ConfirmationTag::from(vec![6, 6, 6]);
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
                MlsGroup::new_from_welcome_internal(broken_welcome, None, key_package_bundle)
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
        let mut group_alice = MlsGroup::new(
            &group_id,
            ciphersuite.name(),
            alice_key_package_bundle,
            GroupConfig::default(),
        )
        .unwrap();

        // === Alice adds Bob ===
        let bob_add_proposal = group_alice.create_add_proposal(
            group_aad,
            &alice_credential_bundle,
            bob_key_package.clone(),
        );
        let epoch_proposals = &[&bob_add_proposal];
        let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) = group_alice
            .create_commit(
                group_aad,
                &alice_credential_bundle,
                epoch_proposals,
                &[],
                false,
            )
            .expect("Error creating commit");

        let commit = match mls_plaintext_commit.content() {
            MLSPlaintextContentType::Commit(commit) => commit,
            _ => panic!("Wrong content type"),
        };
        assert!(!commit.has_path() && kpb_option.is_none());
        // Check that the function returned a Welcome message
        assert!(welcome_bundle_alice_bob_option.is_some());

        group_alice
            .apply_commit(&mls_plaintext_commit, epoch_proposals, &[])
            .expect("error applying commit");
        let ratchet_tree = group_alice.tree().public_key_tree_copy();

        let group_bob = MlsGroup::new_from_welcome(
            welcome_bundle_alice_bob_option.unwrap(),
            Some(ratchet_tree),
            bob_key_package_bundle,
        )
        .unwrap();

        // === Bob updates and commits ===
        let bob_update_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, Vec::new())
                .unwrap();

        let update_proposal_bob = group_bob.create_update_proposal(
            &[],
            &bob_credential_bundle,
            bob_update_key_package_bundle.key_package().clone(),
        );
        let (mls_plaintext_commit, _welcome_option, _kpb_option) = group_bob
            .create_commit(
                &[],
                &bob_credential_bundle,
                &[&update_proposal_bob],
                &[],
                false, /* force self update */
            )
            .unwrap();

        // Now we break Alice's HPKE ciphertext in Bob's commit by breaking
        // apart the commit, manipulating the ciphertexts and the piecing it
        // back together.
        let commit = match &mls_plaintext_commit.content {
            MLSPlaintextContentType::Commit(commit) => commit,
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

        let broken_commit_content = MLSPlaintextContentType::Commit(broken_commit);

        let mut broken_plaintext = MLSPlaintext::new_from_member(
            ciphersuite,
            mls_plaintext_commit.sender.to_leaf_index(),
            &mls_plaintext_commit.authenticated_data,
            broken_commit_content,
            &bob_credential_bundle,
            group_bob.context(),
            &Secret::random(ciphersuite.hash_length()),
        );

        broken_plaintext.confirmation_tag = Some(ConfirmationTag::from(vec![1, 2, 3]));

        assert_eq!(
            group_alice
                .apply_commit(&broken_plaintext, &[&update_proposal_bob], &[])
                .expect_err("Successful processing of a broken commit."),
            GroupError::ApplyCommitError(ApplyCommitError::DecryptionFailure(
                TreeError::PathSecretDecryptionError(CryptoError::HpkeDecryptionError)
            ))
        );
    }
}
