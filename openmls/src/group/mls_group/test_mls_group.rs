use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{CryptoError, HpkeCiphertext},
    OpenMlsCryptoProvider,
};
use tls_codec::Serialize;

use crate::{
    ciphersuite::{signable::Signable, AeadNonce},
    group::{create_commit_params::CreateCommitParams, GroupEpoch},
    messages::{Commit, ConfirmationTag, EncryptedGroupSecrets, GroupInfoPayload, PathSecretError},
    prelude::*,
    schedule::psk::*,
    treesync::treekem::{TreeKemError, UpdatePath, UpdatePathNode},
};

#[test]
fn test_mls_group_persistence() {
    let crypto = OpenMlsRustCrypto::default();
    let ciphersuite = &Config::supported_ciphersuites()[0];

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        &crypto,
    )
    .unwrap();

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        &crypto,
        Vec::new(),
    )
    .unwrap();

    // Alice creates a group
    let alice_group = MlsGroup::builder(GroupId::random(&crypto), alice_key_package_bundle)
        .build(&crypto)
        .expect("Error creating group.");

    let mut file_out = tempfile::NamedTempFile::new().expect("Could not create file");
    alice_group
        .save(&mut file_out)
        .expect("Could not write group state to file");

    let file_in = file_out
        .reopen()
        .expect("Error re-opening serialized group state file");
    let alice_group_deserialized =
        MlsGroup::load(file_in).expect("Could not deserialize managed group");

    assert_eq!(alice_group, alice_group_deserialized);
}

/// This function flips the last byte of the ciphertext.
pub fn flip_last_byte(ctxt: &mut HpkeCiphertext) {
    let mut last_bits = ctxt.ciphertext.pop().unwrap();
    last_bits ^= 0xff;
    ctxt.ciphertext.push(last_bits);
}

#[test]
fn test_failed_groupinfo_decryption() {
    let crypto = OpenMlsRustCrypto::default();
    for version in Config::supported_versions() {
        for ciphersuite in Config::supported_ciphersuites() {
            let epoch = GroupEpoch(123);
            let group_id = GroupId::random(&crypto);
            let tree_hash = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
            let confirmed_transcript_hash = vec![1, 1, 1];
            let extensions = Vec::new();
            let confirmation_tag = ConfirmationTag(Mac {
                mac_value: vec![1, 2, 3, 4, 5, 6, 7, 8, 9].into(),
            });
            let signer_index = LeafIndex::from(8u32);
            let group_info = GroupInfoPayload::new(
                group_id,
                epoch,
                tree_hash,
                confirmed_transcript_hash,
                &Vec::new(),
                &extensions,
                confirmation_tag,
                signer_index,
            );

            // Generate key and nonce for the symmetric cipher.
            let welcome_key = AeadKey::random(ciphersuite, crypto.rand());
            let welcome_nonce = AeadNonce::random(&crypto);

            // Generate receiver key pair.
            let receiver_key_pair = crypto.crypto().derive_hpke_keypair(
                ciphersuite.hpke_config(),
                Secret::random(ciphersuite, &crypto, None)
                    .expect("Not enough randomness.")
                    .as_slice(),
            );
            let hpke_info = b"group info welcome test info";
            let hpke_aad = b"group info welcome test aad";
            let hpke_input = b"these should be the group secrets";
            let mut encrypted_group_secrets = crypto.crypto().hpke_seal(
                ciphersuite.hpke_config(),
                receiver_key_pair.public.as_slice(),
                hpke_info,
                hpke_aad,
                hpke_input,
            );

            let alice_credential_bundle = CredentialBundle::new(
                "Alice".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .unwrap();
            let group_info = group_info
                .sign(&crypto, &alice_credential_bundle)
                .expect("Error signing group info");

            let key_package_bundle = KeyPackageBundle::new(
                &[ciphersuite.name()],
                &alice_credential_bundle,
                &crypto,
                vec![],
            )
            .unwrap();

            // Mess with the ciphertext by flipping the last byte.
            flip_last_byte(&mut encrypted_group_secrets);

            let broken_secrets = vec![EncryptedGroupSecrets {
                key_package_hash: key_package_bundle
                    .key_package
                    .hash(&crypto)
                    .expect("Could not hash KeyPackage.")
                    .into(),
                encrypted_group_secrets,
            }];

            // Encrypt the group info.
            let encrypted_group_info = welcome_key
                .aead_seal(
                    &crypto,
                    &group_info.tls_serialize_detached().unwrap(),
                    &[],
                    &welcome_nonce,
                )
                .unwrap();

            // Now build the welcome message.
            let broken_welcome = Welcome::new(
                *version,
                ciphersuite,
                broken_secrets,
                encrypted_group_info.clone(),
            );

            let error = MlsGroup::new_from_welcome_internal(
                broken_welcome,
                None,
                key_package_bundle,
                None,
                &crypto,
            )
            .expect_err("Creation of MLS group from a broken Welcome was successful.");

            assert_eq!(
                error,
                WelcomeError::CryptoError(CryptoError::HpkeDecryptionError)
            )
        }
    }
}

#[test]
/// Test what happens if the KEM ciphertext for the receiver in the UpdatePath
/// is broken.
fn test_update_path() {
    let crypto = OpenMlsRustCrypto::default();
    for ciphersuite in Config::supported_ciphersuites() {
        // Basic group setup.
        let group_aad = b"Alice's test group";
        let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

        // Define credential bundles
        let alice_credential_bundle = CredentialBundle::new(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            &crypto,
        )
        .unwrap();
        let bob_credential_bundle = CredentialBundle::new(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            &crypto,
        )
        .unwrap();

        // Generate KeyPackages
        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            &crypto,
            Vec::new(),
        )
        .unwrap();

        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            &crypto,
            Vec::new(),
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::builder(GroupId::random(&crypto), alice_key_package_bundle)
            .build(&crypto)
            .expect("Error creating group.");

        // === Alice adds Bob ===
        let bob_add_proposal = alice_group
            .create_add_proposal(
                framing_parameters,
                &alice_credential_bundle,
                bob_key_package.clone(),
                &crypto,
            )
            .expect("Could not create proposal.");
        let proposal_store = ProposalStore::from_staged_proposal(
            StagedProposal::from_mls_plaintext(ciphersuite, &crypto, bob_add_proposal)
                .expect("Could not create StagedProposal."),
        );
        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(&alice_credential_bundle)
            .proposal_store(&proposal_store)
            .force_self_update(false)
            .build();
        let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) = alice_group
            .create_commit(params, &crypto)
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
            mls_plaintext_commit.confirmation_tag()
        );

        let staged_commit = alice_group
            .stage_commit(&mls_plaintext_commit, &proposal_store, &[], None, &crypto)
            .expect("error staging commit");
        alice_group.merge_commit(staged_commit);
        let ratchet_tree = alice_group.tree().public_key_tree_copy();

        let group_bob = MlsGroup::new_from_welcome(
            welcome_bundle_alice_bob_option.unwrap(),
            Some(ratchet_tree),
            bob_key_package_bundle,
            None,
            &crypto,
        )
        .unwrap();

        // === Bob updates and commits ===
        let bob_update_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            &crypto,
            Vec::new(),
        )
        .unwrap();

        let update_proposal_bob = group_bob
            .create_update_proposal(
                framing_parameters,
                &bob_credential_bundle,
                bob_update_key_package_bundle.key_package().clone(),
                &crypto,
            )
            .expect("Could not create proposal.");
        let proposal_store = ProposalStore::from_staged_proposal(
            StagedProposal::from_mls_plaintext(ciphersuite, &crypto, update_proposal_bob)
                .expect("Could not create StagedProposal."),
        );
        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(&bob_credential_bundle)
            .proposal_store(&proposal_store)
            .force_self_update(false)
            .build();
        let (mls_plaintext_commit, _welcome_option, _kpb_option) =
            group_bob.create_commit(params, &crypto).unwrap();

        // Now we break Alice's HPKE ciphertext in Bob's commit by breaking
        // apart the commit, manipulating the ciphertexts and the piecing it
        // back together.
        let commit = match mls_plaintext_commit.content() {
            MlsPlaintextContentType::Commit(commit) => commit,
            _ => panic!("Bob created a commit, which does not contain an actual commit."),
        };

        let commit = commit.clone();

        let path = commit.path.unwrap();

        // For simplicity, let's just break all the ciphertexts.
        let mut new_nodes = Vec::new();
        for node in path.nodes().iter() {
            let mut new_eps = Vec::new();
            for c in node.encrypted_path_secrets.iter() {
                let mut c_copy = c.clone();
                flip_last_byte(&mut c_copy);
                new_eps.push(c_copy);
            }
            let node = UpdatePathNode {
                public_key: node.public_key.clone(),
                encrypted_path_secrets: new_eps.into(),
            };
            new_nodes.push(node);
        }

        let broken_path = UpdatePath::new(path.leaf_key_package().clone(), new_nodes.into());

        // Now let's create a new commit from out broken update path.
        let broken_commit = Commit {
            proposals: commit.proposals.clone(),
            path: Some(broken_path),
        };

        let mut broken_plaintext = MlsPlaintext::new_commit(
            framing_parameters,
            mls_plaintext_commit.sender_index(),
            broken_commit,
            &bob_credential_bundle,
            group_bob.context(),
            &crypto,
        )
        .expect("Could not create plaintext.");

        broken_plaintext
            .set_confirmation_tag(mls_plaintext_commit.confirmation_tag().cloned().unwrap());

        println!(
            "Confirmation tag: {:?}",
            broken_plaintext.confirmation_tag()
        );

        let serialized_context =
            &group_bob.group_context.tls_serialize_detached().unwrap() as &[u8];

        broken_plaintext
            .set_membership_tag(
                &crypto,
                serialized_context,
                group_bob.epoch_secrets.membership_key(),
            )
            .expect("Could not add membership key");

        let staged_commit_res =
            alice_group.stage_commit(&broken_plaintext, &proposal_store, &[], None, &crypto);
        assert_eq!(
            staged_commit_res.expect_err("Successful processing of a broken commit."),
            MlsGroupError::TreeKemError(TreeKemError::PathSecretError(
                PathSecretError::DecryptionError(CryptoError::HpkeDecryptionError)
            ))
        );
    }
}

// Test several scenarios when PSKs are used in a group
ctest_ciphersuites!(test_psks, test(ciphersuite_name: CiphersuiteName) {
    let crypto = OpenMlsRustCrypto::default();
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
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),

        &crypto,
    )
    .unwrap();
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),

        &crypto,
    )
    .unwrap();

    // Generate KeyPackages
    let alice_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle,  &crypto, Vec::new())
            .unwrap();

    let bob_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle,  &crypto, Vec::new())
            .unwrap();
    let bob_key_package = bob_key_package_bundle.key_package();

    // === Alice creates a group with a PSK ===
    let psk_id = vec![1u8, 2, 3];

    let secret = Secret::random(ciphersuite,  &crypto, None /* MLS version */).expect("Not enough randomness.");
    let external_psk_bundle = ExternalPskBundle::new(
        ciphersuite,
        &crypto,
        secret,
        psk_id,
    ).expect("Could not create ExternalPskBundle.");
    let preshared_key_id = external_psk_bundle.to_presharedkey_id();
    let initial_psk = PskSecret::new(
        ciphersuite,
        &crypto,
        &[preshared_key_id.clone()],
        &[external_psk_bundle.secret().clone()],
    ).expect("Could not create PskSecret");
    let mut alice_group = MlsGroup::builder(GroupId::random(&crypto), alice_key_package_bundle)
        .with_psk(initial_psk)
        .build(&crypto)
        .expect("Error creating group.");

    // === Alice creates a PSK proposal ===
    log::info!(" >>> Creating psk proposal ...");
    let psk_proposal = alice_group
        .create_presharedkey_proposal(
            framing_parameters,
            &alice_credential_bundle,
            preshared_key_id,
            &crypto,
        ).expect("Could not create PSK proposal");

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            &crypto,
        ).expect("Could not create proposal");

    let mut proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, &crypto, bob_add_proposal)
            .expect("Could not create StagedProposal."),
    );
    proposal_store.add(
        StagedProposal::from_mls_plaintext(ciphersuite, &crypto, psk_proposal)
            .expect("Could not create StagedProposal."));
    log::info!(" >>> Creating commit ...");
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .psk_fetcher_option(Some(psk_fetcher))
        .build();
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, _kpb_option) = alice_group
        .create_commit(
            params,
            &crypto,
        )
        .expect("Error creating commit");

    log::info!(" >>> Staging & merging commit ...");

    let staged_commit = alice_group
        .stage_commit(
            &mls_plaintext_commit,
            &proposal_store,
            &[],
            Some(psk_fetcher),
            &crypto,
        )
        .expect("error staging commit");
    alice_group.merge_commit(staged_commit);
    let ratchet_tree = alice_group.tree().public_key_tree_copy();

    let group_bob = MlsGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.unwrap(),
        Some(ratchet_tree),
        bob_key_package_bundle,
        Some(psk_fetcher),
        &crypto,
    )
    .expect("Could not create new group from Welcome");

    // === Bob updates and commits ===
    let bob_update_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle,  &crypto, Vec::new())
            .unwrap();

    let update_proposal_bob = group_bob
        .create_update_proposal(
           framing_parameters,
            &bob_credential_bundle,
            bob_update_key_package_bundle.key_package().clone(),
            &crypto,
        )
        .expect("Could not create proposal.");
    let proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, &crypto, update_proposal_bob)
            .expect("Could not create StagedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&bob_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let (_mls_plaintext_commit, _welcome_option, _kpb_option) = group_bob
        .create_commit(params, &crypto)
        .unwrap();

});
