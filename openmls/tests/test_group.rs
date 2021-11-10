use evercrypt_backend::OpenMlsEvercrypt;
use openmls::{group::create_commit::Proposals, prelude::*};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::AeadType, OpenMlsCryptoProvider};

#[test]
fn create_commit_optional_path() {
    let crypto = OpenMlsRustCrypto::default();
    for ciphersuite in Config::supported_ciphersuites() {
        let group_aad = b"Alice's test group";
        // Framing parameters
        let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

        // Define identities
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

        // Mandatory extensions, will be fixed in #164
        let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Extension> = vec![lifetime_extension];

        // Generate KeyPackages
        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            &crypto,
            mandatory_extensions.clone(),
        )
        .unwrap();

        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            &crypto,
            mandatory_extensions.clone(),
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();

        let alice_update_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            &crypto,
            mandatory_extensions,
        )
        .unwrap();
        let alice_update_key_package = alice_update_key_package_bundle.key_package();
        assert!(alice_update_key_package.verify(&crypto,).is_ok());

        // Alice creates a group
        let group_id = [1, 2, 3, 4];
        let mut group_alice = MlsGroup::new(
            &group_id,
            ciphersuite.name(),
            &crypto,
            alice_key_package_bundle,
            MlsGroupConfig::default(),
            None, /* Initial PSK */
            None, /* MLS version */
        )
        .unwrap();

        // Alice proposes to add Bob with forced self-update
        // Even though there are only Add Proposals, this should generated a path field
        // on the Commit
        let bob_add_proposal = group_alice
            .create_add_proposal(
                framing_parameters,
                &alice_credential_bundle,
                bob_key_package.clone(),
                &crypto,
            )
            .expect("Could not create proposal.");
        let epoch_proposals = vec![bob_add_proposal];
        let (mls_plaintext_commit, _welcome_bundle_alice_bob_option, kpb_option) = match group_alice
            .create_commit(
                framing_parameters,
                &alice_credential_bundle,
                Proposals {
                    proposals_by_reference: &(epoch_proposals
                        .iter()
                        .collect::<Vec<&MlsPlaintext>>()),
                    proposals_by_value: &[],
                },
                true, /* force self-update */
                None, /* No PSK fetcher */
                &crypto,
            ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };
        let commit = match mls_plaintext_commit.content() {
            MlsPlaintextContentType::Commit(commit) => commit,
            _ => panic!(),
        };
        assert!(commit.has_path());
        assert!(commit.has_path() && kpb_option.is_some());

        // Alice adds Bob without forced self-update
        // Since there are only Add Proposals, this does not generate a path field on
        // the Commit Creating a second proposal to add the same member should
        // not fail, only committing that proposal should fail
        let bob_add_proposal = group_alice
            .create_add_proposal(
                framing_parameters,
                &alice_credential_bundle,
                bob_key_package.clone(),
                &crypto,
            )
            .expect("Could not create proposal.");
        let epoch_proposals = &[&bob_add_proposal];
        let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) = match group_alice
            .create_commit(
                framing_parameters,
                &alice_credential_bundle,
                Proposals {
                    proposals_by_reference: epoch_proposals,
                    proposals_by_value: &[],
                },
                false, /* don't force selfupdate */
                None,  /* PSK fetcher */
                &crypto,
            ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };
        let commit = match mls_plaintext_commit.content() {
            MlsPlaintextContentType::Commit(commit) => commit,
            _ => panic!(),
        };
        assert!(!commit.has_path() && kpb_option.is_none());

        // Alice applies the Commit without the forced self-update
        let staged_commit = group_alice
            .stage_commit(&mls_plaintext_commit, epoch_proposals, &[], None, &crypto)
            .expect("Error staging commit");
        group_alice.merge_commit(staged_commit);
        let ratchet_tree = group_alice.tree().public_key_tree_copy();

        // Bob creates group from Welcome
        let group_bob = match MlsGroup::new_from_welcome(
            welcome_bundle_alice_bob_option.unwrap(),
            Some(ratchet_tree),
            bob_key_package_bundle,
            None, /* PSK fetcher */
            &crypto,
        ) {
            Ok(group) => group,
            Err(e) => panic!("Error creating group from Welcome: {:?}", e),
        };

        assert_eq!(
            group_alice.tree().public_key_tree(),
            group_bob.tree().public_key_tree()
        );

        // Alice updates
        let alice_update_proposal = group_alice
            .create_update_proposal(
                framing_parameters,
                &alice_credential_bundle,
                alice_update_key_package.clone(),
                &crypto,
            )
            .expect("Could not create proposal.");
        let proposals = &[&alice_update_proposal];

        // Only UpdateProposal
        let (commit_mls_plaintext, _welcome_option, kpb_option) = match group_alice.create_commit(
            framing_parameters,
            &alice_credential_bundle,
            Proposals {
                proposals_by_reference: proposals,
                proposals_by_value: &[],
            },
            false, /* force self update */
            None,  /* PSK fetcher */
            &crypto,
        ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };
        let commit = match commit_mls_plaintext.content() {
            MlsPlaintextContentType::Commit(commit) => commit,
            _ => panic!(),
        };
        assert!(commit.has_path() && kpb_option.is_some());

        // Apply UpdateProposal
        let staged_commit = group_alice
            .stage_commit(
                &commit_mls_plaintext,
                proposals,
                &[kpb_option.unwrap()],
                None, /* PSK fetcher */
                &crypto,
            )
            .expect("Error staging commit");
        group_alice.merge_commit(staged_commit);
    }
}

#[test]
fn basic_group_setup() {
    let crypto = OpenMlsRustCrypto::default();
    for ciphersuite in Config::supported_ciphersuites() {
        let group_aad = b"Alice's test group";
        // Framing parameters
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
        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            &crypto,
            Vec::new(),
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();

        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            &crypto,
            Vec::new(),
        )
        .unwrap();

        // Alice creates a group
        let group_id = [1, 2, 3, 4];
        let group_alice = MlsGroup::new(
            &group_id,
            ciphersuite.name(),
            &crypto,
            alice_key_package_bundle,
            MlsGroupConfig::default(),
            None, /* Initial PSK */
            None, /* MLS version */
        )
        .expect("Could not create group.");

        // Alice adds Bob
        let bob_add_proposal = group_alice
            .create_add_proposal(
                framing_parameters,
                &alice_credential_bundle,
                bob_key_package.clone(),
                &crypto,
            )
            .expect("Could not create proposal.");
        let _commit = match group_alice.create_commit(
            framing_parameters,
            &alice_credential_bundle,
            Proposals {
                proposals_by_reference: &[&bob_add_proposal],
                proposals_by_value: &[],
            },
            true,
            None, /* PSK fetcher */
            &crypto,
        ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };
    }
}

fn do_group_operations<Crypto: OpenMlsCryptoProvider>(crypto: Crypto, ciphersuite: &Ciphersuite) {
    let group_aad = b"Alice's test group";
    // Framing parameters
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

    // Mandatory extensions
    let capabilities_extension = Extension::Capabilities(CapabilitiesExtension::new(
        None,
        Some(&[ciphersuite.name()]),
        None,
    ));
    let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
    let mandatory_extensions: Vec<Extension> = vec![capabilities_extension, lifetime_extension];

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        &crypto,
        mandatory_extensions.clone(),
    )
    .unwrap();

    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        &crypto,
        mandatory_extensions.clone(),
    )
    .unwrap();
    let bob_key_package = bob_key_package_bundle.key_package();

    // === Alice creates a group ===
    let group_id = [1, 2, 3, 4];
    let mut group_alice = MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        &crypto,
        alice_key_package_bundle,
        MlsGroupConfig::default(),
        None, /* Initial PSK */
        None, /* MLS version */
    )
    .expect("Could not create group.");

    // === Alice adds Bob ===
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            &crypto,
        )
        .expect("Could not create proposal.");
    let epoch_proposals = &[&bob_add_proposal];
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) = group_alice
        .create_commit(
            framing_parameters,
            &alice_credential_bundle,
            Proposals {
                proposals_by_reference: epoch_proposals,
                proposals_by_value: &[],
            },
            false,
            None, /* PSK fetcher */
            &crypto,
        )
        .expect("Error creating commit");
    let commit = match mls_plaintext_commit.content() {
        MlsPlaintextContentType::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(!commit.has_path() && kpb_option.is_none());
    // Check that the function returned a Welcome message
    assert!(welcome_bundle_alice_bob_option.is_some());

    let staged_commit = group_alice
        .stage_commit(
            &mls_plaintext_commit,
            epoch_proposals,
            &[],
            None, /* PSK fetcher */
            &crypto,
        )
        .expect("Error staging commit");
    group_alice.merge_commit(staged_commit);
    let ratchet_tree = group_alice.tree().public_key_tree_copy();

    let mut group_bob = match MlsGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.unwrap(),
        Some(ratchet_tree),
        bob_key_package_bundle,
        None, /* PSK fetcher */
        &crypto,
    ) {
        Ok(group) => group,
        Err(e) => panic!("Error creating group from Welcome: {:?}", e),
    };

    // Make sure that both groups have the same public tree
    if group_alice.tree().public_key_tree() != group_bob.tree().public_key_tree() {
        _print_tree(&group_alice.tree(), "Alice added Bob");
        panic!("Different public trees");
    }
    // Make sure that both groups have the same group context
    if group_alice.context() != group_bob.context() {
        panic!("Different group contexts");
    }

    // === Alice sends a message to Bob ===
    let message_alice = [1, 2, 3];
    let mls_ciphertext_alice = group_alice
        .create_application_message(&[], &message_alice, &alice_credential_bundle, 0, &crypto)
        .unwrap();
    let mls_plaintext_bob = match group_bob.decrypt(&mls_ciphertext_alice, &crypto) {
        Ok(mls_plaintext) => mls_plaintext,
        Err(e) => panic!("Error decrypting MlsCiphertext: {:?}", e),
    };
    assert_eq!(
        message_alice,
        mls_plaintext_bob.as_application_message().unwrap()
    );

    // === Bob updates and commits ===
    let bob_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        &crypto,
        mandatory_extensions.clone(),
    )
    .expect("Could not create key package bundle.");

    let update_proposal_bob = group_bob
        .create_update_proposal(
            framing_parameters,
            &bob_credential_bundle,
            bob_update_key_package_bundle.key_package().clone(),
            &crypto,
        )
        .expect("Could not create proposal.");
    let (mls_plaintext_commit, welcome_option, kpb_option) = match group_bob.create_commit(
        framing_parameters,
        &bob_credential_bundle,
        Proposals {
            proposals_by_reference: &[&update_proposal_bob],
            proposals_by_value: &[],
        },
        false, /* force self update */
        None,  /* PSK fetcher */
        &crypto,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    // Check that there is a new KeyPackageBundle
    assert!(kpb_option.is_some());
    // Check there is no Welcome message
    assert!(welcome_option.is_none());

    let staged_commit = group_alice
        .stage_commit(
            &mls_plaintext_commit,
            &[&update_proposal_bob],
            &[],
            None, /* PSK fetcher */
            &crypto,
        )
        .expect("Error applying commit (Alice)");
    group_alice.merge_commit(staged_commit);
    let staged_commit = group_bob
        .stage_commit(
            &mls_plaintext_commit,
            &[&update_proposal_bob],
            &[kpb_option.unwrap()],
            None, /* PSK fetcher */
            &crypto,
        )
        .expect("Error applying commit (Bob)");
    group_bob.merge_commit(staged_commit);

    // Make sure that both groups have the same public tree
    if group_alice.tree().public_key_tree() != group_bob.tree().public_key_tree() {
        _print_tree(&group_alice.tree(), "Alice added Bob");
        panic!("Different public trees");
    }

    // === Alice updates and commits ===
    let alice_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        &crypto,
        mandatory_extensions.clone(),
    )
    .expect("Could not create key package bundle.");

    let update_proposal_alice = group_alice
        .create_update_proposal(
            framing_parameters,
            &alice_credential_bundle,
            alice_update_key_package_bundle.key_package().clone(),
            &crypto,
        )
        .expect("Could not create proposal.");
    let (mls_plaintext_commit, _, kpb_option) = match group_alice.create_commit(
        framing_parameters,
        &alice_credential_bundle,
        Proposals {
            proposals_by_reference: &[&update_proposal_alice],
            proposals_by_value: &[],
        },
        false, /* force self update */
        None,  /* PSK fetcher */
        &crypto,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    // Check that there is a new KeyPackageBundle
    assert!(kpb_option.is_some());

    let staged_commit = group_alice
        .stage_commit(
            &mls_plaintext_commit,
            &[&update_proposal_alice],
            &[kpb_option.unwrap()],
            None, /* PSK fetcher */
            &crypto,
        )
        .expect("Error applying commit (Alice)");
    group_alice.merge_commit(staged_commit);
    let staged_commit = group_bob
        .stage_commit(
            &mls_plaintext_commit,
            &[&update_proposal_alice],
            &[],
            None, /* PSK fetcher */
            &crypto,
        )
        .expect("Error applying commit (Bob)");
    group_bob.merge_commit(staged_commit);

    // Make sure that both groups have the same public tree
    if group_alice.tree().public_key_tree() != group_bob.tree().public_key_tree() {
        _print_tree(&group_alice.tree(), "Alice added Bob");
        panic!("Different public trees");
    }

    // === Bob updates and Alice commits ===
    let bob_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        &crypto,
        mandatory_extensions.clone(),
    )
    .expect("Could not create key package bundle.");

    let update_proposal_bob = group_bob
        .create_update_proposal(
            framing_parameters,
            &bob_credential_bundle,
            bob_update_key_package_bundle.key_package().clone(),
            &crypto,
        )
        .expect("Could not create proposal.");
    let (mls_plaintext_commit, _, kpb_option) = match group_alice.create_commit(
        framing_parameters,
        &alice_credential_bundle,
        Proposals {
            proposals_by_reference: &[&update_proposal_bob],
            proposals_by_value: &[],
        },
        false, /* force self update */
        None,  /* PSK fetcher */
        &crypto,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    // Check that there is a new KeyPackageBundle
    assert!(kpb_option.is_some());

    let staged_commit = group_alice
        .stage_commit(
            &mls_plaintext_commit,
            &[&update_proposal_bob],
            &[kpb_option.unwrap()],
            None,
            /* PSK fetcher */ &crypto,
        )
        .expect("Error applying commit (Alice)");
    group_alice.merge_commit(staged_commit);
    let staged_commit = group_bob
        .stage_commit(
            &mls_plaintext_commit,
            &[&update_proposal_bob],
            &[bob_update_key_package_bundle],
            None,
            /* PSK fetcher */ &crypto,
        )
        .expect("Error applying commit (Bob)");
    group_bob.merge_commit(staged_commit);

    // Make sure that both groups have the same public tree
    if group_alice.tree().public_key_tree() != group_bob.tree().public_key_tree() {
        _print_tree(&group_alice.tree(), "Alice added Bob");
        panic!("Different public trees");
    }

    // === Bob adds Charlie ===
    let charlie_credential_bundle = CredentialBundle::new(
        "Charlie".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        &crypto,
    )
    .unwrap();

    let charlie_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &charlie_credential_bundle,
        &crypto,
        mandatory_extensions.clone(),
    )
    .expect("Could not create key package bundle.");
    let charlie_key_package = charlie_key_package_bundle.key_package().clone();

    let add_charlie_proposal_bob = group_bob
        .create_add_proposal(
            framing_parameters,
            &bob_credential_bundle,
            charlie_key_package,
            &crypto,
        )
        .expect("Could not create proposal.");

    let (mls_plaintext_commit, welcome_for_charlie_option, kpb_option) = match group_bob
        .create_commit(
            framing_parameters,
            &bob_credential_bundle,
            Proposals {
                proposals_by_reference: &[&add_charlie_proposal_bob],
                proposals_by_value: &[],
            },
            false, /* force self update */
            None,  /* PSK fetcher */
            &crypto,
        ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    // Check there is no KeyPackageBundle since there are only Add Proposals and no
    // forced self-update
    assert!(kpb_option.is_none());
    // Make sure the is a Welcome message for Charlie
    assert!(welcome_for_charlie_option.is_some());

    let staged_commit = group_alice
        .stage_commit(
            &mls_plaintext_commit,
            &[&add_charlie_proposal_bob],
            &[],
            None,
            /* PSK fetcher */ &crypto,
        )
        .expect("Error applying commit (Alice)");
    group_alice.merge_commit(staged_commit);
    let staged_commit = group_bob
        .stage_commit(
            &mls_plaintext_commit,
            &[&add_charlie_proposal_bob],
            &[],
            None,
            /* PSK fetcher */ &crypto,
        )
        .expect("Error applying commit (Bob)");
    group_bob.merge_commit(staged_commit);

    let ratchet_tree = group_alice.tree().public_key_tree_copy();
    let mut group_charlie = match MlsGroup::new_from_welcome(
        welcome_for_charlie_option.unwrap(),
        Some(ratchet_tree),
        charlie_key_package_bundle,
        None,
        /* PSK fetcher */ &crypto,
    ) {
        Ok(group) => group,
        Err(e) => panic!("Error creating group from Welcome: {:?}", e),
    };

    // Make sure that all groups have the same public tree
    if group_alice.tree().public_key_tree() != group_bob.tree().public_key_tree() {
        _print_tree(&group_alice.tree(), "Bob added Charlie");
        panic!("Different public trees");
    }
    if group_alice.tree().public_key_tree() != group_charlie.tree().public_key_tree() {
        _print_tree(&group_alice.tree(), "Bob added Charlie");
        panic!("Different public trees");
    }

    // === Charlie sends a message to the group ===
    let message_charlie = [1, 2, 3];
    let mls_ciphertext_charlie = group_charlie
        .create_application_message(
            &[],
            &message_charlie,
            &charlie_credential_bundle,
            0,
            &crypto,
        )
        .unwrap();
    let mls_plaintext_alice = match group_alice.decrypt(&mls_ciphertext_charlie.clone(), &crypto) {
        Ok(mls_plaintext) => mls_plaintext,
        Err(e) => panic!("Error decrypting MlsCiphertext: {:?}", e),
    };
    let mls_plaintext_bob = match group_bob.decrypt(&mls_ciphertext_charlie, &crypto) {
        Ok(mls_plaintext) => mls_plaintext,
        Err(e) => panic!("Error decrypting MlsCiphertext: {:?}", e),
    };
    assert_eq!(
        message_charlie,
        mls_plaintext_alice.as_application_message().unwrap()
    );
    assert_eq!(
        message_charlie,
        mls_plaintext_bob.as_application_message().unwrap()
    );

    // === Charlie updates and commits ===
    let charlie_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &charlie_credential_bundle,
        &crypto,
        mandatory_extensions.clone(),
    )
    .expect("Could not create key package bundle.");

    let update_proposal_charlie = group_charlie
        .create_update_proposal(
            framing_parameters,
            &charlie_credential_bundle,
            charlie_update_key_package_bundle.key_package().clone(),
            &crypto,
        )
        .expect("Could not create proposal.");
    let (mls_plaintext_commit, _, kpb_option) = match group_charlie.create_commit(
        framing_parameters,
        &charlie_credential_bundle,
        Proposals {
            proposals_by_reference: &[&update_proposal_charlie],
            proposals_by_value: &[],
        },
        false, /* force self update */
        None,  /* PSK fetcher */
        &crypto,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    // Check that there is a new KeyPackageBundle
    assert!(kpb_option.is_some());

    let staged_commit = group_alice
        .stage_commit(
            &mls_plaintext_commit,
            &[&update_proposal_charlie],
            &[],
            None,
            /* PSK fetcher */ &crypto,
        )
        .expect("Error applying commit (Alice)");
    group_alice.merge_commit(staged_commit);
    let staged_commit = group_bob
        .stage_commit(
            &mls_plaintext_commit,
            &[&update_proposal_charlie],
            &[],
            None,
            /* PSK fetcher */ &crypto,
        )
        .expect("Error applying commit (Bob)");
    group_bob.merge_commit(staged_commit);
    let staged_commit = group_charlie
        .stage_commit(
            &mls_plaintext_commit,
            &[&update_proposal_charlie],
            &[kpb_option.unwrap()],
            None,
            /* PSK fetcher */ &crypto,
        )
        .expect("Error applying commit (Charlie)");
    group_charlie.merge_commit(staged_commit);

    // Make sure that all groups have the same public tree
    if group_alice.tree().public_key_tree() != group_bob.tree().public_key_tree() {
        _print_tree(&group_alice.tree(), "Charlie updated");
        panic!("Different public trees");
    }
    if group_alice.tree().public_key_tree() != group_charlie.tree().public_key_tree() {
        _print_tree(&group_alice.tree(), "Charlie updated");
        panic!("Different public trees");
    }

    // === Charlie removes Bob ===
    let remove_bob_proposal_charlie = group_charlie
        .create_remove_proposal(
            framing_parameters,
            &charlie_credential_bundle,
            LeafIndex::from(1u32),
            &crypto,
        )
        .expect("Could not create proposal.");
    let (mls_plaintext_commit, _, kpb_option) = match group_charlie.create_commit(
        framing_parameters,
        &charlie_credential_bundle,
        Proposals {
            proposals_by_reference: &[&remove_bob_proposal_charlie],
            proposals_by_value: &[],
        },
        false, /* force self update */
        None,  /* PSK fetcher */
        &crypto,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    // Check that there is a new KeyPackageBundle
    assert!(kpb_option.is_some());

    let staged_commit = group_alice
        .stage_commit(
            &mls_plaintext_commit,
            &[&remove_bob_proposal_charlie],
            &[],
            None,
            /* PSK fetcher */ &crypto,
        )
        .expect("Error applying commit (Alice)");
    group_alice.merge_commit(staged_commit);
    assert!(
        group_bob
            .stage_commit(
                &mls_plaintext_commit,
                &[&remove_bob_proposal_charlie],
                &[],
                None,
                /* PSK fetcher */ &crypto,
            )
            .unwrap_err()
            == MlsGroupError::StageCommitError(StageCommitError::SelfRemoved)
    );
    let staged_commit = group_charlie
        .stage_commit(
            &mls_plaintext_commit,
            &[&remove_bob_proposal_charlie],
            &[kpb_option.unwrap()],
            None,
            /* PSK fetcher */ &crypto,
        )
        .expect("Error applying commit (Charlie)");
    group_charlie.merge_commit(staged_commit);

    // Make sure that all groups have the same public tree
    if group_alice.tree().public_key_tree() == group_bob.tree().public_key_tree() {
        _print_tree(&group_alice.tree(), "Charlie removed Bob");
        panic!("Same public trees");
    }
    if group_alice.tree().public_key_tree() != group_charlie.tree().public_key_tree() {
        _print_tree(&group_alice.tree(), "Charlie removed Bob");
        panic!("Different public trees");
    }

    // Make sure all groups export the same key
    let alice_exporter = group_alice
        .export_secret(&crypto, "export test", &[], 32)
        .unwrap();
    let charlie_exporter = group_charlie
        .export_secret(&crypto, "export test", &[], 32)
        .unwrap();
    assert_eq!(alice_exporter, charlie_exporter);

    // Now alice tries to derive an exporter with too large of a key length.
    let exporter_length: usize = u16::MAX.into();
    let exporter_length = exporter_length + 1;
    let alice_exporter = group_alice.export_secret(&crypto, "export test", &[], exporter_length);
    assert!(alice_exporter.is_err())
}

#[test]
/// This test simulates various group operations like Add, Update, Remove in a
/// small group
///  - Alice creates a group
///  - Alice adds Bob
///  - Alice sends a message to Bob
///  - Bob updates and commits
///  - Alice updates and commits
///  - Bob updates and Alice commits
///  - Bob adds Charlie
///  - Charlie sends a message to the group
///  - Charlie updates and commits
///  - Charlie removes Bob
fn group_operations() {
    for ciphersuite in Config::supported_ciphersuites() {
        if ciphersuite.aead() == AeadType::ChaCha20Poly1305 {
            do_group_operations(OpenMlsEvercrypt::default(), ciphersuite);
        }
        do_group_operations(OpenMlsRustCrypto::default(), ciphersuite);
    }
}
