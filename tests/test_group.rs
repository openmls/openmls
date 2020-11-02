use openmls::prelude::*;

#[test]
fn create_commit_optional_path() {
    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_aad = b"Alice's test group";

    // Define identities
    let alice_credential_bundle =
        CredentialBundle::new("Alice".into(), CredentialType::Basic, ciphersuite_name).unwrap();
    let bob_credential_bundle =
        CredentialBundle::new("Bob".into(), CredentialType::Basic, ciphersuite_name).unwrap();

    // Mandatory extensions, will be fixed in #164
    let lifetime_extension = Box::new(LifetimeExtension::new(60));
    let mandatory_extensions: Vec<Box<dyn Extension>> = vec![lifetime_extension];

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite_name],
        &alice_credential_bundle,
        mandatory_extensions.clone(),
    )
    .unwrap();

    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite_name],
        &bob_credential_bundle,
        mandatory_extensions.clone(),
    )
    .unwrap();
    let bob_key_package = bob_key_package_bundle.get_key_package();

    let alice_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite_name],
        &alice_credential_bundle,
        mandatory_extensions,
    )
    .unwrap();
    let alice_update_key_package = alice_update_key_package_bundle.get_key_package();
    assert!(alice_update_key_package.verify().is_ok());

    // Alice creates a group
    let group_id = [1, 2, 3, 4];
    let mut group_alice_1234 = MlsGroup::new(
        &group_id,
        ciphersuite_name,
        alice_key_package_bundle,
        GroupConfig::default(),
    )
    .unwrap();

    // Alice proposes to add Bob with forced self-update
    // Even though there are only Add Proposals, this should generated a path field on the Commit
    let bob_add_proposal = group_alice_1234.create_add_proposal(
        group_aad,
        &alice_credential_bundle,
        bob_key_package.clone(),
    );
    let epoch_proposals = vec![bob_add_proposal];
    let (mls_plaintext_commit, _welcome_bundle_alice_bob_option, kpb_option) =
        match group_alice_1234.create_commit(
            group_aad,
            &alice_credential_bundle,
            epoch_proposals,
            true, /* force self-update */
        ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };
    let commit = match &mls_plaintext_commit.content {
        MLSPlaintextContentType::Commit((commit, _)) => commit,
        _ => panic!(),
    };
    assert!(commit.path.is_some());
    assert!(commit.path.is_some() && kpb_option.is_some());

    // Alice adds Bob without forced self-update
    // Since there are only Add Proposals, this does not generate a path field on the Commit
    // Creating a second proposal to add the same member should not fail, only committing that proposal should fail
    let bob_add_proposal = group_alice_1234.create_add_proposal(
        group_aad,
        &alice_credential_bundle,
        bob_key_package.clone(),
    );
    let epoch_proposals = vec![bob_add_proposal];
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) = match group_alice_1234
        .create_commit(
            group_aad,
            &alice_credential_bundle,
            epoch_proposals.clone(),
            false, /* don't force selfupdate */
        ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
    let commit = match &mls_plaintext_commit.content {
        MLSPlaintextContentType::Commit((commit, _)) => commit,
        _ => panic!(),
    };
    assert!(commit.path.is_none() && kpb_option.is_none());

    // Alice applies the Commit without the forced self-update
    match group_alice_1234.apply_commit(mls_plaintext_commit, epoch_proposals, vec![]) {
        Ok(_) => {}
        Err(e) => panic!("Error applying commit: {:?}", e),
    };
    let ratchet_tree = group_alice_1234.tree().public_key_tree_copy();

    // Bob creates group from Welcome
    let _group_bob_1234 = match MlsGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.unwrap(),
        Some(ratchet_tree),
        bob_key_package_bundle,
    ) {
        Ok(group) => group,
        Err(e) => panic!("Error creating group from Welcome: {:?}", e),
    };

    assert_eq!(
        group_alice_1234.tree().public_key_tree(),
        group_alice_1234.tree().public_key_tree()
    );

    // Alice updates
    let alice_update_proposal = group_alice_1234.create_update_proposal(
        group_aad,
        &alice_credential_bundle,
        alice_update_key_package.clone(),
    );
    let proposals = vec![alice_update_proposal];

    // Only UpdateProposal
    let (commit_mls_plaintext, _welcome_option, kpb_option) = match group_alice_1234.create_commit(
        group_aad,
        &alice_credential_bundle,
        proposals.clone(),
        false, /* force self update */
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
    let (commit, _confirmation_tag) = match &commit_mls_plaintext.content {
        MLSPlaintextContentType::Commit((commit, confirmation_tag)) => (commit, confirmation_tag),
        _ => panic!(),
    };
    assert!(commit.path.is_some() && kpb_option.is_some());

    // Apply UpdateProposal
    group_alice_1234
        .apply_commit(
            commit_mls_plaintext.clone(),
            proposals,
            vec![kpb_option.unwrap()],
        )
        .expect("Error applying commit");
}

#[test]
fn basic_group_setup() {
    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_aad = b"Alice's test group";

    // Define identities
    let alice_credential_bundle =
        CredentialBundle::new("Alice".into(), CredentialType::Basic, ciphersuite_name).unwrap();
    let bob_credential_bundle =
        CredentialBundle::new("Bob".into(), CredentialType::Basic, ciphersuite_name).unwrap();

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite_name],
        &bob_credential_bundle, // TODO: bad API, we shouldn't have to get the private key out here (this function shouldn't exist!)
        Vec::new(),
    )
    .unwrap();
    let bob_key_package = bob_key_package_bundle.get_key_package();

    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite_name],
        &alice_credential_bundle, // TODO: bad API, we shouldn't have to get the private key out here (this function shouldn't exist!)
        Vec::new(),
    )
    .unwrap();

    // Alice creates a group
    let group_id = [1, 2, 3, 4];
    let group_alice_1234 = MlsGroup::new(
        &group_id,
        ciphersuite_name,
        alice_key_package_bundle,
        GroupConfig::default(),
    )
    .unwrap();

    // Alice adds Bob
    let bob_add_proposal = group_alice_1234.create_add_proposal(
        group_aad,
        &alice_credential_bundle,
        bob_key_package.clone(),
    );
    let _commit = match group_alice_1234.create_commit(
        group_aad,
        &alice_credential_bundle,
        vec![bob_add_proposal],
        true,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
}

#[test]
/// This test simulates various group operations like Add, Update, Remove in a small group
///  - Alice creates a group
///  - Alice invites Bob
///  - Alice sends a message to Bob
fn group_operations() {
    let supported_ciphersuites = vec![
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    ];

    for ciphersuite_name in supported_ciphersuites {
        let group_aad = b"Alice's test group";

        // Define identities
        let alice_credential_bundle =
            CredentialBundle::new("Alice".into(), CredentialType::Basic, ciphersuite_name).unwrap();
        let bob_credential_bundle =
            CredentialBundle::new("Bob".into(), CredentialType::Basic, ciphersuite_name).unwrap();

        // Mandatory extensions
        let capabilities_extension = Box::new(CapabilitiesExtension::default());
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Box<dyn Extension>> =
            vec![capabilities_extension, lifetime_extension];

        // Generate KeyPackages
        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite_name],
            &alice_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();

        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite_name],
            &bob_credential_bundle,
            mandatory_extensions,
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.get_key_package();

        // Alice creates a group
        let group_id = [1, 2, 3, 4];
        let mut group_alice_1234 = MlsGroup::new(
            &group_id,
            ciphersuite_name,
            alice_key_package_bundle,
            GroupConfig::default(),
        )
        .unwrap();

        // Alice adds Bob
        let bob_add_proposal = group_alice_1234.create_add_proposal(
            group_aad,
            &alice_credential_bundle,
            bob_key_package.clone(),
        );
        let epoch_proposals = vec![bob_add_proposal];
        let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) =
            match group_alice_1234.create_commit(
                group_aad,
                &alice_credential_bundle,
                epoch_proposals.clone(),
                false,
            ) {
                Ok(c) => c,
                Err(e) => panic!("Error creating commit: {:?}", e),
            };
        let commit = match &mls_plaintext_commit.content {
            MLSPlaintextContentType::Commit((commit, _)) => commit,
            _ => panic!("Wrong content type"),
        };
        assert!(commit.path.is_none() && kpb_option.is_none());
        // Check that the function returned a Welcome message
        assert!(welcome_bundle_alice_bob_option.is_some());

        group_alice_1234
            .apply_commit(mls_plaintext_commit, epoch_proposals, vec![])
            .expect("error applying commit");
        let ratchet_tree = group_alice_1234.tree().public_key_tree_copy();

        let mut group_bob = match MlsGroup::new_from_welcome(
            welcome_bundle_alice_bob_option.unwrap(),
            Some(ratchet_tree),
            bob_key_package_bundle,
        ) {
            Ok(group) => group,
            Err(e) => panic!("Error creating group from Welcome: {:?}", e),
        };

        // Make sure that both groups have the same public tree
        if group_alice_1234.tree().public_key_tree() != group_alice_1234.tree().public_key_tree() {
            _print_tree(&group_alice_1234.tree(), "Alice added Bob");
            panic!("Different public trees");
        }

        // Alice sends a message to Bob
        let message_alice = [1, 2, 3];
        let mls_ciphertext_alice = group_alice_1234.create_application_message(
            &[],
            &message_alice,
            &alice_credential_bundle,
        );
        let mls_plaintext_bob = match group_bob.decrypt(mls_ciphertext_alice) {
            Ok(mls_plaintext) => mls_plaintext,
            Err(e) => panic!("Error decrypting MLSCiphertext: {:?}", e),
        };
        assert_eq!(
            message_alice,
            mls_plaintext_bob.as_application_message().unwrap()
        );
    }
}
/*
    // Bob updates and commits
    let update_proposal_bob = group_bob.create_update_proposal(None);
    let (commit2, ms2, _) = group_bob.create_commit(None);

    group_alice_1234.process_proposal(update_proposal_bob);
    group_alice_1234.process_commit(commit2.clone());
    group_bob.process_commit(commit2);

    group_alice_1234.tree.print(&format!("\n{:?}", ms2));

    // Alice updates and commits
    let update_proposal_alice = group_alice_1234.create_update_proposal(None);
    let (commit3, ms3, _) = group_alice_1234.create_commit(None);

    group_bob.process_proposal(update_proposal_alice);
    group_alice_1234.process_commit(commit3.clone());
    group_bob.process_commit(commit3);

    group_alice_1234.tree.print(&format!("\n{:?}", ms3));

    // Alice updates and Bob commits
    let update_proposal_alice = group_alice_1234.create_update_proposal(None);
    group_bob.process_proposal(update_proposal_alice);
    let (commit4, ms4, _) = group_bob.create_commit(None);

    group_bob.process_commit(commit4.clone());
    group_alice_1234.process_commit(commit4);

    group_alice_1234.tree.print(&format!("\n{:?}", ms4));

    // Bob updates and Alice commits
    let update_proposal_bob = group_bob.create_update_proposal(None);
    group_alice_1234.process_proposal(update_proposal_bob);
    let (commit5, ms5, _) = group_alice_1234.create_commit(None);

    group_alice_1234.process_commit(commit5.clone());
    group_bob.process_commit(commit5);

    group_alice_1234.tree.print(&format!("\n{:?}", ms5));

    // Bob adds Charlie
    let add_proposal = group_bob.create_add_proposal(&charlie_key_package, None);
    group_alice_1234.process_proposal(add_proposal);

    let (commit6, ms6, welcome_bundle_bob_charlie) = group_bob.create_commit(None);

    group_alice_1234.process_commit(commit6.clone());
    group_bob.process_commit(commit6);

    let mut group_charlie = Group::new_from_welcome(
        charlie_identity,
        welcome_bundle_bob_charlie.unwrap(),
        charlie_key_package_bundle,
    );

    group_alice_1234.tree.print(&format!("\n{:?}", ms6));

    // Charlie updates
    let update_proposal_charlie = group_charlie.create_update_proposal(None);

    group_alice_1234.process_proposal(update_proposal_charlie.clone());
    group_bob.process_proposal(update_proposal_charlie);

    let (commit7, ms7, _) = group_charlie.create_commit(None);

    group_alice_1234.process_commit(commit7.clone());
    group_bob.process_commit(commit7.clone());
    group_charlie.process_commit(commit7);

    group_alice_1234.tree.print(&format!("\n{:?}", ms7));

    // Alice updates
    let update_proposal_alice = group_alice_1234.create_update_proposal(None);

    group_bob.process_proposal(update_proposal_alice.clone());
    group_charlie.process_proposal(update_proposal_alice);

    let (commit8, ms8, _) = group_alice_1234.create_commit(None);

    group_alice_1234.process_commit(commit8.clone());
    group_bob.process_commit(commit8.clone());
    group_charlie.process_commit(commit8);

    group_alice_1234.tree.print(&format!("\n{:?}", ms8));

    // Charlie removes Bob
    let remove_proposal_charlie = group_charlie.create_remove_proposal(2, None);

    group_alice_1234.process_proposal(remove_proposal_charlie.clone());
    group_bob.process_proposal(remove_proposal_charlie);

    let (commit9, ms9, _) = group_charlie.create_commit(None);

    group_alice_1234.process_commit(commit9.clone());
    group_bob.process_commit(commit9.clone());
    group_charlie.process_commit(commit9);

    group_alice_1234.tree.print(&format!("\n{:?}", ms9));
}
*/
