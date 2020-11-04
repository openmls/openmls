use openmls::prelude::*;

#[test]
fn create_commit_optional_path() {
    for ciphersuite in Config::supported_ciphersuites() {
        let group_aad = b"Alice's test group";

        // Define identities
        let alice_credential_bundle =
            CredentialBundle::new("Alice".into(), CredentialType::Basic, ciphersuite.name())
                .unwrap();
        let bob_credential_bundle =
            CredentialBundle::new("Bob".into(), CredentialType::Basic, ciphersuite.name()).unwrap();

        // Mandatory extensions, will be fixed in #164
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Box<dyn Extension>> = vec![lifetime_extension];

        // Generate KeyPackages
        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();

        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.get_key_package();

        let alice_update_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            mandatory_extensions,
        )
        .unwrap();
        let alice_update_key_package = alice_update_key_package_bundle.get_key_package();
        assert!(alice_update_key_package.verify().is_ok());

        // Alice creates a group
        let group_id = [1, 2, 3, 4];
        let mut group_alice = MlsGroup::new(
            &group_id,
            ciphersuite.name(),
            alice_key_package_bundle,
            GroupConfig::default(),
        )
        .unwrap();

        // Alice proposes to add Bob with forced self-update
        // Even though there are only Add Proposals, this should generated a path field on the Commit
        let bob_add_proposal = group_alice.create_add_proposal(
            group_aad,
            &alice_credential_bundle,
            bob_key_package.clone(),
        );
        let epoch_proposals = vec![bob_add_proposal];
        let (mls_plaintext_commit, _welcome_bundle_alice_bob_option, kpb_option) = match group_alice
            .create_commit(
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
        let bob_add_proposal = group_alice.create_add_proposal(
            group_aad,
            &alice_credential_bundle,
            bob_key_package.clone(),
        );
        let epoch_proposals = vec![bob_add_proposal];
        let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) = match group_alice
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
        match group_alice.apply_commit(mls_plaintext_commit, epoch_proposals, &[]) {
            Ok(_) => {}
            Err(e) => panic!("Error applying commit: {:?}", e),
        };
        let ratchet_tree = group_alice.tree().public_key_tree_copy();

        // Bob creates group from Welcome
        let _group_bob = match MlsGroup::new_from_welcome(
            welcome_bundle_alice_bob_option.unwrap(),
            Some(ratchet_tree),
            bob_key_package_bundle,
        ) {
            Ok(group) => group,
            Err(e) => panic!("Error creating group from Welcome: {:?}", e),
        };

        assert_eq!(
            group_alice.tree().public_key_tree(),
            group_alice.tree().public_key_tree()
        );

        // Alice updates
        let alice_update_proposal = group_alice.create_update_proposal(
            group_aad,
            &alice_credential_bundle,
            alice_update_key_package.clone(),
        );
        let proposals = vec![alice_update_proposal];

        // Only UpdateProposal
        let (commit_mls_plaintext, _welcome_option, kpb_option) = match group_alice.create_commit(
            group_aad,
            &alice_credential_bundle,
            proposals.clone(),
            false, /* force self update */
        ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };
        let (commit, _confirmation_tag) = match &commit_mls_plaintext.content {
            MLSPlaintextContentType::Commit((commit, confirmation_tag)) => {
                (commit, confirmation_tag)
            }
            _ => panic!(),
        };
        assert!(commit.path.is_some() && kpb_option.is_some());

        // Apply UpdateProposal
        group_alice
            .apply_commit(
                commit_mls_plaintext.clone(),
                proposals,
                &[kpb_option.unwrap()],
            )
            .expect("Error applying commit");
    }
}

#[test]
fn basic_group_setup() {
    for ciphersuite in Config::supported_ciphersuites() {
        let group_aad = b"Alice's test group";

        // Define identities
        let alice_credential_bundle =
            CredentialBundle::new("Alice".into(), CredentialType::Basic, ciphersuite.name())
                .unwrap();
        let bob_credential_bundle =
            CredentialBundle::new("Bob".into(), CredentialType::Basic, ciphersuite.name()).unwrap();

        // Generate KeyPackages
        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle, // TODO: bad API, we shouldn't have to get the private key out here (this function shouldn't exist!)
            Vec::new(),
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.get_key_package();

        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle, // TODO: bad API, we shouldn't have to get the private key out here (this function shouldn't exist!)
            Vec::new(),
        )
        .unwrap();

        // Alice creates a group
        let group_id = [1, 2, 3, 4];
        let group_alice = MlsGroup::new(
            &group_id,
            ciphersuite.name(),
            alice_key_package_bundle,
            GroupConfig::default(),
        )
        .unwrap();

        // Alice adds Bob
        let bob_add_proposal = group_alice.create_add_proposal(
            group_aad,
            &alice_credential_bundle,
            bob_key_package.clone(),
        );
        let _commit = match group_alice.create_commit(
            group_aad,
            &alice_credential_bundle,
            vec![bob_add_proposal],
            true,
        ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };
    }
}

#[test]
/// This test simulates various group operations like Add, Update, Remove in a small group
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
        let group_aad = b"Alice's test group";

        // Define identities
        let alice_credential_bundle =
            CredentialBundle::new("Alice".into(), CredentialType::Basic, ciphersuite.name())
                .unwrap();
        let bob_credential_bundle =
            CredentialBundle::new("Bob".into(), CredentialType::Basic, ciphersuite.name()).unwrap();

        // Mandatory extensions
        let capabilities_extension = Box::new(CapabilitiesExtension::default());
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Box<dyn Extension>> =
            vec![capabilities_extension, lifetime_extension];

        // Generate KeyPackages
        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();

        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.get_key_package();

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
        let epoch_proposals = vec![bob_add_proposal];
        let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) = match group_alice
            .create_commit(
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

        group_alice
            .apply_commit(mls_plaintext_commit, epoch_proposals, &[])
            .expect("error applying commit");
        let ratchet_tree = group_alice.tree().public_key_tree_copy();

        let mut group_bob = match MlsGroup::new_from_welcome(
            welcome_bundle_alice_bob_option.unwrap(),
            Some(ratchet_tree),
            bob_key_package_bundle,
        ) {
            Ok(group) => group,
            Err(e) => panic!("Error creating group from Welcome: {:?}", e),
        };

        // Make sure that both groups have the same public tree
        if group_alice.tree().public_key_tree() != group_bob.tree().public_key_tree() {
            _print_tree(&group_alice.tree(), "Alice added Bob");
            panic!("Different public trees");
        }

        // === Alice sends a message to Bob ===
        let message_alice = [1, 2, 3];
        let mls_ciphertext_alice =
            group_alice.create_application_message(&[], &message_alice, &alice_credential_bundle);
        let mls_plaintext_bob = match group_bob.decrypt(mls_ciphertext_alice) {
            Ok(mls_plaintext) => mls_plaintext,
            Err(e) => panic!("Error decrypting MLSCiphertext: {:?}", e),
        };
        assert_eq!(
            message_alice,
            mls_plaintext_bob.as_application_message().unwrap()
        );

        // === Bob updates and commits ===
        let bob_update_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();

        let update_proposal_bob = group_bob.create_update_proposal(
            &[],
            &bob_credential_bundle,
            bob_update_key_package_bundle.get_key_package().clone(),
        );
        let (mls_plaintext_commit, welcome_option, kpb_option) = match group_bob.create_commit(
            &[],
            &bob_credential_bundle,
            vec![update_proposal_bob.clone()],
            false, /* force self update*/
        ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };

        // Check that there is a new KeyPackageBundle
        assert!(kpb_option.is_some());
        // Check there is no Welcome message
        assert!(welcome_option.is_none());

        group_alice
            .apply_commit(
                mls_plaintext_commit.clone(),
                vec![update_proposal_bob.clone()],
                &[],
            )
            .expect("Error applying commit (Alice)");
        group_bob
            .apply_commit(
                mls_plaintext_commit,
                vec![update_proposal_bob],
                &[kpb_option.unwrap()],
            )
            .expect("Error applying commit (Bob)");

        // Make sure that both groups have the same public tree
        if group_alice.tree().public_key_tree() != group_bob.tree().public_key_tree() {
            _print_tree(&group_alice.tree(), "Alice added Bob");
            panic!("Different public trees");
        }

        // === Alice updates and commits ===
        let alice_update_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();

        let update_proposal_alice = group_alice.create_update_proposal(
            &[],
            &alice_credential_bundle,
            alice_update_key_package_bundle.get_key_package().clone(),
        );
        let (mls_plaintext_commit, _, kpb_option) = match group_alice.create_commit(
            &[],
            &alice_credential_bundle,
            vec![update_proposal_alice.clone()],
            false, /* force self update*/
        ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };

        // Check that there is a new KeyPackageBundle
        assert!(kpb_option.is_some());

        group_alice
            .apply_commit(
                mls_plaintext_commit.clone(),
                vec![update_proposal_alice.clone()],
                &[kpb_option.unwrap()],
            )
            .expect("Error applying commit (Alice)");
        group_bob
            .apply_commit(
                mls_plaintext_commit.clone(),
                vec![update_proposal_alice],
                &[],
            )
            .expect("Error applying commit (Bob)");

        // Make sure that both groups have the same public tree
        if group_alice.tree().public_key_tree() != group_bob.tree().public_key_tree() {
            _print_tree(&group_alice.tree(), "Alice added Bob");
            panic!("Different public trees");
        }

        // === Bob updates and Alice commits ===
        let bob_update_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();

        let update_proposal_bob = group_bob.create_update_proposal(
            &[],
            &bob_credential_bundle,
            bob_update_key_package_bundle.get_key_package().clone(),
        );
        let (mls_plaintext_commit, _, kpb_option) = match group_alice.create_commit(
            &[],
            &alice_credential_bundle,
            vec![update_proposal_bob.clone()],
            false, /* force self update*/
        ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };

        // Check that there is a new KeyPackageBundle
        assert!(kpb_option.is_some());

        group_alice
            .apply_commit(
                mls_plaintext_commit.clone(),
                vec![update_proposal_bob.clone()],
                &[kpb_option.unwrap()],
            )
            .expect("Error applying commit (Alice)");
        group_bob
            .apply_commit(
                mls_plaintext_commit.clone(),
                vec![update_proposal_bob],
                &[bob_update_key_package_bundle],
            )
            .expect("Error applying commit (Bob)");

        // Make sure that both groups have the same public tree
        if group_alice.tree().public_key_tree() != group_bob.tree().public_key_tree() {
            _print_tree(&group_alice.tree(), "Alice added Bob");
            panic!("Different public trees");
        }

        // === Bob adds Charlie ===
        let charlie_credential_bundle =
            CredentialBundle::new("Charlie".into(), CredentialType::Basic, ciphersuite.name())
                .unwrap();

        let charlie_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &charlie_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();
        let charlie_key_package = charlie_key_package_bundle.get_key_package().clone();

        let add_charlie_proposal_bob =
            group_bob.create_add_proposal(&[], &bob_credential_bundle, charlie_key_package);

        let (mls_plaintext_commit, welcome_for_charlie_option, kpb_option) = match group_bob
            .create_commit(
                &[],
                &bob_credential_bundle,
                vec![add_charlie_proposal_bob.clone()],
                false, /* force self update*/
            ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };

        // Check there is no KeyPackageBundle since there are only Add Proposals and no forced self-update
        assert!(kpb_option.is_none());
        // Make sure the is a Welcome message for Charlie
        assert!(welcome_for_charlie_option.is_some());

        group_alice
            .apply_commit(
                mls_plaintext_commit.clone(),
                vec![add_charlie_proposal_bob.clone()],
                &[],
            )
            .expect("Error applying commit (Alice)");
        group_bob
            .apply_commit(
                mls_plaintext_commit.clone(),
                vec![add_charlie_proposal_bob],
                &[],
            )
            .expect("Error applying commit (Bob)");

        let ratchet_tree = group_alice.tree().public_key_tree_copy();
        let mut group_charlie = match MlsGroup::new_from_welcome(
            welcome_for_charlie_option.unwrap(),
            Some(ratchet_tree),
            charlie_key_package_bundle,
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
        let mls_ciphertext_charlie = group_charlie.create_application_message(
            &[],
            &message_charlie,
            &charlie_credential_bundle,
        );
        let mls_plaintext_alice = match group_alice.decrypt(mls_ciphertext_charlie.clone()) {
            Ok(mls_plaintext) => mls_plaintext,
            Err(e) => panic!("Error decrypting MLSCiphertext: {:?}", e),
        };
        let mls_plaintext_bob = match group_bob.decrypt(mls_ciphertext_charlie) {
            Ok(mls_plaintext) => mls_plaintext,
            Err(e) => panic!("Error decrypting MLSCiphertext: {:?}", e),
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
            mandatory_extensions.clone(),
        )
        .unwrap();

        let update_proposal_charlie = group_charlie.create_update_proposal(
            &[],
            &charlie_credential_bundle,
            charlie_update_key_package_bundle.get_key_package().clone(),
        );
        let (mls_plaintext_commit, _, kpb_option) = match group_charlie.create_commit(
            &[],
            &charlie_credential_bundle,
            vec![update_proposal_charlie.clone()],
            false, /* force self update*/
        ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };

        // Check that there is a new KeyPackageBundle
        assert!(kpb_option.is_some());

        group_alice
            .apply_commit(
                mls_plaintext_commit.clone(),
                vec![update_proposal_charlie.clone()],
                &[],
            )
            .expect("Error applying commit (Alice)");
        group_bob
            .apply_commit(
                mls_plaintext_commit.clone(),
                vec![update_proposal_charlie.clone()],
                &[],
            )
            .expect("Error applying commit (Bob)");
        group_charlie
            .apply_commit(
                mls_plaintext_commit.clone(),
                vec![update_proposal_charlie],
                &[kpb_option.unwrap()],
            )
            .expect("Error applying commit (Charlie)");

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
        let remove_bob_proposal_charlie = group_charlie.create_remove_proposal(
            &[],
            &charlie_credential_bundle,
            LeafIndex::from(1u32),
        );
        let (mls_plaintext_commit, _, kpb_option) = match group_charlie.create_commit(
            &[],
            &charlie_credential_bundle,
            vec![remove_bob_proposal_charlie.clone()],
            false, /* force self update*/
        ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };

        // Check that there is a new KeyPackageBundle
        assert!(kpb_option.is_some());

        group_alice
            .apply_commit(
                mls_plaintext_commit.clone(),
                vec![remove_bob_proposal_charlie.clone()],
                &[],
            )
            .expect("Error applying commit (Alice)");
        assert!(
            group_bob
                .apply_commit(
                    mls_plaintext_commit.clone(),
                    vec![remove_bob_proposal_charlie.clone()],
                    &[],
                )
                .unwrap_err()
                == ApplyCommitError::SelfRemoved
        );
        group_charlie
            .apply_commit(
                mls_plaintext_commit.clone(),
                vec![remove_bob_proposal_charlie],
                &[kpb_option.unwrap()],
            )
            .expect("Error applying commit (Charlie)");

        // Make sure that all groups have the same public tree
        if group_alice.tree().public_key_tree() == group_bob.tree().public_key_tree() {
            _print_tree(&group_alice.tree(), "Charlie removed Bob");
            panic!("Same public trees");
        }
        if group_alice.tree().public_key_tree() != group_charlie.tree().public_key_tree() {
            _print_tree(&group_alice.tree(), "Charlie removed Bob");
            panic!("Different public trees");
        }
    }
}
