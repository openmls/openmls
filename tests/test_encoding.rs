use openmls::prelude::*;
mod utils;
use utils::*;

/// Creates a simple test setup for various encoding tests.
fn create_encoding_test_setup() -> TestSetup {
    // Create a test config for a single client supporting all possible
    // ciphersuites.
    let alice_config = TestClientConfig {
        name: "alice",
        ciphersuites: Config::supported_ciphersuite_names(),
    };

    let bob_config = TestClientConfig {
        name: "bob",
        ciphersuites: Config::supported_ciphersuite_names(),
    };
    let charlie_config = TestClientConfig {
        name: "charlie",
        ciphersuites: Config::supported_ciphersuite_names(),
    };

    let mut test_group_configs = Vec::new();

    // Create a group config for each ciphersuite.
    for ciphersuite_name in Config::supported_ciphersuite_names() {
        let test_group = TestGroupConfig {
            ciphersuite: ciphersuite_name,
            config: GroupConfig {
                add_ratchet_tree_extension: true,
                padding_block_size: 10,
                additional_as_epochs: 0,
            },
            members: vec![alice_config.clone(), bob_config.clone()],
        };
        test_group_configs.push(test_group);
    }

    // Create the test setup config.
    let test_setup_config = TestSetupConfig {
        clients: vec![alice_config, bob_config, charlie_config],
        groups: test_group_configs,
    };

    // Initialize the test setup according to config.
    setup(test_setup_config)
}

#[test]
/// This test tests encoding and decoding of application messages.
fn test_application_message_encoding() {
    let test_setup = create_encoding_test_setup();
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients.get("alice").unwrap().borrow();

    // Create a message in each group and test the padding.
    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite().name())
            .unwrap();
        for _ in 0..100 {
            // Test encoding/decoding of Application messages.
            let message = randombytes(random_usize() % 1000);
            let aad = randombytes(random_usize() % 1000);
            let encrypted_message = group_state
                .create_application_message(&aad, &message, &credential_bundle)
                .unwrap();
            let encrypted_message_bytes = encrypted_message.encode_detached().unwrap();
            let encrypted_message_decoded =
                match MLSCiphertext::decode(&mut Cursor::new(&encrypted_message_bytes)) {
                    Ok(a) => a,
                    Err(err) => panic!("Error decoding MLSCiphertext: {:?}", err),
                };
            assert_eq!(encrypted_message, encrypted_message_decoded);
        }
    }
}

#[test]
/// This test tests encoding and decoding of update proposals.
fn test_update_proposal_encoding() {
    let test_setup = create_encoding_test_setup();
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients.get("alice").unwrap().borrow();

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite().name())
            .unwrap();

        let capabilities_extension = Box::new(CapabilitiesExtension::new(
            None,
            Some(&[group_state.ciphersuite().name()]),
            None,
        ));
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Box<dyn Extension>> =
            vec![capabilities_extension, lifetime_extension];

        let key_package_bundle = KeyPackageBundle::new(
            &[group_state.ciphersuite().name()],
            credential_bundle,
            mandatory_extensions,
        )
        .unwrap();

        let update = group_state.create_update_proposal(
            &[],
            credential_bundle,
            key_package_bundle.key_package().clone(),
        );
        let update_encoded = update.encode_detached().unwrap();
        let update_decoded = match MLSPlaintext::decode(&mut Cursor::new(&update_encoded)) {
            Ok(a) => a,
            Err(err) => panic!("Error decoding MPLSPlaintext Update: {:?}", err),
        };

        assert_eq!(update, update_decoded);
    }
}

#[test]
/// This test tests encoding and decoding of add proposals.
fn test_add_proposal_encoding() {
    let test_setup = create_encoding_test_setup();
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients.get("alice").unwrap().borrow();

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite().name())
            .unwrap();

        let capabilities_extension = Box::new(CapabilitiesExtension::new(
            None,
            Some(&[group_state.ciphersuite().name()]),
            None,
        ));
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Box<dyn Extension>> =
            vec![capabilities_extension, lifetime_extension];

        let key_package_bundle = KeyPackageBundle::new(
            &[group_state.ciphersuite().name()],
            credential_bundle,
            mandatory_extensions,
        )
        .unwrap();

        // Adds
        let add = group_state.create_add_proposal(
            &[],
            credential_bundle,
            key_package_bundle.key_package().clone(),
        );
        let add_encoded = add.encode_detached().unwrap();
        let add_decoded = match MLSPlaintext::decode(&mut Cursor::new(&add_encoded)) {
            Ok(a) => a,
            Err(err) => panic!("Error decoding MPLSPlaintext Add: {:?}", err),
        };

        assert_eq!(add, add_decoded);
    }
}

#[test]
/// This test tests encoding and decoding of remove proposals.
fn test_remove_proposal_encoding() {
    let test_setup = create_encoding_test_setup();
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients.get("alice").unwrap().borrow();

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite().name())
            .unwrap();

        let remove =
            group_state.create_remove_proposal(&[], credential_bundle, LeafIndex::from(1u32));
        let remove_encoded = remove.encode_detached().unwrap();
        let remove_decoded = match MLSPlaintext::decode(&mut Cursor::new(&remove_encoded)) {
            Ok(a) => a,
            Err(err) => panic!("Error decoding MPLSPlaintext Remove: {:?}", err),
        };

        assert_eq!(remove, remove_decoded);
    }
}

/// This test tests encoding and decoding of commit messages.
#[test]
fn test_commit_encoding() {
    let test_setup = create_encoding_test_setup();
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients.get("alice").unwrap().borrow();

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let alice_credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite().name())
            .unwrap();

        let capabilities_extension = Box::new(CapabilitiesExtension::new(
            None,
            Some(&[group_state.ciphersuite().name()]),
            None,
        ));
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Box<dyn Extension>> =
            vec![capabilities_extension, lifetime_extension];

        let alice_key_package_bundle = KeyPackageBundle::new(
            &[group_state.ciphersuite().name()],
            alice_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();

        // Create a few proposals to put into the commit

        // Alice updates her own leaf
        let update = group_state.create_update_proposal(
            &[],
            alice_credential_bundle,
            alice_key_package_bundle.key_package().clone(),
        );

        // Alice adds Charlie to the group
        let charlie_key_package = test_setup
            ._key_store
            .borrow_mut()
            .get_mut(&("charlie", group_state.ciphersuite().name()))
            .unwrap()
            .pop()
            .unwrap();
        let add = group_state.create_add_proposal(
            &[],
            alice_credential_bundle,
            charlie_key_package.clone(),
        );

        // Alice removes Bob
        let remove =
            group_state.create_remove_proposal(&[], alice_credential_bundle, LeafIndex::from(2u32));

        let proposals = &[&add, &remove, &update];
        let (commit, _welcome_option, _key_package_bundle_option) = group_state
            .create_commit(&[], alice_credential_bundle, proposals, true)
            .unwrap();
        let commit_encoded = commit.encode_detached().unwrap();
        let commit_decoded = match MLSPlaintext::decode(&mut Cursor::new(&commit_encoded)) {
            Ok(a) => a,
            Err(err) => panic!("Error decoding MPLSPlaintext Commit: {:?}", err),
        };

        assert_eq!(commit, commit_decoded);
    }
}

#[test]
fn test_welcome_message_encoding() {
    let test_setup = create_encoding_test_setup();
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients.get("alice").unwrap().borrow();

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite().name())
            .unwrap();

        // Create a few proposals to put into the commit

        // Alice adds Charlie to the group
        let charlie_key_package = test_setup
            ._key_store
            .borrow_mut()
            .get_mut(&("charlie", group_state.ciphersuite().name()))
            .unwrap()
            .pop()
            .unwrap();
        let add =
            group_state.create_add_proposal(&[], credential_bundle, charlie_key_package.clone());

        let proposals = &[&add];
        let (_commit, welcome_option, _key_package_bundle_option) = group_state
            .create_commit(&[], credential_bundle, proposals, true)
            .unwrap();

        // Welcome messages

        let welcome = welcome_option.unwrap();

        let welcome_encoded = welcome.encode_detached().unwrap();
        let welcome_decoded = match Welcome::decode(&mut Cursor::new(&welcome_encoded)) {
            Ok(a) => a,
            Err(err) => panic!("Error decoding Welcome message: {:?}", err),
        };

        assert_eq!(welcome, welcome_decoded);

        let charlie = test_clients.get("charlie").unwrap().borrow();

        let charlie_key_package_bundle = charlie
            .find_key_package_bundle(&charlie_key_package)
            .unwrap();

        // This makes Charlie decode the internals of the Welcome message, for
        // example the RatchetTreeExtension.
        assert!(MlsGroup::new_from_welcome(welcome, None, charlie_key_package_bundle).is_ok());
    }
}
