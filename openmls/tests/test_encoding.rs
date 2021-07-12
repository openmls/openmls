use openmls::{ciphersuite::signable::Verifiable, prelude::*};
pub mod utils;
use tls_codec::{Deserialize, Serialize};
use utils::mls_utils::*;

/// Creates a simple test setup for various encoding tests.
fn create_encoding_test_setup() -> TestSetup {
    // Create a test config for a single client supporting all possible
    // ciphersuites.
    let alice_config = TestClientConfig {
        name: "alice",
        ciphersuites: Config::supported_ciphersuite_names().to_vec(),
    };

    let bob_config = TestClientConfig {
        name: "bob",
        ciphersuites: Config::supported_ciphersuite_names().to_vec(),
    };
    let charlie_config = TestClientConfig {
        name: "charlie",
        ciphersuites: Config::supported_ciphersuite_names().to_vec(),
    };

    let mut test_group_configs = Vec::new();

    // Create a group config for each ciphersuite.
    for ciphersuite_name in Config::supported_ciphersuite_names() {
        let test_group = TestGroupConfig {
            ciphersuite: *ciphersuite_name,
            config: MlsGroupConfig {
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
                .create_application_message(&aad, &message, &credential_bundle, 0)
                .unwrap();
            let encrypted_message_bytes = encrypted_message.tls_serialize_detached().unwrap();
            let encrypted_message_decoded =
                match MlsCiphertext::tls_deserialize(&mut encrypted_message_bytes.as_slice()) {
                    Ok(a) => a,
                    Err(err) => panic!("Error decoding MlsCiphertext: {:?}", err),
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

        let capabilities_extension = Extension::Capabilities(CapabilitiesExtension::new(
            None,
            Some(&[group_state.ciphersuite().name()]),
            None,
        ));
        let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Extension> = vec![capabilities_extension, lifetime_extension];

        let key_package_bundle = KeyPackageBundle::new(
            &[group_state.ciphersuite().name()],
            credential_bundle,
            mandatory_extensions,
        )
        .unwrap();

        let update = group_state
            .create_update_proposal(
                &[],
                credential_bundle,
                key_package_bundle.key_package().clone(),
            )
            .expect("Could not create proposal.");
        let update_encoded = update
            .tls_serialize_detached()
            .expect("Could not encode proposal.");
        let update_decoded =
            match VerifiableMlsPlaintext::tls_deserialize(&mut update_encoded.as_slice()) {
                Ok(a) => a,
                Err(err) => panic!("Error decoding MPLSPlaintext Update: {:?}", err),
            }
            .set_context(&group_state.context().tls_serialize_detached().unwrap())
            .verify(credential_bundle.credential())
            .expect("Error verifying MlsPlaintext");

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

        let capabilities_extension = Extension::Capabilities(CapabilitiesExtension::new(
            None,
            Some(&[group_state.ciphersuite().name()]),
            None,
        ));
        let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Extension> = vec![capabilities_extension, lifetime_extension];

        let key_package_bundle = KeyPackageBundle::new(
            &[group_state.ciphersuite().name()],
            credential_bundle,
            mandatory_extensions,
        )
        .unwrap();

        // Adds
        let add = group_state
            .create_add_proposal(
                &[],
                credential_bundle,
                key_package_bundle.key_package().clone(),
            )
            .expect("Could not create proposal.");
        let add_encoded = add
            .tls_serialize_detached()
            .expect("Could not encode proposal.");
        let add_decoded =
            match VerifiableMlsPlaintext::tls_deserialize(&mut add_encoded.as_slice()) {
                Ok(a) => a,
                Err(err) => panic!("Error decoding MPLSPlaintext Add: {:?}", err),
            }
            .set_context(&group_state.context().tls_serialize_detached().unwrap())
            .verify(credential_bundle.credential())
            .expect("Error verifying MlsPlaintext");

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

        let remove = group_state
            .create_remove_proposal(&[], credential_bundle, LeafIndex::from(1u32))
            .expect("Could not create proposal.");
        let remove_encoded = remove
            .tls_serialize_detached()
            .expect("Could not encode proposal.");
        let remove_decoded =
            match VerifiableMlsPlaintext::tls_deserialize(&mut remove_encoded.as_slice()) {
                Ok(a) => a,
                Err(err) => panic!("Error decoding MPLSPlaintext Remove: {:?}", err),
            }
            .set_context(&group_state.context().tls_serialize_detached().unwrap())
            .verify(credential_bundle.credential())
            .expect("Error verifying MlsPlaintext");

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

        let capabilities_extension = Extension::Capabilities(CapabilitiesExtension::new(
            None,
            Some(&[group_state.ciphersuite().name()]),
            None,
        ));
        let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Extension> = vec![capabilities_extension, lifetime_extension];

        let alice_key_package_bundle = KeyPackageBundle::new(
            &[group_state.ciphersuite().name()],
            alice_credential_bundle,
            mandatory_extensions.clone(),
        )
        .unwrap();

        // Create a few proposals to put into the commit

        // Alice updates her own leaf
        let update = group_state
            .create_update_proposal(
                &[],
                alice_credential_bundle,
                alice_key_package_bundle.key_package().clone(),
            )
            .expect("Could not create proposal.");

        // Alice adds Charlie to the group
        let charlie_key_package = test_setup
            ._key_store
            .borrow_mut()
            .get_mut(&("charlie", group_state.ciphersuite().name()))
            .unwrap()
            .pop()
            .unwrap();
        let add = group_state
            .create_add_proposal(&[], alice_credential_bundle, charlie_key_package.clone())
            .expect("Could not create proposal.");

        // Alice removes Bob
        let remove = group_state
            .create_remove_proposal(&[], alice_credential_bundle, LeafIndex::from(2u32))
            .expect("Could not create proposal.");

        let proposals = &[&add, &remove, &update];
        let (commit, _welcome_option, _key_package_bundle_option) = group_state
            .create_commit(&[], alice_credential_bundle, proposals, &[], true, None)
            .unwrap();
        let commit_encoded = commit.tls_serialize_detached().unwrap();
        let commit_decoded =
            match VerifiableMlsPlaintext::tls_deserialize(&mut commit_encoded.as_slice()) {
                Ok(a) => a,
                Err(err) => panic!("Error decoding MPLSPlaintext Commit: {:?}", err),
            }
            .set_context(&group_state.context().tls_serialize_detached().unwrap())
            .verify(alice_credential_bundle.credential())
            .expect("Error verifying MlsPlaintext");

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
        let add = group_state
            .create_add_proposal(&[], credential_bundle, charlie_key_package.clone())
            .expect("Could not create proposal.");

        let proposals = &[&add];
        let (commit, welcome_option, key_package_bundle_option) = group_state
            .create_commit(&[], credential_bundle, proposals, &[], true, None)
            .unwrap();
        // Alice applies the commit
        assert!(group_state
            .apply_commit(
                &commit,
                proposals,
                &[key_package_bundle_option.unwrap()],
                None
            )
            .is_ok());

        // Welcome messages

        let welcome = welcome_option.unwrap();

        let welcome_encoded = welcome.tls_serialize_detached().unwrap();
        let welcome_decoded = match Welcome::tls_deserialize(&mut welcome_encoded.as_slice()) {
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
        assert!(MlsGroup::new_from_welcome(
            welcome,
            Some(group_state.tree().public_key_tree_copy()),
            charlie_key_package_bundle,
            None,
        )
        .is_ok());
    }
}
