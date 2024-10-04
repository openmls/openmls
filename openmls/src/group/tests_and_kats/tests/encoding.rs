use openmls_traits::crypto::OpenMlsCrypto;
use tls_codec::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafNodeIndex,
    framing::*,
    group::{tests_and_kats::utils::*, *},
    key_packages::*,
    messages::*,
    treesync::LeafNodeParameters,
};

/// Creates a simple test setup for various encoding tests.
fn create_encoding_test_setup(provider: &impl crate::storage::OpenMlsProvider) -> TestSetup {
    // Create a test config for a single client supporting all possible
    // ciphersuites.
    let alice_config = TestClientConfig {
        name: "alice",
        ciphersuites: provider.crypto().supported_ciphersuites(),
    };

    let bob_config = TestClientConfig {
        name: "bob",
        ciphersuites: provider.crypto().supported_ciphersuites(),
    };
    let charlie_config = TestClientConfig {
        name: "charlie",
        ciphersuites: provider.crypto().supported_ciphersuites(),
    };

    let mut test_group_configs = Vec::new();

    // Create a group config for each ciphersuite.
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        let test_group = TestGroupConfig {
            ciphersuite,
            use_ratchet_tree_extension: true,
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
    setup(test_setup_config, provider)
}

/// This test tests encoding and decoding of application messages.
#[openmls_test::openmls_test]
fn test_application_message_encoding(provider: &impl crate::storage::OpenMlsProvider) {
    let test_setup = create_encoding_test_setup(provider);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();

    // Create a message in each group and test the padding.
    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_with_key_and_signer = alice
            .credentials
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");
        for _ in 0..100 {
            // Test encoding/decoding of Application messages.
            let message = randombytes(random_usize() % 1000);
            let aad = randombytes(random_usize() % 1000);
            group_state.set_aad(aad);
            let encrypted_message = group_state
                .create_message(provider, &credential_with_key_and_signer.signer, &message)
                .unwrap();
            let encrypted_message = match encrypted_message.body {
                MlsMessageBodyOut::PrivateMessage(pm) => pm,
                _ => panic!("Expected a PrivateMessage"),
            };
            let encrypted_message_bytes = encrypted_message
                .tls_serialize_detached()
                .expect("An unexpected error occurred.");
            let encrypted_message_decoded =
                match PrivateMessageIn::tls_deserialize(&mut encrypted_message_bytes.as_slice()) {
                    Ok(a) => a,
                    Err(err) => panic!("Error decoding PrivateMessage: {err:?}"),
                };
            assert_eq!(encrypted_message, encrypted_message_decoded.into());
        }
    }
}

/// This test tests encoding and decoding of update proposals.
#[openmls_test::openmls_test]
fn test_update_proposal_encoding(provider: &impl crate::storage::OpenMlsProvider) {
    let test_setup = create_encoding_test_setup(provider);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_with_key_and_signer = alice
            .credentials
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        let (update, _) = group_state
            .propose_self_update(
                provider,
                &credential_with_key_and_signer.signer,
                LeafNodeParameters::default(),
            )
            .unwrap();
        let update = match update.body {
            MlsMessageBodyOut::PublicMessage(pm) => pm,
            _ => panic!("Expected a PublicMessage"),
        };
        let update_encoded = update
            .tls_serialize_detached()
            .expect("Could not encode proposal.");
        let update_decoded = match PublicMessageIn::tls_deserialize(&mut update_encoded.as_slice())
        {
            Ok(a) => a,
            Err(err) => panic!("Error decoding MPLSPlaintext Update: {err:?}"),
        };

        assert_eq!(update, update_decoded.into());
    }
}

/// This test tests encoding and decoding of add proposals.
#[openmls_test::openmls_test]
fn test_add_proposal_encoding(provider: &impl crate::storage::OpenMlsProvider) {
    let test_setup = create_encoding_test_setup(provider);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_with_key_and_signer = alice
            .credentials
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        let key_package_bundle = KeyPackageBundle::generate(
            provider,
            &credential_with_key_and_signer.signer,
            group_state.ciphersuite(),
            credential_with_key_and_signer.credential_with_key.clone(),
        );

        // Adds
        let (add, _) = group_state
            .propose_add_member(
                provider,
                &credential_with_key_and_signer.signer,
                key_package_bundle.key_package(),
            )
            .unwrap();
        let add = match add.body {
            MlsMessageBodyOut::PublicMessage(pm) => pm,
            _ => panic!("Expected a PublicMessage"),
        };
        let add_encoded = add
            .tls_serialize_detached()
            .expect("Could not encode proposal.");
        let add_decoded = PublicMessageIn::tls_deserialize(&mut add_encoded.as_slice())
            .expect("An unexpected error occurred.");

        assert_eq!(add, add_decoded.into());
    }
}

/// This test tests encoding and decoding of remove proposals.
#[openmls_test::openmls_test]
fn test_remove_proposal_encoding(provider: &impl crate::storage::OpenMlsProvider) {
    let test_setup = create_encoding_test_setup(provider);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_with_key_and_signer = alice
            .credentials
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        let (remove, _) = group_state
            .propose_remove_member(
                provider,
                &credential_with_key_and_signer.signer,
                LeafNodeIndex::new(1),
            )
            .unwrap();
        let remove = match remove.body {
            MlsMessageBodyOut::PublicMessage(pm) => pm,
            _ => panic!("Expected a PublicMessage"),
        };

        let remove_encoded = remove
            .tls_serialize_detached()
            .expect("Could not encode proposal.");
        let remove_decoded = PublicMessageIn::tls_deserialize(&mut remove_encoded.as_slice())
            .expect("An unexpected error occurred.");

        assert_eq!(remove, remove_decoded.into());
    }
}

/// This test tests encoding and decoding of commit messages.
#[openmls_test::openmls_test]
fn test_commit_encoding(provider: &impl crate::storage::OpenMlsProvider) {
    let test_setup = create_encoding_test_setup(provider);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let alice_credential_with_key_and_signer = alice
            .credentials
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        // Alice updates her own leaf and adds Charlie to the group
        let charlie_key_package = test_setup
            ._key_store
            .borrow_mut()
            .get_mut(&("charlie", group_state.ciphersuite()))
            .expect("An unexpected error occurred.")
            .pop()
            .expect("An unexpected error occurred.");
        let (commit, _, _) = group_state
            .add_members(
                provider,
                &alice_credential_with_key_and_signer.signer,
                &[charlie_key_package.clone()],
            )
            .expect("Could not create commit.");

        let commit = match commit.body {
            MlsMessageBodyOut::PublicMessage(pm) => pm,
            _ => panic!("Expected a PublicMessage"),
        };
        let commit_encoded = commit
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");

        let commit_decoded = PublicMessageIn::tls_deserialize(&mut commit_encoded.as_slice())
            .expect("An unexpected error occurred.");

        assert_eq!(commit, commit_decoded.into());
    }
}

#[openmls_test::openmls_test]
fn test_welcome_message_encoding(provider: &impl crate::storage::OpenMlsProvider) {
    let test_setup = create_encoding_test_setup(provider);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_with_key_and_signer = alice
            .credentials
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        // Create a few proposals to put into the commit

        // Alice adds Charlie to the group
        let charlie_key_package = test_setup
            ._key_store
            .borrow_mut()
            .get_mut(&("charlie", group_state.ciphersuite()))
            .expect("An unexpected error occurred.")
            .pop()
            .expect("An unexpected error occurred.");
        let (_commit, welcome, _) = group_state
            .add_members(
                provider,
                &credential_with_key_and_signer.signer,
                &[charlie_key_package.clone()],
            )
            .expect("Could not create commit.");
        group_state.merge_pending_commit(provider).unwrap();
        let welcome = welcome.into_welcome().unwrap();

        // Welcome messages
        let welcome_encoded = welcome
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");
        let welcome_decoded = match Welcome::tls_deserialize(&mut welcome_encoded.as_slice()) {
            Ok(a) => a,
            Err(err) => panic!("Error decoding Welcome message: {err:?}"),
        };

        assert_eq!(welcome, welcome_decoded);

        // This makes Charlie decode the internals of the Welcome message, for
        // example the RatchetTreeExtension.
        let config = MlsGroupJoinConfig::default();
        let ratchet_tree = Some(group_state.export_ratchet_tree().into());
        let charlie_group =
            StagedWelcome::new_from_welcome(provider, &config, welcome, ratchet_tree)
                .unwrap()
                .into_group(provider);
        assert!(charlie_group.is_ok());
    }
}
