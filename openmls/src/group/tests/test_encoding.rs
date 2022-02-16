use super::utils::*;
use crate::{
    ciphersuite::signable::*, framing::*, group::*, key_packages::*, messages::*, test_utils::*, *,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use tls_codec::{Deserialize, Serialize};

/// Creates a simple test setup for various encoding tests.
fn create_encoding_test_setup(backend: &impl OpenMlsCryptoProvider) -> TestSetup {
    // Create a test config for a single client supporting all possible
    // ciphersuites.
    let alice_config = TestClientConfig {
        name: "alice",
        ciphersuites: backend.crypto().supported_ciphersuites(),
    };

    let bob_config = TestClientConfig {
        name: "bob",
        ciphersuites: backend.crypto().supported_ciphersuites(),
    };
    let charlie_config = TestClientConfig {
        name: "charlie",
        ciphersuites: backend.crypto().supported_ciphersuites(),
    };

    let mut test_group_configs = Vec::new();

    // Create a group config for each ciphersuite.
    for &ciphersuite in backend.crypto().supported_ciphersuites().iter() {
        let test_group = TestGroupConfig {
            ciphersuite,
            config: CoreGroupConfig {
                add_ratchet_tree_extension: true,
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
    setup(test_setup_config, backend)
}

/// This test tests encoding and decoding of application messages.
#[apply(backends)]
fn test_application_message_encoding(backend: &impl OpenMlsCryptoProvider) {
    let test_setup = create_encoding_test_setup(backend);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();

    // Create a message in each group and test the padding.
    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");
        for _ in 0..100 {
            // Test encoding/decoding of Application messages.
            let message = randombytes(random_usize() % 1000);
            let aad = randombytes(random_usize() % 1000);
            let encrypted_message = group_state
                .create_application_message(&aad, &message, credential_bundle, 0, backend)
                .expect("An unexpected error occurred.");
            let encrypted_message_bytes = encrypted_message
                .tls_serialize_detached()
                .expect("An unexpected error occurred.");
            let encrypted_message_decoded =
                match MlsCiphertext::tls_deserialize(&mut encrypted_message_bytes.as_slice()) {
                    Ok(a) => a,
                    Err(err) => panic!("Error decoding MlsCiphertext: {:?}", err),
                };
            assert_eq!(encrypted_message, encrypted_message_decoded);
        }
    }
}

/// This test tests encoding and decoding of update proposals.
#[apply(backends)]
fn test_update_proposal_encoding(backend: &impl OpenMlsCryptoProvider) {
    let test_setup = create_encoding_test_setup(backend);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::MlsPlaintext);

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        let capabilities_extension = Extension::Capabilities(CapabilitiesExtension::new(
            None,
            Some(&[group_state.ciphersuite()]),
            None,
            None,
        ));
        let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Extension> = vec![capabilities_extension, lifetime_extension];

        let key_package_bundle = KeyPackageBundle::new(
            &[group_state.ciphersuite()],
            credential_bundle,
            backend,
            mandatory_extensions,
        )
        .expect("An unexpected error occurred.");

        let update = group_state
            .create_update_proposal(
                framing_parameters,
                credential_bundle,
                key_package_bundle.key_package().clone(),
                backend,
            )
            .expect("Could not create proposal.");
        let update_encoded = update
            .tls_serialize_detached()
            .expect("Could not encode proposal.");
        let mut update_decoded =
            match VerifiableMlsPlaintext::tls_deserialize(&mut update_encoded.as_slice()) {
                Ok(a) => a,
                Err(err) => panic!("Error decoding MPLSPlaintext Update: {:?}", err),
            };
        update_decoded.set_context(
            group_state
                .context()
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        );
        let update_decoded = update_decoded
            .verify(backend, credential_bundle.credential())
            .expect("Error verifying MlsPlaintext");

        assert_eq!(update, update_decoded);
    }
}

/// This test tests encoding and decoding of add proposals.
#[apply(backends)]
fn test_add_proposal_encoding(backend: &impl OpenMlsCryptoProvider) {
    let test_setup = create_encoding_test_setup(backend);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::MlsPlaintext);

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        let capabilities_extension = Extension::Capabilities(CapabilitiesExtension::new(
            None,
            Some(&[group_state.ciphersuite()]),
            None,
            None,
        ));
        let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Extension> = vec![capabilities_extension, lifetime_extension];

        let key_package_bundle = KeyPackageBundle::new(
            &[group_state.ciphersuite()],
            credential_bundle,
            backend,
            mandatory_extensions,
        )
        .expect("An unexpected error occurred.");

        // Adds
        let add = group_state
            .create_add_proposal(
                framing_parameters,
                credential_bundle,
                key_package_bundle.key_package().clone(),
                backend,
            )
            .expect("Could not create proposal.");
        let add_encoded = add
            .tls_serialize_detached()
            .expect("Could not encode proposal.");
        let mut verifiable_plaintext =
            VerifiableMlsPlaintext::tls_deserialize(&mut add_encoded.as_slice())
                .expect("An unexpected error occurred.");

        verifiable_plaintext.set_context(
            group_state
                .context()
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        );

        let credential = group_state
            .treesync()
            .own_leaf_node()
            .expect("An unexpected error occurred.")
            .key_package()
            .credential();
        let add_decoded = verifiable_plaintext
            .verify(backend, credential)
            .expect("An unexpected error occurred.");

        assert_eq!(add, add_decoded);
    }
}

/// This test tests encoding and decoding of remove proposals.
#[apply(backends)]
fn test_remove_proposal_encoding(backend: &impl OpenMlsCryptoProvider) {
    use ciphersuite::hash_ref::KeyPackageRef;

    let test_setup = create_encoding_test_setup(backend);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::MlsPlaintext);

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        let remove = group_state
            .create_remove_proposal(
                framing_parameters,
                credential_bundle,
                &KeyPackageRef::from_slice(
                    &backend
                        .rand()
                        .random_vec(16)
                        .expect("An unexpected error occurred."),
                ),
                backend,
            )
            .expect("Could not create proposal.");
        let remove_encoded = remove
            .tls_serialize_detached()
            .expect("Could not encode proposal.");
        let mut verifiable_plaintext =
            VerifiableMlsPlaintext::tls_deserialize(&mut remove_encoded.as_slice())
                .expect("An unexpected error occurred.");

        verifiable_plaintext.set_context(
            group_state
                .context()
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        );

        let credential = group_state
            .treesync()
            .own_leaf_node()
            .expect("An unexpected error occurred.")
            .key_package()
            .credential();
        let remove_decoded = verifiable_plaintext
            .verify(backend, credential)
            .expect("An unexpected error occurred.");

        assert_eq!(remove, remove_decoded);
    }
}

/// This test tests encoding and decoding of commit messages.
#[apply(backends)]
fn test_commit_encoding(backend: &impl OpenMlsCryptoProvider) {
    let test_setup = create_encoding_test_setup(backend);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::MlsPlaintext);

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let alice_credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        let capabilities_extension = Extension::Capabilities(CapabilitiesExtension::new(
            None,
            Some(&[group_state.ciphersuite()]),
            None,
            None,
        ));
        let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
        let mandatory_extensions: Vec<Extension> = vec![capabilities_extension, lifetime_extension];

        let alice_key_package_bundle = KeyPackageBundle::new(
            &[group_state.ciphersuite()],
            alice_credential_bundle,
            backend,
            mandatory_extensions.clone(),
        )
        .expect("An unexpected error occurred.");

        // Create a few proposals to put into the commit

        // Alice updates her own leaf
        let update = group_state
            .create_update_proposal(
                framing_parameters,
                alice_credential_bundle,
                alice_key_package_bundle.key_package().clone(),
                backend,
            )
            .expect("Could not create proposal.");

        // Alice adds Charlie to the group
        let charlie_key_package = test_setup
            ._key_store
            .borrow_mut()
            .get_mut(&("charlie", group_state.ciphersuite()))
            .expect("An unexpected error occurred.")
            .pop()
            .expect("An unexpected error occurred.");
        let add = group_state
            .create_add_proposal(
                framing_parameters,
                alice_credential_bundle,
                charlie_key_package.clone(),
                backend,
            )
            .expect("Could not create proposal.");

        let mut proposal_store = ProposalStore::from_queued_proposal(
            QueuedProposal::from_mls_plaintext(group_state.ciphersuite(), backend, add)
                .expect("Could not create QueuedProposal."),
        );
        proposal_store.add(
            QueuedProposal::from_mls_plaintext(group_state.ciphersuite(), backend, update)
                .expect("Could not create QueuedProposal."),
        );

        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(alice_credential_bundle)
            .proposal_store(&proposal_store)
            .build();
        let create_commit_result = group_state
            .create_commit(params, backend)
            .expect("An unexpected error occurred.");
        let commit_encoded = create_commit_result
            .commit
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");

        let mut verifiable_plaintext =
            VerifiableMlsPlaintext::tls_deserialize(&mut commit_encoded.as_slice())
                .expect("An unexpected error occurred.");

        verifiable_plaintext.set_context(
            group_state
                .context()
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        );

        let credential = group_state
            .treesync()
            .own_leaf_node()
            .expect("An unexpected error occurred.")
            .key_package()
            .credential();
        let commit_decoded = verifiable_plaintext
            .verify(backend, credential)
            .expect("An unexpected error occurred.");

        assert_eq!(create_commit_result.commit, commit_decoded);
    }
}

#[apply(backends)]
fn test_welcome_message_encoding(backend: &impl OpenMlsCryptoProvider) {
    let test_setup = create_encoding_test_setup(backend);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::MlsPlaintext);

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_bundle = alice
            .credential_bundles
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
        let add = group_state
            .create_add_proposal(
                framing_parameters,
                credential_bundle,
                charlie_key_package.clone(),
                backend,
            )
            .expect("Could not create proposal.");

        let proposal_store = ProposalStore::from_queued_proposal(
            QueuedProposal::from_mls_plaintext(group_state.ciphersuite(), backend, add)
                .expect("Could not create QueuedProposal."),
        );

        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(credential_bundle)
            .proposal_store(&proposal_store)
            .build();
        let create_commit_result = group_state
            .create_commit(params, backend)
            .expect("An unexpected error occurred.");
        // Alice applies the commit
        group_state
            .merge_commit(create_commit_result.staged_commit)
            .expect("error merging own commits");

        // Welcome messages

        let welcome = create_commit_result
            .welcome_option
            .expect("An unexpected error occurred.");

        let welcome_encoded = welcome
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");
        let welcome_decoded = match Welcome::tls_deserialize(&mut welcome_encoded.as_slice()) {
            Ok(a) => a,
            Err(err) => panic!("Error decoding Welcome message: {:?}", err),
        };

        assert_eq!(welcome, welcome_decoded);

        let charlie = test_clients
            .get("charlie")
            .expect("An unexpected error occurred.")
            .borrow();

        let charlie_key_package_bundle = charlie
            .find_key_package_bundle(&charlie_key_package, backend)
            .expect("An unexpected error occurred.");

        // This makes Charlie decode the internals of the Welcome message, for
        // example the RatchetTreeExtension.
        assert!(CoreGroup::new_from_welcome(
            welcome,
            Some(group_state.treesync().export_nodes()),
            charlie_key_package_bundle,
            backend
        )
        .is_ok());
    }
}
