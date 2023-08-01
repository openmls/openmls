use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use tls_codec::{Deserialize, Serialize};

use super::utils::*;
use crate::{
    binary_tree::LeafNodeIndex, framing::*, group::*, key_packages::*, messages::*,
    schedule::psk::store::ResumptionPskStore, test_utils::*, *,
};

/// Creates a simple test setup for various encoding tests.
fn create_encoding_test_setup(provider: &impl OpenMlsProvider) -> TestSetup {
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
    setup(test_setup_config, provider)
}

/// This test tests encoding and decoding of application messages.
#[apply(providers)]
fn test_application_message_encoding(provider: &impl OpenMlsProvider) {
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
            let encrypted_message = group_state
                .create_application_message(
                    &aad,
                    &message,
                    0,
                    provider,
                    &credential_with_key_and_signer.signer,
                )
                .expect("An unexpected error occurred.");
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
#[apply(providers)]
fn test_update_proposal_encoding(provider: &impl OpenMlsProvider) {
    let test_setup = create_encoding_test_setup(provider);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_with_key_and_signer = alice
            .credentials
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        let key_package_bundle = KeyPackageBundle::new(
            provider,
            &credential_with_key_and_signer.signer,
            group_state.ciphersuite(),
            credential_with_key_and_signer.credential_with_key.clone(),
        );

        let mut update: PublicMessage = group_state
            .create_update_proposal(
                framing_parameters,
                key_package_bundle.key_package().leaf_node().clone(),
                &credential_with_key_and_signer.signer,
            )
            .expect("Could not create proposal.")
            .into();
        update
            .set_membership_tag(
                provider.crypto(),
                group_state.message_secrets().membership_key(),
                group_state.message_secrets().serialized_context(),
            )
            .expect("error setting membership tag");
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
#[apply(providers)]
fn test_add_proposal_encoding(provider: &impl OpenMlsProvider) {
    let test_setup = create_encoding_test_setup(provider);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_with_key_and_signer = alice
            .credentials
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        let key_package_bundle = KeyPackageBundle::new(
            provider,
            &credential_with_key_and_signer.signer,
            group_state.ciphersuite(),
            credential_with_key_and_signer.credential_with_key.clone(),
        );

        // Adds
        let mut add: PublicMessage = group_state
            .create_add_proposal(
                framing_parameters,
                key_package_bundle.key_package().clone(),
                &credential_with_key_and_signer.signer,
            )
            .expect("Could not create proposal.")
            .into();
        add.set_membership_tag(
            provider.crypto(),
            group_state.message_secrets().membership_key(),
            group_state.message_secrets().serialized_context(),
        )
        .expect("error setting membership tag");
        let add_encoded = add
            .tls_serialize_detached()
            .expect("Could not encode proposal.");
        let add_decoded = PublicMessageIn::tls_deserialize(&mut add_encoded.as_slice())
            .expect("An unexpected error occurred.");

        assert_eq!(add, add_decoded.into());
    }
}

/// This test tests encoding and decoding of remove proposals.
#[apply(providers)]
fn test_remove_proposal_encoding(provider: &impl OpenMlsProvider) {
    let test_setup = create_encoding_test_setup(provider);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_with_key_and_signer = alice
            .credentials
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        let mut remove: PublicMessage = group_state
            .create_remove_proposal(
                framing_parameters,
                LeafNodeIndex::new(1),
                &credential_with_key_and_signer.signer,
            )
            .expect("Could not create proposal.")
            .into();
        remove
            .set_membership_tag(
                provider.crypto(),
                group_state.message_secrets().membership_key(),
                group_state.message_secrets().serialized_context(),
            )
            .expect("error setting membership tag");
        let remove_encoded = remove
            .tls_serialize_detached()
            .expect("Could not encode proposal.");
        let remove_decoded = PublicMessageIn::tls_deserialize(&mut remove_encoded.as_slice())
            .expect("An unexpected error occurred.");

        assert_eq!(remove, remove_decoded.into());
    }
}

/// This test tests encoding and decoding of commit messages.
#[apply(providers)]
fn test_commit_encoding(provider: &impl OpenMlsProvider) {
    let test_setup = create_encoding_test_setup(provider);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let alice_credential_with_key_and_signer = alice
            .credentials
            .get(&group_state.ciphersuite())
            .expect("An unexpected error occurred.");

        let alice_key_package_bundle = KeyPackageBundle::new(
            provider,
            &alice_credential_with_key_and_signer.signer,
            group_state.ciphersuite(),
            alice_credential_with_key_and_signer
                .credential_with_key
                .clone(),
        );

        // Create a few proposals to put into the commit

        // Alice updates her own leaf
        let update = group_state
            .create_update_proposal(
                framing_parameters,
                alice_key_package_bundle.key_package().leaf_node().clone(),
                &alice_credential_with_key_and_signer.signer,
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
                charlie_key_package.clone(),
                &alice_credential_with_key_and_signer.signer,
            )
            .expect("Could not create proposal.");

        let mut proposal_store = ProposalStore::from_queued_proposal(
            QueuedProposal::from_authenticated_content_by_ref(
                group_state.ciphersuite(),
                provider.crypto(),
                add,
            )
            .expect("Could not create QueuedProposal."),
        );
        proposal_store.add(
            QueuedProposal::from_authenticated_content_by_ref(
                group_state.ciphersuite(),
                provider.crypto(),
                update,
            )
            .expect("Could not create QueuedProposal."),
        );

        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .proposal_store(&proposal_store)
            .build();
        let create_commit_result = group_state
            .create_commit(
                params,
                provider,
                &alice_credential_with_key_and_signer.signer,
            )
            .expect("An unexpected error occurred.");
        let mut commit: PublicMessage = create_commit_result.commit.into();
        commit
            .set_membership_tag(
                provider.crypto(),
                group_state.message_secrets().membership_key(),
                group_state.message_secrets().serialized_context(),
            )
            .expect("error setting membership tag");
        let commit_encoded = commit
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");

        let commit_decoded = PublicMessageIn::tls_deserialize(&mut commit_encoded.as_slice())
            .expect("An unexpected error occurred.");

        assert_eq!(commit, commit_decoded.into());
    }
}

#[apply(providers)]
fn test_welcome_message_encoding(provider: &impl OpenMlsProvider) {
    let test_setup = create_encoding_test_setup(provider);
    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);

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
        let add = group_state
            .create_add_proposal(
                framing_parameters,
                charlie_key_package.clone(),
                &credential_with_key_and_signer.signer,
            )
            .expect("Could not create proposal.");

        let proposal_store = ProposalStore::from_queued_proposal(
            QueuedProposal::from_authenticated_content_by_ref(
                group_state.ciphersuite(),
                provider.crypto(),
                add,
            )
            .expect("Could not create QueuedProposal."),
        );

        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .proposal_store(&proposal_store)
            .build();
        let create_commit_result = group_state
            .create_commit(params, provider, &credential_with_key_and_signer.signer)
            .expect("An unexpected error occurred.");
        // Alice applies the commit
        group_state
            .merge_commit(provider, create_commit_result.staged_commit)
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
            Err(err) => panic!("Error decoding Welcome message: {err:?}"),
        };

        assert_eq!(welcome, welcome_decoded);

        let charlie = test_clients
            .get("charlie")
            .expect("An unexpected error occurred.")
            .borrow();

        let charlie_key_package_bundle = charlie
            .find_key_package_bundle(&charlie_key_package, provider.crypto())
            .expect("An unexpected error occurred.");

        // This makes Charlie decode the internals of the Welcome message, for
        // example the RatchetTreeExtension.
        assert!(CoreGroup::new_from_welcome(
            welcome,
            Some(group_state.public_group().export_ratchet_tree().into()),
            charlie_key_package_bundle,
            provider,
            ResumptionPskStore::new(1024),
        )
        .is_ok());
    }
}
