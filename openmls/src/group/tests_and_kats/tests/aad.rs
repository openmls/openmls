// Import necessary modules and dependencies
use crate::{
    binary_tree::LeafNodeIndex,
    framing::*,
    group::{
        tests_and_kats::utils::{generate_credential_with_key, generate_key_package},
        mls_group::{
            tests_and_kats::utils::{setup_alice_group, setup_client},
        },
        *,
    },
};

// Tests AAD in end-to-end group creation, message and removal with three members.
#[openmls_test::openmls_test]
fn test_add_member_with_aad() {
    // Test over both wire format policies
    for wire_format_policy in [
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    ] {
        let alice_provider = &Provider::default();
        let bob_provider = &Provider::default();
        let charlie_provider = &Provider::default();
        let group_id = GroupId::random(alice_provider.rand());

        // Generate credentials with keys
        let alice_credential_with_key_and_signer = generate_credential_with_key(
            "Alice".into(),
            ciphersuite.signature_algorithm(),
            alice_provider,
        );

        let bob_credential_with_key_and_signer = generate_credential_with_key(
            "Bob".into(),
            ciphersuite.signature_algorithm(),
            bob_provider,
        );

        let charlie_credential_with_key_and_signer = generate_credential_with_key(
            "Charlie".into(),
            ciphersuite.signature_algorithm(),
            charlie_provider,
        );

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            bob_provider,
            bob_credential_with_key_and_signer.clone(),
        );
        let charlie_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            charlie_provider,
            charlie_credential_with_key_and_signer,
        );

        // Define the MlsGroup configuration
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .wire_format_policy(wire_format_policy)
            .build();

        // === Alice creates a group ===

        let mut alice_group = MlsGroup::new_with_group_id(
            alice_provider,
            &alice_credential_with_key_and_signer.signer,
            &mls_group_create_config,
            group_id,
            alice_credential_with_key_and_signer
                .credential_with_key
                .clone(),
        )
        .expect("An unexpected error occurred.");

        let aad = b"Test AAD".to_vec();

        alice_group.set_aad(aad.clone());

        // Test the AAD was set correctly
        assert_eq!(alice_group.aad(), &aad);

        // === Alice adds Bob ===

        let (_message, welcome, _group_info) = alice_group
            .add_members(
                alice_provider,
                &alice_credential_with_key_and_signer.signer,
                core::slice::from_ref(bob_key_package.key_package()),
            )
            .expect("An unexpected error occurred.");
        alice_group
            .merge_pending_commit(alice_provider)
            .expect("error merging pending commit");

        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome
            .into_welcome()
            .expect("expected message to be a welcome");

        let mut bob_group = StagedWelcome::new_from_welcome(
            bob_provider,
            mls_group_create_config.join_config(),
            welcome.clone(),
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("Error creating staged join from Welcome")
        .into_group(bob_provider)
        .expect("Error creating group from staged join");

        // === Alice sends a message to Bob ===

        let message = b"Hello, World!".to_vec();
        alice_group.set_aad(aad.clone());
        let alice_message: MlsMessageIn = alice_group
            .create_message(
                alice_provider,
                &alice_credential_with_key_and_signer.signer,
                &message,
            )
            .expect("Error creating message")
            .into();

        // Test the AAD was reset
        assert_eq!(alice_group.aad().len(), 0);

        let bob_message = bob_group
            .process_message(
                bob_provider,
                alice_message.clone().into_protocol_message().unwrap(),
            )
            .expect("Error handling message");

        // Test the AAD was set correctly
        assert_eq!(bob_message.aad(), &aad);

        // === Alice adds Charlie ===

        alice_group.set_aad(aad.clone());
        let (commit, _welcome, _group_info) = alice_group
            .add_members(
                alice_provider,
                &alice_credential_with_key_and_signer.signer,
                core::slice::from_ref(charlie_key_package.key_package()),
            )
            .expect("An unexpected error occurred.");
        alice_group
            .merge_pending_commit(alice_provider)
            .expect("error merging pending commit");

        // Test the AAD was reset
        assert_eq!(alice_group.aad().len(), 0);

        let bob_processed_message = bob_group
            .process_message(
                bob_provider,
                commit.clone().into_protocol_message().unwrap(),
            )
            .expect("Error handling message");

        match bob_processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(bob_staged_commit) => {
                bob_group
                    .merge_staged_commit(bob_provider, *bob_staged_commit)
                    .unwrap();
            }
            _ => panic!("Expected a StagedCommitMessage"),
        }

        // Test the AAD was set correctly
        assert_eq!(bob_message.aad(), &aad);

        // === Alice removes Charlie ===

        alice_group.set_aad(aad.clone());
        let (commit, _welcome, _group_info) = alice_group
            .remove_members(
                alice_provider,
                &alice_credential_with_key_and_signer.signer,
                &[LeafNodeIndex::new(2)],
            )
            .expect("An unexpected error occurred.");
        alice_group
            .merge_pending_commit(alice_provider)
            .expect("error merging pending commit");

        // Test the AAD was reset
        assert_eq!(alice_group.aad().len(), 0);

        let bob_processed_message = bob_group
            .process_message(
                bob_provider,
                commit.clone().into_protocol_message().unwrap(),
            )
            .expect("Error handling message");

        // Test the AAD was set correctly
        assert_eq!(bob_processed_message.aad(), &aad);
    }
}



#[openmls_test::openmls_test]
fn test_set_aad() {
    use crate::test_utils::single_group_test_framework::*;
    let alice_party = CorePartyState::<Provider>::new("alice");

    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let group_id = GroupId::from_slice(b"Test Group");

    let mut group_state = GroupState::new_from_party(
        group_id,
        alice_party.generate_pre_group(ciphersuite),
        create_config.clone(),
    )
    .unwrap();

    let [alice] = group_state.members_mut(&["alice"]);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    alice.group.set_aad(aad);

    assert_eq!(alice.group.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_commit() {
    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    let message_bundle = group
        .commit_builder()
        .load_psks(provider.storage())
        .unwrap()
        .build(provider.rand(), provider.crypto(), &signer, |_proposal| {
            true
        })
        .unwrap()
        .stage_commit(provider)
        .unwrap();

    assert_eq!(group.aad(), b"");

    let processed_message = group
        .process_message(provider, message_bundle
            .commit()
            .clone()
            .into_protocol_message()
            .unwrap(),
        )
        .unwrap();

    assert_eq!(processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_commit_with_group_info() {
    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    let message_bundle = group
        .commit_builder()
        .load_psks(provider.storage())
        .unwrap()
        .create_group_info(true)
        .build(provider.rand(), provider.crypto(), &signer, |_proposal| {
            true
        })
        .unwrap()
        .stage_commit(provider)
        .unwrap();

    assert_eq!(group.aad(), b"");

    message_bundle.group_info().expect("expected group info in commit");

    let processed_message = group
        .process_message(provider, message_bundle
            .commit()
            .clone()
            .into_protocol_message()
            .unwrap(),
        )
        .unwrap();

    assert_eq!(processed_message.aad(), b"Test AAD");
}


#[openmls_test::openmls_test]
fn test_aad_commit_with_welcome() {
    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    let bob_provider = &Provider::default();
    let (_, bob_pkb, _bob_signer, _) = setup_client("Bob", ciphersuite, bob_provider);

    let message_bundle = group
        .commit_builder()
        .propose_adds(Some(bob_pkb.into_key_package()))
        .load_psks(provider.storage())
        .unwrap()
        .use_ratchet_tree_extension(true) // TODO; named differently than on the external commit builder
        .build(provider.rand(), provider.crypto(), &signer, |_proposal| {
            true
        })
        .unwrap()
        .stage_commit(provider)
        .unwrap();

    assert_eq!(group.aad(), b"");

    let welcome = message_bundle.welcome().expect("expected welcome message in commit");

    let processed_message = group
        .process_message(provider, message_bundle
            .commit()
            .clone()
            .into_protocol_message()
            .unwrap(),
        )
        .unwrap();

    assert_eq!(processed_message.aad(), b"Test AAD");

    StagedWelcome::new_from_welcome(
        bob_provider,
        group.configuration(),
        welcome.clone(),
        None,
    )
    .expect("expected valid welcome")
    .into_group(bob_provider)
    .expect("welcome to create group");

// TODO: mutation test for adding aad to welcome!
}

#[openmls_test::openmls_test]
fn test_aad_application_message() {
    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    let message_bundle = group
        .create_message(provider, &signer, b"Test Message")
        .unwrap();

    assert_eq!(group.aad(), b"");

    let processed_message = group
        .process_message(
            provider,
            message_bundle.into_protocol_message().unwrap(),
        )
        .unwrap();

    assert_eq!(processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_propose_add() {

    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    // TODO: Cleaner way to create key package?
    let (_, bob_pkb, _, _) = setup_client("Bob", ciphersuite, &Provider::default());

    // TODO: difference to create_add_proposal?
    let (message_bundle, _) = group
        .propose_add_member(provider, &signer, bob_pkb.key_package())
        .unwrap();

    assert_eq!(group.aad(), b"");

    let alice_processed_message = group
        .process_message(
            provider,
            message_bundle.into_protocol_message().unwrap(),
        )
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_propose_add_by_value() {
    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    let (_, bob_pkb, _, _) = setup_client("Bob", ciphersuite, &Provider::default());

    let (message_bundle, _) = group
        .propose_add_member_by_value(provider, &signer,  bob_pkb.into_key_package())
        .unwrap();

    assert_eq!(group.aad(), b"");

    let alice_processed_message = group
        .process_message(
            provider,
            message_bundle.into_protocol_message().unwrap(),
        )
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}
