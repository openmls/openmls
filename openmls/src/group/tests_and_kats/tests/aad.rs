// Import necessary modules and dependencies
use crate::{
    binary_tree::LeafNodeIndex,
    framing::*,
    group::{
        mls_group::tests_and_kats::utils::{
            setup_alice_bob_group, setup_alice_group, setup_client,
        },
        tests_and_kats::utils::{generate_credential_with_key, generate_key_package},
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

        let aad = b"Test AAD commit".to_vec();

        alice_group.set_aad(aad.clone());

        // Test the AAD was set correctly
        assert_eq!(alice_group.aad(), &aad);

        // === Alice adds Bob ===
        // Tests that AAD is not used for welcome messages

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

        assert_eq!(alice_group.aad(), b"");

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
        // Tests that AAD is set on application messages.

        let message = b"Hello, World!".to_vec();
        let aad = b"Test AAD message".to_vec();

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
        assert_eq!(alice_group.aad(), b"");

        let bob_message = bob_group
            .process_message(
                bob_provider,
                alice_message.clone().into_protocol_message().unwrap(),
            )
            .expect("Error handling message");

        // Test the AAD was set correctly
        assert_eq!(bob_message.aad(), &aad);

        // === Alice adds Charlie ===
        // Tests that AAD is set on commits

        let aad = b"Test AAD commit 2".to_vec();

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
        assert_eq!(alice_group.aad(), b"");

        let bob_processed_message = bob_group
            .process_message(
                bob_provider,
                commit.clone().into_protocol_message().unwrap(),
            )
            .expect("Error handling message");

        // Test the AAD was set correctly
        assert_eq!(bob_processed_message.aad(), &aad);

        match bob_processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(bob_staged_commit) => {
                bob_group
                    .merge_staged_commit(bob_provider, *bob_staged_commit)
                    .unwrap();
            }
            _ => panic!("Expected a StagedCommitMessage"),
        }

        // === Alice removes Charlie ===

        let aad = b"Test AAD commit 3".to_vec();

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
        assert_eq!(alice_group.aad(), b"");

        let bob_processed_message = bob_group
            .process_message(
                bob_provider,
                commit.clone().into_protocol_message().unwrap(),
            )
            .expect("Error handling message");

        assert_eq!(bob_processed_message.aad(), &aad);
    }
}

#[openmls_test::openmls_test]
fn test_set_aad() {
    for wire_format_policy in WIRE_FORMAT_POLICIES.iter() {
        use crate::test_utils::single_group_test_framework::{CorePartyState, GroupState};

        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .wire_format_policy(*wire_format_policy)
            .build();

        let alice_party = CorePartyState::<Provider>::new("alice");
        let group_id = GroupId::from_slice(b"Test Group");

        let mut group_state = GroupState::new_from_party(
            group_id,
            alice_party.generate_pre_group(config.ciphersuite),
            config.clone(),
        )
        .unwrap();

        let [alice] = group_state.members_mut(&["alice"]);

        let aad: Vec<u8> = b"Test AAD".to_vec();
        alice.group.set_aad(aad);

        assert_eq!(alice.group.aad(), b"Test AAD");
    }
}

// Tests for individual functions that call reset_add()

#[openmls_test::openmls_test]
fn test_aad_stage_commit() {
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
        .process_message(
            provider,
            message_bundle
                .commit()
                .clone()
                .into_protocol_message()
                .unwrap(),
        )
        .unwrap();

    assert_eq!(processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_stage_commit_with_group_info() {
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

    message_bundle
        .group_info()
        .expect("expected group info in commit");

    let processed_message = group
        .process_message(
            provider,
            message_bundle
                .commit()
                .clone()
                .into_protocol_message()
                .unwrap(),
        )
        .unwrap();

    assert_eq!(processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_stage_commit_with_welcome() {
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

    let welcome = message_bundle
        .welcome()
        .expect("expected welcome message in commit");

    let processed_message = group
        .process_message(
            provider,
            message_bundle
                .commit()
                .clone()
                .into_protocol_message()
                .unwrap(),
        )
        .unwrap();

    assert_eq!(processed_message.aad(), b"Test AAD");

    StagedWelcome::new_from_welcome(bob_provider, group.configuration(), welcome.clone(), None)
        .expect("expected valid welcome")
        .into_group(bob_provider)
        .expect("expeceted welcome to create group");
}

#[openmls_test::openmls_test]
fn test_aad_create_application_message() {
    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    let message_bundle = group
        .create_message(provider, &signer, b"Test Message")
        .unwrap();

    assert_eq!(group.aad(), b"");

    let processed_message = group
        .process_message(provider, message_bundle.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_propose_add() {
    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);
    let (_, bob_pkb, _, _) = setup_client("Bob", ciphersuite, &Provider::default());

    let (message_bundle, _) = group
        .propose_add_member(provider, &signer, bob_pkb.key_package())
        .unwrap();

    assert_eq!(group.aad(), b"");

    let alice_processed_message = group
        .process_message(provider, message_bundle.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_add_members() {
    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);
    let (_, bob_pkb, _, _) = setup_client("Bob", ciphersuite, &Provider::default());

    let (commit, _welcome, _group_info) = group
        .add_members(provider, &signer, &[bob_pkb.into_key_package()])
        .unwrap();

    assert_eq!(group.aad(), b"");

    let alice_processed_message = group
        .process_message(provider, commit.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_add_members_without_update() {
    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);
    let (_, bob_pkb, _, _) = setup_client("Bob", ciphersuite, &Provider::default());

    let (commit, _welcome, _group_info) = group
        .add_members_without_update(provider, &signer, &[bob_pkb.into_key_package()])
        .unwrap();

    assert_eq!(group.aad(), b"");

    let alice_processed_message = group
        .process_message(provider, commit.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_swap_members() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (
        mut alice_group,
        alice_signer,
        bob_group,
        _bob_signer,
        _alice_credential_with_key,
        _bob_credential_with_key,
    ) = setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    alice_group.set_aad(aad);
    let (_, charlie_pkb, _, _) = setup_client("Charlie", ciphersuite, &Provider::default());

    let welcomeCommits = alice_group
        .swap_members(
            alice_provider,
            &alice_signer,
            &[bob_group.own_leaf_index()],
            &[charlie_pkb.into_key_package()],
        )
        .unwrap();

    assert_eq!(alice_group.aad(), b"");

    let alice_processed_message = alice_group
        .process_message(
            alice_provider,
            welcomeCommits.commit.into_protocol_message().unwrap(),
        )
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_remove_members() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (
        mut alice_group,
        alice_signer,
        bob_group,
        _bob_signer,
        _alice_credential_with_key,
        _bob_credential_with_key,
    ) = setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    alice_group.set_aad(aad);

    let (commit, _welcome_option, _group_info) = alice_group
        .remove_members(alice_provider, &alice_signer, &[bob_group.own_leaf_index()])
        .unwrap();

    assert_eq!(alice_group.aad(), b"");

    let alice_processed_message = alice_group
        .process_message(alice_provider, commit.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_leave_group() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (
        mut alice_group,
        alice_signer,
        mut bob_group,
        _bob_signer,
        _alice_credential_with_key,
        _bob_credential_with_key,
    ) = setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    alice_group.set_aad(aad);

    let proposal = alice_group
        .leave_group(alice_provider, &alice_signer)
        .unwrap();

    assert_eq!(alice_group.aad(), b"");

    let bob_processed_message = bob_group
        .process_message(bob_provider, proposal.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(bob_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_leave_group_via_self_remove() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (
        mut alice_group,
        alice_signer,
        mut bob_group,
        _bob_signer,
        _alice_credential_with_key,
        _bob_credential_with_key,
    ) = setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    alice_group.set_aad(aad);

    let proposal = alice_group
        .leave_group_via_self_remove(alice_provider, &alice_signer)
        .unwrap();

    assert_eq!(alice_group.aad(), b"");

    let bob_processed_message = bob_group
        .process_message(bob_provider, proposal.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(bob_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_propose_remove_member() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (
        mut alice_group,
        alice_signer,
        bob_group,
        _bob_signer,
        _alice_credential_with_key,
        _bob_credential_with_key,
    ) = setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    alice_group.set_aad(aad);

    let (proposal, _hash_reference) = alice_group
        .propose_remove_member(alice_provider, &alice_signer, bob_group.own_leaf_index())
        .unwrap();

    assert_eq!(alice_group.aad(), b"");

    let alice_processed_message = alice_group
        .process_message(alice_provider, proposal.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_propose_remove_member_by_credential() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (
        mut alice_group,
        alice_signer,
        _bob_group,
        _bob_signer,
        _alice_credential_with_key,
        bob_credential_with_key,
    ) = setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    alice_group.set_aad(aad);

    let (proposal, _hash_reference) = alice_group
        .propose_remove_member_by_credential(
            alice_provider,
            &alice_signer,
            &bob_credential_with_key.credential,
        )
        .unwrap();

    assert_eq!(alice_group.aad(), b"");

    let alice_processed_message = alice_group
        .process_message(alice_provider, proposal.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

// propose_add_member_by_value is created by the `impl_propose_fun!` macro.
// This test thus covers that macro.
#[openmls_test::openmls_test]
fn test_aad_propose_add_by_value() {
    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    let (_, bob_pkb, _, _) = setup_client("Bob", ciphersuite, &Provider::default());

    let (message_bundle, _) = group
        .propose_add_member_by_value(provider, &signer, bob_pkb.into_key_package())
        .unwrap();

    assert_eq!(group.aad(), b"");

    let alice_processed_message = group
        .process_message(provider, message_bundle.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_propose_group_context_extensions() {
    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    let extensions =
        Extensions::from_vec(vec![Extension::Unknown(1, UnknownExtension(Vec::new()))]).unwrap();

    let (message, _proposal_ref) = group
        .propose_group_context_extensions(provider, extensions, &signer)
        .unwrap();

    assert_eq!(group.aad(), b"");

    let alice_processed_message = group
        .process_message(provider, message.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_self_update() {
    use crate::treesync::LeafNodeParameters;

    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    let commit = group
        .self_update(provider, &signer, LeafNodeParameters::default())
        .unwrap();

    assert_eq!(group.aad(), b"");

    let alice_processed_message = group
        .process_message(
            provider,
            commit.into_commit().into_protocol_message().unwrap(),
        )
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_self_update_with_new_signer() {
    use crate::{credentials::NewSignerBundle, treesync::LeafNodeParameters};

    let provider = &Provider::default();
    let (mut group, _old_credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    let (new_credential_with_key, _, signature_key_pair, _) =
        setup_client("Bob", ciphersuite, &Provider::default());

    let new_signer = NewSignerBundle {
        signer: &signature_key_pair,
        credential_with_key: new_credential_with_key,
    };

    let commit = group
        .self_update_with_new_signer(provider, &signer, new_signer, LeafNodeParameters::default())
        .unwrap();

    assert_eq!(group.aad(), b"");

    let alice_processed_message = group
        .process_message(
            provider,
            commit.into_commit().into_protocol_message().unwrap(),
        )
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_propose_self_update() {
    use crate::treesync::LeafNodeParameters;

    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    let (proposal, _hash_reference) = group
        .propose_self_update(provider, &signer, LeafNodeParameters::default())
        .unwrap();

    assert_eq!(group.aad(), b"");

    let alice_processed_message = group
        .process_message(provider, proposal.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}

#[openmls_test::openmls_test]
fn test_aad_propose_self_update_with_new_signer() {
    use crate::{credentials::NewSignerBundle, treesync::LeafNodeParameters};

    let provider = &Provider::default();
    let (mut group, _old_credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let aad: Vec<u8> = b"Test AAD".to_vec();
    group.set_aad(aad);

    let (new_credential_with_key, _, signature_key_pair, _) =
        setup_client("Alice", ciphersuite, &Provider::default());

    let new_signer = NewSignerBundle {
        signer: &signature_key_pair,
        credential_with_key: new_credential_with_key,
    };

    let (proposal, _hash_reference) = group
        .propose_self_update_with_new_signer(
            provider,
            &signer,
            new_signer,
            LeafNodeParameters::default(),
        )
        .unwrap();

    assert_eq!(group.aad(), b"");

    let alice_processed_message = group
        .process_message(provider, proposal.into_protocol_message().unwrap())
        .unwrap();

    assert_eq!(alice_processed_message.aad(), b"Test AAD");
}
