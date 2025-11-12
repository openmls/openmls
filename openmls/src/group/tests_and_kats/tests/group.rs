use crate::{
    framing::*,
    group::{mls_group::tests_and_kats::utils::setup_alice_group, *},
    *,
};
use mls_group::tests_and_kats::utils::{setup_alice_bob, setup_alice_bob_group, setup_client};
use prelude::KeyPackageBundle;
use treesync::{node::leaf_node::Capabilities, LeafNodeParameters};

#[openmls_test::openmls_test]
fn create_commit_optional_path() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Define identities
    let (alice_credential_with_key, alice_signer, bob_kpb, _bob_signer) =
        setup_alice_bob(ciphersuite, alice_provider, bob_provider);

    // Alice creates a group
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(alice_provider, &alice_signer, alice_credential_with_key)
        .unwrap();

    // Alice proposes to add Bob with forced self-update
    // Even though there are only Add Proposals, this should generated a path field
    // on the Commit
    let (commit_message, _welcome, _) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_kpb.key_package()),
        )
        .unwrap();

    let commit = match commit_message.body() {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!(),
        },
        _ => panic!(),
    };

    assert!(commit.has_path());

    alice_group
        .clear_pending_commit(alice_provider.storage())
        .unwrap();

    // Alice adds Bob without forced self-update
    let (commit_message, welcome, _) = alice_group
        .add_members_without_update(
            alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_kpb.key_package()),
        )
        .unwrap();

    let commit = match commit_message.body() {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!(),
        },
        _ => panic!(),
    };

    assert!(!commit.has_path());

    // Alice applies the Commit without the forced self-update
    alice_group.merge_pending_commit(alice_provider).unwrap();
    let ratchet_tree = alice_group.export_ratchet_tree();

    // Bob creates group from Welcome
    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .unwrap()
    .into_group(bob_provider)
    .unwrap();

    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // Alice updates
    let (commit_message, _, _) = alice_group
        .self_update(alice_provider, &alice_signer, LeafNodeParameters::default())
        .unwrap()
        .into_contents();

    let commit = match commit_message.body() {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!(),
        },
        _ => panic!(),
    };

    assert!(commit.has_path());

    // Apply UpdateProposal
    alice_group.merge_pending_commit(alice_provider).unwrap();
}

#[openmls_test::openmls_test]
fn basic_group_setup() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, _, _, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let _result =
        match alice_group.self_update(alice_provider, &alice_signer, LeafNodeParameters::default())
        {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {e:?}"),
        };
}

/// This test checks that we can't create a group that is invalid.
/// Specifically, we test that the extensions in the leaf node must be supported by the lead node's
/// own capabilities ([valn0107]).
///
/// [valn0107]: https://validation.openmls.tech/#valn0107
#[openmls_test::openmls_test]
fn wrong_group_create_config() {
    MlsGroupCreateConfig::builder()
        .with_leaf_node_extensions(Extensions::single(Extension::Unknown(
            0xff00,
            UnknownExtension(b"testdata".to_vec()),
        )))
        .expect_err("leaf node extension is not in leaf node capabilities, should have failed");

    MlsGroupCreateConfig::builder()
        .capabilities(
            Capabilities::builder()
                .extensions(vec![ExtensionType::Unknown(0xff00)])
                .build(),
        )
        .with_leaf_node_extensions(Extensions::single(Extension::Unknown(
            0xff01,
            UnknownExtension(b"testdata".to_vec()),
        )))
        .expect_err("leaf node extension is not in leaf node capabilities, should have failed");

    MlsGroupCreateConfig::builder()
        .capabilities(
            Capabilities::builder()
                .extensions(vec![ExtensionType::Unknown(0xff00)])
                .build(),
        )
        .with_leaf_node_extensions(Extensions::single(Extension::Unknown(
            0xff00,
            UnknownExtension(b"testdata".to_vec()),
        )))
        .expect("leaf node extension is in leaf node capabilities, should have succeeded")
        .build();
}

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
#[openmls_test::openmls_test]
fn group_operations() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    // Create group with alice and bob
    let (mut alice_group, alice_signer, mut bob_group, bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // Make sure that both groups have the same group context
    if alice_group.export_group_context() != bob_group.export_group_context() {
        panic!("Different group contexts");
    }

    // === Alice sends a message to Bob ===
    let message_alice = [1, 2, 3];
    let mls_cipertext_alice = alice_group
        .create_message(alice_provider, &alice_signer, &message_alice)
        .expect("An unexpected error occurred.");

    // Test persistence after Alice creates message
    alice_group
        .ensure_persistence(alice_provider.storage())
        .unwrap();

    let processed_message = bob_group
        .process_message(
            bob_provider,
            mls_cipertext_alice.into_protocol_message().unwrap(),
        )
        .unwrap();

    // Test persistence after Bob processes Alice's message
    bob_group
        .ensure_persistence(bob_provider.storage())
        .unwrap();

    match processed_message.content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            assert_eq!(message, &ApplicationMessage::new(message_alice.to_vec()));
        }
        _ => panic!("Wrong content type"),
    }

    // === Bob updates and commits ===
    let (commit_message, welcome_option, _) = bob_group
        .self_update(bob_provider, &bob_signer, LeafNodeParameters::default())
        .expect("Error updating group")
        .into_contents();

    // Check that there is a path
    let commit = match &commit_message.body {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!("Wrong content type"),
        },
        _ => panic!("Wrong message type"),
    };
    assert!(commit.has_path());
    // Check there is no Welcome message
    assert!(welcome_option.is_none());

    bob_group
        .merge_pending_commit(bob_provider)
        .expect("error merging commit");

    // Test persistence after Bob merges pending commit
    bob_group
        .ensure_persistence(bob_provider.storage())
        .unwrap();

    let processed_message = alice_group
        .process_message(
            alice_provider,
            commit_message.into_protocol_message().unwrap(),
        )
        .unwrap();
    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            alice_group
                .merge_staged_commit(alice_provider, *staged_commit)
                .expect("error merging commit");

            // Test persistence after Alice merges staged commit
            alice_group
                .ensure_persistence(alice_provider.storage())
                .unwrap();
        }
        _ => panic!("Wrong content type"),
    }

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // === Alice updates and commits ===
    let (commit_message, _, _) = alice_group
        .self_update(alice_provider, &alice_signer, LeafNodeParameters::default())
        .expect("Error updating group")
        .into_contents();

    let commit = match &commit_message.body {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!("Wrong content type"),
        },
        _ => panic!("Wrong message type"),
    };

    // Check that there is a path
    assert!(commit.has_path());

    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging commit");

    // Test persistence after Alice merges pending commit
    alice_group
        .ensure_persistence(alice_provider.storage())
        .unwrap();

    let processed_message = bob_group
        .process_message(
            bob_provider,
            commit_message.into_protocol_message().unwrap(),
        )
        .unwrap();

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            bob_group
                .merge_staged_commit(bob_provider, *staged_commit)
                .expect("error merging commit");

            // Test persistence after Bob merges staged commit
            bob_group
                .ensure_persistence(bob_provider.storage())
                .unwrap();
        }
        _ => panic!("Wrong content type"),
    }

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // === Bob updates and Alice commits ===
    let (bob_update_proposal, _) = bob_group
        .propose_self_update(bob_provider, &bob_signer, LeafNodeParameters::default())
        .expect("Error proposing update");

    match alice_group
        .process_message(
            alice_provider,
            bob_update_proposal.into_protocol_message().unwrap(),
        )
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::ProposalMessage(proposal) => {
            alice_group
                .store_pending_proposal(alice_provider.storage(), *proposal)
                .unwrap();
        }
        _ => panic!("Wrong content type"),
    }

    let (commit_message, _, _) = alice_group
        .commit_to_pending_proposals(alice_provider, &alice_signer)
        .unwrap();

    let commit = match &commit_message.body {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!("Wrong content type"),
        },
        _ => panic!("Wrong message type"),
    };

    // Check that there is a path
    assert!(commit.has_path());

    alice_group.merge_pending_commit(alice_provider).unwrap();

    match bob_group.process_message(
        bob_provider,
        commit_message.into_protocol_message().unwrap(),
    ) {
        Ok(processed_message) => match processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                bob_group
                    .merge_staged_commit(bob_provider, *staged_commit)
                    .expect("error merging commit");
            }
            _ => panic!("Wrong content type"),
        },
        Err(e) => panic!("Error processing message: {e:?}"),
    }

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // === Bob adds Charlie ===
    let (_charlie_credential_with_key, charlie_kpb, charlie_signer, _charlie_sig_pk) =
        setup_client("Charlie", ciphersuite, charlie_provider);

    let (commit_message, welcome, _) = bob_group
        .add_members(
            bob_provider,
            &bob_signer,
            core::slice::from_ref(charlie_kpb.key_package()),
        )
        .expect("Could not create add commit.");

    bob_group.merge_pending_commit(bob_provider).unwrap();

    // Test persistence after Bob merges pending commit
    bob_group
        .ensure_persistence(bob_provider.storage())
        .unwrap();

    match alice_group.process_message(
        alice_provider,
        commit_message.into_protocol_message().unwrap(),
    ) {
        Ok(processed_message) => match processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                alice_group
                    .merge_staged_commit(alice_provider, *staged_commit)
                    .expect("error merging commit");

                // Test persistence after Alice merges staged commit
                alice_group
                    .ensure_persistence(alice_provider.storage())
                    .unwrap();
            }
            _ => panic!("Wrong content type"),
        },
        Err(e) => panic!("Error processing message: {e:?}"),
    }

    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    let ratchet_tree = alice_group.export_ratchet_tree();
    let mut charlie_group = StagedWelcome::new_from_welcome(
        charlie_provider,
        &config,
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .unwrap()
    .into_group(charlie_provider)
    .unwrap();

    // Test persistence after Charlie joins group
    charlie_group
        .ensure_persistence(charlie_provider.storage())
        .unwrap();

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // === Charlie sends a message to the group ===
    let message_charlie = [1, 2, 3];
    let mls_ciphertext_charlie = charlie_group
        .create_message(charlie_provider, &charlie_signer, &message_charlie)
        .expect("An unexpected error occurred.");

    // Test persistence after Charlie creates message
    charlie_group
        .ensure_persistence(charlie_provider.storage())
        .unwrap();

    let processed_message = alice_group
        .process_message(
            alice_provider,
            mls_ciphertext_charlie
                .clone()
                .into_protocol_message()
                .unwrap(),
        )
        .unwrap();

    // Test persistence after Alice processes Charlie's message
    alice_group
        .ensure_persistence(alice_provider.storage())
        .unwrap();

    assert!(matches!(
        processed_message.content(),
            ProcessedMessageContent::ApplicationMessage(message) if message == &ApplicationMessage::new(message_charlie.to_vec())));

    let processed_message = bob_group
        .process_message(
            bob_provider,
            mls_ciphertext_charlie.into_protocol_message().unwrap(),
        )
        .unwrap();

    assert!(matches!(
        processed_message.content(),
            ProcessedMessageContent::ApplicationMessage(message) if message == &ApplicationMessage::new(message_charlie.to_vec())));

    // === Charlie updates and commits ===
    let (commit_message, _, _) = charlie_group
        .self_update(
            charlie_provider,
            &charlie_signer,
            LeafNodeParameters::default(),
        )
        .expect("Error updating group")
        .into_contents();

    let commit = match &commit_message.body {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!("Wrong content type"),
        },
        _ => panic!("Wrong message type"),
    };

    assert!(commit.has_path());

    charlie_group
        .merge_pending_commit(charlie_provider)
        .expect("error merging commit");

    match alice_group
        .process_message(
            alice_provider,
            commit_message.clone().into_protocol_message().unwrap(),
        )
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            alice_group
                .merge_staged_commit(alice_provider, *staged_commit)
                .expect("error merging commit");
        }
        _ => panic!("Wrong content type"),
    };

    match bob_group
        .process_message(
            bob_provider,
            commit_message.into_protocol_message().unwrap(),
        )
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            bob_group
                .merge_staged_commit(bob_provider, *staged_commit)
                .expect("error merging commit");
        }
        _ => panic!("Wrong content type"),
    };

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // === Charlie removes Bob ===
    let (commit_message, _, _) = charlie_group
        .remove_members(
            charlie_provider,
            &charlie_signer,
            &[bob_group.own_leaf_index()],
        )
        .expect("Could not create remove commit.");

    let commit = match &commit_message.body {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!("Wrong content type"),
        },
        _ => panic!("Wrong message type"),
    };

    assert!(commit.has_path());

    charlie_group
        .merge_pending_commit(charlie_provider)
        .expect("error merging commit");

    match alice_group
        .process_message(
            alice_provider,
            commit_message.clone().into_protocol_message().unwrap(),
        )
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            alice_group
                .merge_staged_commit(alice_provider, *staged_commit)
                .expect("error merging commit");
        }
        _ => panic!("Wrong content type"),
    };

    match bob_group
        .process_message(
            bob_provider,
            commit_message.into_protocol_message().unwrap(),
        )
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            bob_group
                .merge_staged_commit(bob_provider, *staged_commit)
                .expect("error merging commit");
        }
        _ => panic!("Wrong content type"),
    };

    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // Make sure all groups export the same key
    let alice_exporter = alice_group.epoch_authenticator();
    let charlie_exporter = charlie_group.epoch_authenticator();
    assert_eq!(alice_exporter, charlie_exporter);

    // Now alice tries to derive an exporter with too large of a key length.
    let exporter_length: usize = u16::MAX.into();
    let exporter_length = exporter_length + 1;
    let alice_exporter =
        alice_group.export_secret(alice_provider.crypto(), "export test", &[], exporter_length);
    assert!(alice_exporter.is_err())
}

#[openmls_test::openmls_test]
fn decrypt_after_leaf_index_reuse() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let dora_provider = &Provider::default();
    // Create credentials and keys
    let (alice_credential, alice_signature_keys) = crate::credentials::test_utils::new_credential(
        alice_provider,
        b"Alice",
        ciphersuite.signature_algorithm(),
    );
    let (bob_credential, bob_signature_keys) = crate::credentials::test_utils::new_credential(
        bob_provider,
        b"Bob",
        ciphersuite.signature_algorithm(),
    );
    let (charlie_credential, charlie_signature_keys) =
        crate::credentials::test_utils::new_credential(
            charlie_provider,
            b"charlie",
            ciphersuite.signature_algorithm(),
        );
    let (dora_credential, dora_signature_keys) = crate::credentials::test_utils::new_credential(
        dora_provider,
        b"dora",
        ciphersuite.signature_algorithm(),
    );

    // Alice creates a group
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .max_past_epochs(5)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(
            alice_provider,
            &alice_signature_keys,
            alice_credential.clone(),
        )
        .expect("Error creating group.");

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::generate(
        bob_provider,
        &bob_signature_keys,
        ciphersuite,
        bob_credential.clone(),
    );
    let bob_key_package = bob_key_package_bundle.key_package();

    // Generate KeyPackages
    let charlie_key_package_bundle = KeyPackageBundle::generate(
        charlie_provider,
        &charlie_signature_keys,
        ciphersuite,
        charlie_credential.clone(),
    );
    let charlie_key_package = charlie_key_package_bundle.key_package();

    // Generate KeyPackages
    let dora_key_package_bundle = KeyPackageBundle::generate(
        dora_provider,
        &dora_signature_keys,
        ciphersuite,
        dora_credential.clone(),
    );
    let dora_key_package = dora_key_package_bundle.key_package();

    // Alice adds Bob
    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            alice_provider,
            &alice_signature_keys,
            &[bob_key_package.clone(), charlie_key_package.clone()],
        )
        .expect("Could not create proposal.");

    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");

    let welcome = welcome.into_welcome().unwrap();

    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        &MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(5)
            .build(),
        welcome.clone(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .and_then(|staged_join| staged_join.into_group(bob_provider))
    .expect("error creating bob's group from welcome");

    let mut group_charlie = StagedWelcome::new_from_welcome(
        charlie_provider,
        &MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(5)
            .build(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .and_then(|staged_join| staged_join.into_group(charlie_provider))
    .expect("error creating charlie's group from welcome");

    let charlie_msg = group_charlie
        .create_message(
            charlie_provider,
            &charlie_signature_keys,
            b"this is a test message",
        )
        .unwrap();

    // replace charlie with dora
    let commit_bundle = alice_group
        .commit_builder()
        .propose_removals(Some(group_charlie.own_leaf_index()))
        .propose_adds(Some(dora_key_package.clone()))
        .load_psks(alice_provider.storage())
        .unwrap()
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signature_keys,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap();

    alice_group.merge_pending_commit(alice_provider).unwrap();

    let bob_incoming_commit = bob_group
        .process_message(
            bob_provider,
            commit_bundle
                .commit()
                .clone()
                .into_protocol_message()
                .unwrap(),
        )
        .unwrap();

    match bob_incoming_commit.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => bob_group
            .merge_staged_commit(bob_provider, *staged_commit)
            .unwrap(),
        _ => unreachable!(),
    };

    let charlie_protocol_message = charlie_msg.into_protocol_message().unwrap();

    let _bob_incoming_appmsg = bob_group
        .process_message(bob_provider, charlie_protocol_message)
        .unwrap();
}

#[openmls_test::openmls_test]
fn create_group_info_flag() {
    let alice_provider = &Provider::default();

    // The `use_ratchet_tree_extension` flag is set to `false` by default.
    let (mut alice_group, _alice_credential, alice_signer, _alice_pk) =
        setup_alice_group(ciphersuite, alice_provider);

    let commit_bundle = alice_group
        .commit_builder()
        .load_psks(alice_provider.storage())
        .unwrap()
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap();

    assert!(commit_bundle.group_info().is_none());

    // Now we set the `create_group_info` flag to `true`.
    let commit_bundle = alice_group
        .commit_builder()
        .load_psks(alice_provider.storage())
        .unwrap()
        .create_group_info(true)
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap();

    let group_info = commit_bundle.into_group_info_msg().unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();
    let exported_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, false)
        .unwrap();
    assert_eq!(group_info, exported_group_info);
}

#[openmls_test::openmls_test]
fn use_ratchet_tree_extension_flag() {
    for use_ratchet_tree_extension in [true, false] {
        let provider = &Provider::default();
        // The `use_ratchet_tree_extension` flag is set to `false` by default.
        let (mut alice_group, _alice_credential, alice_signer, _alice_pk) =
            setup_alice_group(ciphersuite, provider);

        let commit_bundle = alice_group
            .commit_builder()
            .load_psks(provider.storage())
            .unwrap()
            .build(provider.rand(), provider.crypto(), &alice_signer, |_| true)
            .unwrap()
            .stage_commit(provider)
            .unwrap();

        assert!(commit_bundle.group_info().is_none());

        // Now we set the `use_ratchet_tree_extension` flag.
        let commit_bundle = alice_group
            .commit_builder()
            .load_psks(provider.storage())
            .unwrap()
            .create_group_info(true)
            .use_ratchet_tree_extension(use_ratchet_tree_extension)
            .build(provider.rand(), provider.crypto(), &alice_signer, |_| true)
            .unwrap()
            .stage_commit(provider)
            .unwrap();

        let group_info = commit_bundle.into_group_info_msg().unwrap();
        alice_group.merge_pending_commit(provider).unwrap();
        let exported_group_info = alice_group
            .export_group_info(provider.crypto(), &alice_signer, use_ratchet_tree_extension)
            .unwrap();
        assert_eq!(group_info, exported_group_info);
    }
}

#[openmls_test::openmls_test]
fn test_create_group_info_with_extensions() {
    let provider = &Provider::default();
    let (mut alice_group, _alice_credential, alice_signer, _alice_pk) =
        setup_alice_group(ciphersuite, provider);

    let commit_bundle = alice_group
        .commit_builder()
        .load_psks(provider.storage())
        .unwrap()
        .build(provider.rand(), provider.crypto(), &alice_signer, |_| true)
        .unwrap()
        .stage_commit(provider)
        .unwrap();

    assert!(commit_bundle.group_info().is_none());

    let unknown_extension = Extension::Unknown(3, extensions::UnknownExtension(vec![]));
    let extensions = vec![unknown_extension.clone()];
    // Now we set the remaining extensions.
    let commit_bundle = alice_group
        .commit_builder()
        .load_psks(provider.storage())
        .unwrap()
        .use_ratchet_tree_extension(false)
        .create_group_info_with_extensions(extensions.clone())
        .unwrap()
        .build(provider.rand(), provider.crypto(), &alice_signer, |_| true)
        .unwrap()
        .stage_commit(provider)
        .unwrap();

    let group_info = commit_bundle.into_group_info_msg().unwrap();
    alice_group.merge_pending_commit(provider).unwrap();

    // compare against exported without extensions
    let exported_group_info = alice_group
        .export_group_info(provider.crypto(), &alice_signer, false)
        .unwrap();
    assert_ne!(group_info, exported_group_info);

    // compare against exported with extensions
    let exported_group_info = alice_group
        .export_group_info_with_additional_extensions(
            provider.crypto(),
            &alice_signer,
            false,
            extensions.clone(),
        )
        .unwrap();
    assert_eq!(group_info, exported_group_info);
}
