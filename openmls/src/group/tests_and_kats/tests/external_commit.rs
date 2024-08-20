//! This module contains tests for external commit messages
use tls_codec::{Deserialize, Serialize};

use crate::{
    framing::{MlsMessageIn, Sender},
    group::{
        tests_and_kats::utils::generate_credential_with_key, MlsGroup, MlsGroupCreateConfig,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    prelude::ProcessedMessageContent,
};

// External Commit in a group of 1 & 2 members and resync
#[openmls_test::openmls_test]
fn test_external_commit() {
    // Generate credentials with keys
    let alice_credential =
        generate_credential_with_key("Alice".into(), ciphersuite.signature_algorithm(), provider);

    let bob_credential =
        generate_credential_with_key("Bob".into(), ciphersuite.signature_algorithm(), provider);

    let charlie_credential = generate_credential_with_key(
        "Charlie".into(),
        ciphersuite.signature_algorithm(),
        provider,
    );

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .build();

    // Alice creates a group
    let mut alice_group = MlsGroup::new(
        provider,
        &alice_credential.signer,
        &mls_group_create_config,
        alice_credential.credential_with_key.clone(),
    )
    .unwrap();

    // === Single member group external join ===

    // Bob wants to commit externally.

    let verifiable_group_info = alice_group
        .export_group_info(provider, &alice_credential.signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let tree_option = alice_group.export_ratchet_tree();

    let (mut bob_group, public_message_commit, _) = MlsGroup::join_by_external_commit(
        provider,
        &bob_credential.signer,
        Some(tree_option.into()),
        verifiable_group_info,
        alice_group.configuration(),
        None,
        None,
        &[],
        bob_credential.credential_with_key.clone(),
    )
    .unwrap();
    bob_group.merge_pending_commit(provider).unwrap();

    let public_message_commit = {
        let serialized_message = public_message_commit.tls_serialize_detached().unwrap();

        MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
            .unwrap()
            .into_plaintext()
            .unwrap()
    };

    assert!(matches!(
        public_message_commit.sender(),
        Sender::NewMemberCommit
    ));

    // Alice processes Bob's Commit

    let processed_message = alice_group
        .process_message(provider, public_message_commit)
        .unwrap();

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            alice_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        }
        _ => panic!("Expected Commit message"),
    }

    // Compare Alice's and Bob's private & public state

    assert_eq!(
        alice_group.export_secret(provider, "label", b"context", 32),
        bob_group.export_secret(provider, "label", b"context", 32)
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // === 2-member group external join ===

    // Charlie wants to commit externally.

    let verifiable_group_info = alice_group
        .export_group_info(provider, &alice_credential.signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let tree_option = alice_group.export_ratchet_tree();

    let (mut charlie_group, public_message_commit, _) = MlsGroup::join_by_external_commit(
        provider,
        &charlie_credential.signer,
        Some(tree_option.into()),
        verifiable_group_info,
        alice_group.configuration(),
        None,
        None,
        &[],
        charlie_credential.credential_with_key.clone(),
    )
    .unwrap();
    charlie_group.merge_pending_commit(provider).unwrap();

    // Alice & Bob process Charlie's Commit

    let charlie_commit = MlsMessageIn::from(public_message_commit)
        .into_plaintext()
        .unwrap();

    let alice_processed_message = alice_group
        .process_message(provider, charlie_commit.clone())
        .unwrap();

    match alice_processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            alice_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        }
        _ => panic!("Expected Commit message"),
    }

    let bob_processed_message = bob_group.process_message(provider, charlie_commit).unwrap();

    match bob_processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            bob_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        }
        _ => panic!("Expected Commit message"),
    }

    // Compare Alice's, Bob's and Charlie's private & public state

    assert_eq!(
        alice_group.export_secret(provider, "label", b"context", 32),
        bob_group.export_secret(provider, "label", b"context", 32)
    );
    assert_eq!(
        alice_group.export_secret(provider, "label", b"context", 32),
        charlie_group.export_secret(provider, "label", b"context", 32)
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // === Resync ===

    // Alice wants to resync

    let verifiable_group_info = bob_group
        .export_group_info(provider, &bob_credential.signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let tree_option = bob_group.export_ratchet_tree();

    let (mut alice_group, public_message_commit, _) = MlsGroup::join_by_external_commit(
        provider,
        &alice_credential.signer,
        Some(tree_option.into()),
        verifiable_group_info,
        bob_group.configuration(),
        None,
        None,
        &[],
        alice_credential.credential_with_key.clone(),
    )
    .unwrap();
    alice_group.merge_pending_commit(provider).unwrap();

    // Bob & Charlie process Alice's Commit

    let alice_commit = MlsMessageIn::from(public_message_commit)
        .into_plaintext()
        .unwrap();

    let bob_processed_message = bob_group
        .process_message(provider, alice_commit.clone())
        .unwrap();

    match bob_processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            // Make sure there is a remove proposal for Alice
            let remove_proposals = staged_commit.remove_proposals().collect::<Vec<_>>();
            assert_eq!(remove_proposals.len(), 1);
            let remove_proposal = &remove_proposals[0];
            assert_eq!(remove_proposal.remove_proposal().removed().u32(), 0);
            bob_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        }
        _ => panic!("Expected Commit message"),
    }

    let charlie_processed_message = charlie_group
        .process_message(provider, alice_commit)
        .unwrap();

    match charlie_processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            charlie_group
                .merge_staged_commit(provider, *staged_commit)
                .unwrap();
        }
        _ => panic!("Expected Commit message"),
    }

    // Compare Alice's, Bob's and Charlie's private & public state

    assert_eq!(
        alice_group.export_secret(provider, "label", b"context", 32),
        bob_group.export_secret(provider, "label", b"context", 32)
    );
    assert_eq!(
        alice_group.export_secret(provider, "label", b"context", 32),
        charlie_group.export_secret(provider, "label", b"context", 32)
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );
}
