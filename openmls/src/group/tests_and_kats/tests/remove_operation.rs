//! This module tests the classification of remove operations with RemoveOperation

use crate::group::tests_and_kats::utils::{generate_credential_with_key, generate_key_package};
use crate::{framing::*, group::*};
use openmls_traits::prelude::*;

#[openmls_test::openmls_test]
fn remove_blank() {
    let group_id = GroupId::from_slice(b"Test Group");

    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

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

    // === Alice adds Bob & Charlie ===

    let (_message, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_credential_with_key_and_signer.signer,
            &[
                bob_key_package.key_package().clone(),
                charlie_key_package.key_package().clone(),
            ],
        )
        .expect("An unexpected error occurred.");
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome.clone(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(bob_provider)
    .expect("Error creating group from staged join");

    // === Remove operation ===

    let bob_index = bob_group.own_leaf_index();

    alice_group
        .remove_members(
            alice_provider,
            &alice_credential_with_key_and_signer.signer,
            &[bob_index],
        )
        .expect("error removing member the first time");

    alice_group.merge_pending_commit(alice_provider).unwrap();

    // try removing bob a second time
    alice_group
        .remove_members(
            alice_provider,
            &alice_credential_with_key_and_signer.signer,
            &[bob_index],
        )
        .expect_err("using API to re-remove someone should fail");

    // TODO: craft another remove commit that removes bob's (blank) index and check that merging
    //       that fails
}

// Tests the different variants of the RemoveOperation enum.
#[openmls_test::openmls_test]
fn test_remove_operation_variants() {
    // We define two test cases, one where the member is removed by another member
    // and one where the member leaves the group on its own
    #[derive(Debug, Clone, Copy)]
    enum TestCase {
        Remove,
        Leave,
    }

    for test_case in [TestCase::Remove, TestCase::Leave] {
        let group_id = GroupId::from_slice(b"Test Group");

        // Generate credentials with keys
        let alice_credential_with_key_and_signer = generate_credential_with_key(
            "Alice".into(),
            ciphersuite.signature_algorithm(),
            provider,
        );

        let bob_credential_with_key_and_signer =
            generate_credential_with_key("Bob".into(), ciphersuite.signature_algorithm(), provider);

        let charlie_credential_with_key_and_signer = generate_credential_with_key(
            "Charlie".into(),
            ciphersuite.signature_algorithm(),
            provider,
        );

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            bob_credential_with_key_and_signer.clone(),
        );
        let charlie_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            charlie_credential_with_key_and_signer,
        );

        // Define the MlsGroup configuration
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            provider,
            &alice_credential_with_key_and_signer.signer,
            &mls_group_create_config,
            group_id,
            alice_credential_with_key_and_signer
                .credential_with_key
                .clone(),
        )
        .expect("An unexpected error occurred.");

        // === Alice adds Bob & Charlie ===

        let (_message, welcome, _group_info) = alice_group
            .add_members(
                provider,
                &alice_credential_with_key_and_signer.signer,
                &[
                    bob_key_package.key_package().clone(),
                    charlie_key_package.key_package().clone(),
                ],
            )
            .expect("An unexpected error occurred.");
        alice_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome
            .into_welcome()
            .expect("expected message to be a welcome");

        let mut bob_group = StagedWelcome::new_from_welcome(
            provider,
            mls_group_create_config.join_config(),
            welcome.clone(),
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("Error creating staged join from Welcome")
        .into_group(provider)
        .expect("Error creating group from staged join");

        let mut charlie_group = StagedWelcome::new_from_welcome(
            provider,
            mls_group_create_config.join_config(),
            welcome,
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("Error creating staged join from Welcome")
        .into_group(provider)
        .expect("Error creating group from staged join");

        // === Remove operation ===

        let alice_index = alice_group.own_leaf_index();
        let bob_index = bob_group.own_leaf_index();

        // We differentiate between the two test cases here
        let (message, _welcome, _group_info) = match test_case {
            // Alice removes Bob
            TestCase::Remove => alice_group
                .remove_members(
                    provider,
                    &alice_credential_with_key_and_signer.signer,
                    &[bob_index],
                )
                .expect("Could not remove members."),
            // Bob leaves
            TestCase::Leave => {
                // Bob leaves the group
                let message = bob_group
                    .leave_group(provider, &bob_credential_with_key_and_signer.signer)
                    .expect("Could not leave group.");

                // Alice & Charlie store the pending proposal
                for group in [&mut alice_group, &mut charlie_group] {
                    let processed_message = group
                        .process_message(provider, message.clone().into_protocol_message().unwrap())
                        .expect("Could not process message.");

                    match processed_message.into_content() {
                        ProcessedMessageContent::ProposalMessage(proposal) => {
                            group
                                .store_pending_proposal(provider.storage(), *proposal)
                                .unwrap();
                        }
                        _ => unreachable!(),
                    }
                }

                // Alice commits to Bob's proposal
                alice_group
                    .commit_to_pending_proposals(
                        provider,
                        &alice_credential_with_key_and_signer.signer,
                    )
                    .expect("An unexpected error occurred.")
            }
        };

        // === Remove operation from Alice's perspective ===

        let alice_staged_commit = alice_group.pending_commit().expect("No pending commit.");

        let remove_proposal = alice_staged_commit
            .remove_proposals()
            .next()
            .expect("An unexpected error occurred.");

        let remove_operation = RemoveOperation::new(remove_proposal, &alice_group)
            .expect("An unexpected Error occurred.");

        match test_case {
            TestCase::Remove => {
                // We expect this variant, since Alice removed Bob
                match remove_operation {
                    RemoveOperation::WeRemovedThem(removed) => {
                        // Check that it was indeed Bob who was removed
                        assert_eq!(removed, bob_index);
                    }
                    _ => unreachable!(),
                }
            }
            TestCase::Leave => {
                // We expect this variant, since Bob left
                match remove_operation {
                    RemoveOperation::TheyLeft(removed) => {
                        // Check that it was indeed Bob who left
                        assert_eq!(removed, bob_index);
                    }
                    _ => unreachable!(),
                }
            }
        }

        // === Remove operation from Bob's perspective ===

        let bob_processed_message = bob_group
            .process_message(provider, message.clone().into_protocol_message().unwrap())
            .expect("Could not process message.");

        match bob_processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(bob_staged_commit) => {
                let remove_proposal = bob_staged_commit
                    .remove_proposals()
                    .next()
                    .expect("An unexpected error occurred.");

                let remove_operation = RemoveOperation::new(remove_proposal, &bob_group)
                    .expect("An unexpected Error occurred.");

                match test_case {
                    TestCase::Remove => {
                        // We expect this variant, since Alice removed Bob
                        match remove_operation {
                            RemoveOperation::WeWereRemovedBy(sender) => {
                                // Make sure Alice is indeed a member
                                assert!(sender.is_member());
                                // Check Bob was removed
                                assert!(bob_staged_commit.self_removed());
                                match sender {
                                    Sender::Member(member) => {
                                        // Check that it was Alice who removed Bob
                                        assert_eq!(member, alice_index);
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                    TestCase::Leave => {
                        // We expect this variant, since Bob left
                        match remove_operation {
                            RemoveOperation::WeLeft => {
                                // Check that Bob is no longer part of the group
                                assert!(bob_staged_commit.self_removed());
                            }
                            _ => unreachable!(),
                        }
                    }
                }
            }
            _ => unreachable!(),
        }

        // === Remove operation from Charlie's perspective ===

        let protocol_message = message.into_protocol_message().unwrap();

        let charlie_processed_message = charlie_group
            .process_message(provider, protocol_message)
            .expect("Could not process message.");

        match charlie_processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(charlie_staged_commit) => {
                let remove_proposal = charlie_staged_commit
                    .remove_proposals()
                    .next()
                    .expect("An unexpected error occurred.");

                let remove_operation = RemoveOperation::new(remove_proposal, &charlie_group)
                    .expect("An unexpected Error occurred.");

                match test_case {
                    TestCase::Remove => {
                        // We expect this variant, since Alice removed Bob
                        match remove_operation {
                            RemoveOperation::TheyWereRemovedBy((removed, sender)) => {
                                // Make sure Alice is indeed a member
                                assert!(sender.is_member());
                                // Check that it was indeed Bob who was removed
                                assert_eq!(removed, bob_index);
                                match sender {
                                    Sender::Member(member) => {
                                        // Check that it was Alice who removed Bob
                                        assert_eq!(member, alice_index);
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                    TestCase::Leave => {
                        // We expect this variant, since Bob left
                        match remove_operation {
                            RemoveOperation::TheyLeft(removed) => {
                                // Check that it was indeed Bob who left
                                assert_eq!(removed, bob_index);
                            }
                            _ => unreachable!(),
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}
