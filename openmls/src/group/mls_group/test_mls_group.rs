use core_group::test_core_group::setup_client;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsProvider};
use tls_codec::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafNodeIndex,
    extensions::errors::InvalidExtensionError,
    framing::*,
    group::{config::CryptoConfig, errors::*, *},
    key_packages::*,
    messages::proposals::*,
    prelude::Capabilities,
    test_utils::test_framework::{
        errors::ClientError, noop_authentication_service, ActionType::Commit, CodecUse,
        MlsGroupTestSetup,
    },
    test_utils::*,
    tree::sender_ratchet::SenderRatchetConfiguration,
};

#[apply(ciphersuites_and_providers)]
fn test_mls_group_persistence(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupCreateConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_config,
        group_id.clone(),
        alice_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    // Check the internal state has changed
    assert_eq!(alice_group.state_changed(), InnerState::Changed);

    alice_group
        .save(provider.key_store())
        .expect("Could not write group state to file");

    let alice_group_deserialized =
        MlsGroup::load(&group_id, provider.key_store()).expect("Could not deserialize MlsGroup");

    assert_eq!(
        (
            alice_group.export_ratchet_tree(),
            alice_group.export_secret(provider.crypto(), "test", &[], 32)
        ),
        (
            alice_group_deserialized.export_ratchet_tree(),
            alice_group_deserialized.export_secret(provider.crypto(), "test", &[], 32)
        )
    );
}

// This tests if the remover is correctly passed to the callback when one member
// issues a RemoveProposal and another members issues the next Commit.
#[apply(ciphersuites_and_providers)]
fn remover(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential, bob_kpb, bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);
    let (_charlie_credential, charlie_kpb, charlie_signer, _charlie_pk) =
        setup_client("Charly", ciphersuite, provider);

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob ===
    let (_queued_message, welcome, _group_info) = alice_group
        .add_members(provider, &alice_signer, &[bob_kpb.key_package().clone()])
        .expect("Could not add member to group.");

    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome.into_welcome().expect("expected a welcome");

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(provider)
    .expect("Error creating group from staged join");

    // === Bob adds Charlie ===
    let (queued_messages, welcome, _group_info) = bob_group
        .add_members(provider, &bob_signer, &[charlie_kpb.key_package().clone()])
        .unwrap();

    let alice_processed_message = alice_group
        .process_message(
            provider,
            queued_messages
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process messages.");
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    bob_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome.into_welcome().expect("expected a welcome");

    let mut charlie_group = StagedWelcome::new_from_welcome(
        provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(bob_group.export_ratchet_tree().into()),
    )
    .expect("Error creating group from Welcome")
    .into_group(provider)
    .expect("Error creating group from Welcome");

    // === Alice removes Bob & Charlie commits ===

    let (queued_messages, _) = alice_group
        .propose_remove_member(provider, &alice_signer, LeafNodeIndex::new(1))
        .expect("Could not propose removal");

    let charlie_processed_message = charlie_group
        .process_message(
            provider,
            queued_messages
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process messages.");

    // Check that we received the correct proposals
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        charlie_processed_message.into_content()
    {
        if let Proposal::Remove(ref remove_proposal) = staged_proposal.proposal() {
            // Check that Bob was removed
            assert_eq!(remove_proposal.removed(), LeafNodeIndex::new(1));
            // Store proposal
            charlie_group.store_pending_proposal(*staged_proposal.clone());
        } else {
            unreachable!("Expected a Proposal.");
        }

        // Check that Alice removed Bob
        assert!(matches!(
            staged_proposal.sender(),
            Sender::Member(member) if member.u32() == 0
        ));
    } else {
        unreachable!("Expected a QueuedProposal.");
    }

    // Charlie commits
    let (_queued_messages, _welcome, _group_info) = charlie_group
        .commit_to_pending_proposals(provider, &charlie_signer)
        .expect("Could not commit proposal");

    // Check that we receive the correct proposal
    if let Some(staged_commit) = charlie_group.pending_commit() {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        assert_eq!(remove.remove_proposal().removed().u32(), 1);
        // Check that Alice removed Bob
        assert!(matches!(remove.sender(), Sender::Member(member) if member.u32() == 0));
    } else {
        unreachable!("Expected a StagedCommit.");
    };

    charlie_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // TODO #524: Check that Alice removed Bob
}

#[apply(ciphersuites_and_providers)]
fn export_secret(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    assert!(
        alice_group
            .export_secret(provider.crypto(), "test1", &[], ciphersuite.hash_length())
            .expect("An unexpected error occurred.")
            != alice_group
                .export_secret(provider.crypto(), "test2", &[], ciphersuite.hash_length())
                .expect("An unexpected error occurred.")
    );
    assert!(
        alice_group
            .export_secret(provider.crypto(), "test", &[0u8], ciphersuite.hash_length())
            .expect("An unexpected error occurred.")
            != alice_group
                .export_secret(provider.crypto(), "test", &[1u8], ciphersuite.hash_length())
                .expect("An unexpected error occurred.")
    )
}

#[apply(ciphersuites_and_providers)]
fn staged_join(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential, bob_kpb, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    let (_queued_message, welcome, _group_info) = alice_group
        .add_members(provider, &alice_signer, &[bob_kpb.key_package().clone()])
        .expect("Could not add member to group.");

    alice_group
        .merge_pending_commit(provider)
        .expect("couldn't merge commit that adds bob");

    let join_config = mls_group_create_config.join_config();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome.into_welcome().expect("expected a welcome");

    let staged_bob_group = StagedWelcome::new_from_welcome(
        provider,
        join_config,
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("error creating staged mls group");

    let welcome_sender = staged_bob_group
        .welcome_sender()
        .expect("couldn't determine sender of welcome");

    assert_eq!(
        welcome_sender.credential(),
        alice_kpb.key_package().leaf_node().credential()
    );

    let bob_group = staged_bob_group
        .into_group(provider)
        .expect("error turning StagedWelcome into MlsGroup");

    assert_eq!(
        alice_group
            .export_secret(provider.crypto(), "test", &[], ciphersuite.hash_length())
            .expect("An unexpected error occurred."),
        bob_group
            .export_secret(provider.crypto(), "test", &[], ciphersuite.hash_length())
            .expect("An unexpected error occurred.")
    );
}

#[apply(ciphersuites_and_providers)]
fn test_invalid_plaintext(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // Some basic setup functions for the MlsGroup.
    let mls_group_create_config = MlsGroupCreateConfig::test_default(ciphersuite);

    let number_of_clients = 20;
    let setup = MlsGroupTestSetup::new(
        mls_group_create_config,
        number_of_clients,
        CodecUse::StructMessages,
    );
    // Create a basic group with more than 4 members to create a tree with intermediate nodes.
    let group_id = setup
        .create_random_group(10, ciphersuite, noop_authentication_service)
        .expect("An unexpected error occurred.");
    let mut groups = setup.groups.write().expect("An unexpected error occurred.");
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    let (_, client_id) = &group
        .members()
        .find(|(index, _)| index == &0)
        .expect("An unexpected error occurred.");

    let clients = setup.clients.read().expect("An unexpected error occurred.");
    let client = clients
        .get(client_id)
        .expect("An unexpected error occurred.")
        .read()
        .expect("An unexpected error occurred.");

    let (mls_message, _welcome_option, _group_info) = client
        .self_update(Commit, &group_id, None)
        .expect("error creating self update");

    // Store the context and membership key so that we can re-compute the membership tag later.
    let client_groups = client.groups.read().unwrap();
    let client_group = client_groups.get(&group_id).unwrap();
    let membership_key = client_group.group().message_secrets().membership_key();

    // Tamper with the message such that signature verification fails
    // Once #574 is addressed the new function from there should be used to manipulate the signature.
    // Right now the membership tag is verified first, wihich yields `VerificationError::InvalidMembershipTag`
    // error instead of a `CredentialError:InvalidSignature`.
    let mut msg_invalid_signature = mls_message.clone();
    if let MlsMessageBodyOut::PublicMessage(ref mut pt) = msg_invalid_signature.body {
        pt.invalidate_signature()
    };

    // Tamper with the message such that sender lookup fails
    let mut msg_invalid_sender = mls_message;
    let random_sender = Sender::build_member(LeafNodeIndex::new(987543210));
    match &mut msg_invalid_sender.body {
        MlsMessageBodyOut::PublicMessage(pt) => {
            pt.set_sender(random_sender);
            pt.set_membership_tag(
                provider.crypto(),
                ciphersuite,
                membership_key,
                client_group.group().message_secrets().serialized_context(),
            )
            .unwrap()
        }
        _ => panic!("This should be a plaintext!"),
    };

    drop(client_groups);
    drop(client);
    drop(clients);

    let error = setup
        // We're the "no_client" id to prevent the original sender from treating
        // this message as his own and merging the pending commit.
        .distribute_to_members(
            "no_client".as_bytes(),
            group,
            &msg_invalid_signature.into(),
            &noop_authentication_service,
        )
        .expect_err("No error when distributing message with invalid signature.");

    assert_eq!(
        ClientError::ProcessMessageError(ProcessMessageError::ValidationError(
            ValidationError::InvalidMembershipTag
        )),
        error
    );

    let error = setup
        // We're the "no_client" id to prevent the original sender from treating
        // this message as his own and merging the pending commit.
        .distribute_to_members(
            "no_client".as_bytes(),
            group,
            &msg_invalid_sender.into(),
            &noop_authentication_service,
        )
        .expect_err("No error when distributing message with invalid signature.");

    assert_eq!(
        ClientError::ProcessMessageError(ProcessMessageError::ValidationError(
            ValidationError::UnknownMember
        )),
        error
    );
}

#[apply(ciphersuites_and_providers)]
fn test_verify_staged_commit_credentials(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential, bob_kpb, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupCreateConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_config,
        group_id,
        alice_credential_with_key.clone(),
    )
    .expect("An unexpected error occurred.");

    // There should be no pending commit after group creation.
    assert!(alice_group.pending_commit().is_none());

    let bob_key_package = bob_kpb.key_package();

    // === Alice adds Bob to the group ===
    let (proposal, _) = alice_group
        .propose_add_member(provider, &alice_signer, bob_key_package)
        .expect("error creating self-update proposal");

    let alice_processed_message = alice_group
        .process_message(provider, proposal.into_protocol_message().unwrap())
        .expect("Could not process messages.");
    assert!(alice_group.pending_commit().is_none());

    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        alice_processed_message.into_content()
    {
        alice_group.store_pending_proposal(*staged_proposal);
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    let (_msg, welcome_option, _group_info) = alice_group
        .self_update(provider, &alice_signer)
        .expect("error creating self-update commit");

    // Merging the pending commit should clear the pending commit and we should
    // end up in the same state as bob.
    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");
    assert!(alice_group.pending_commit().is_none());
    assert!(alice_group.pending_proposals().next().is_none());

    let welcome: MlsMessageIn = welcome_option.expect("expected a welcome").into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        mls_group_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("error creating group from welcome")
    .into_group(provider)
    .expect("error creating group from welcome");

    assert_eq!(
        bob_group.export_ratchet_tree(),
        alice_group.export_ratchet_tree()
    );
    assert_eq!(
        bob_group.export_secret(provider.crypto(), "test", &[], ciphersuite.hash_length()),
        alice_group.export_secret(provider.crypto(), "test", &[], ciphersuite.hash_length())
    );
    // Bob is added and the state aligns.

    // === Make a new, empty commit and check that the leaf node credentials match ===
    let (commit_msg, _welcome_option, _group_info) = alice_group
        .self_update(provider, &alice_signer)
        .expect("error creating self-update commit");

    // empty commits should only produce a single message
    assert!(_welcome_option.is_none());
    assert!(_group_info.is_none());

    // There should be a pending commit after issuing a self-update commit.
    let alice_pending_commit = alice_group
        .pending_commit()
        .expect("alice should have the self-update as pending commit");

    // The commit contains only Alice's credentials, in the update path leaf node.
    for cred in alice_pending_commit.credentials_to_verify() {
        assert_eq!(cred, &alice_credential_with_key.credential);
    }

    // great, they match! now commit
    alice_group
        .merge_pending_commit(provider)
        .expect("alice failed to merge the pending empty commit");

    // === transfer message to bob and process it ===

    // this requires serializing and deserializing
    let mut wire_msg = Vec::<u8>::new();
    commit_msg
        .tls_serialize(&mut wire_msg)
        .expect("alice failed serializing her message");
    let msg_in = MlsMessageIn::tls_deserialize(&mut &wire_msg[..])
        .expect("bob failed deserializing alice's message");

    // neither party should have pending proposals
    assert!(alice_group.pending_proposals().next().is_none());
    assert!(bob_group.pending_proposals().next().is_none());

    // neither should have pending commits after merging and before processing
    assert!(bob_group.pending_commit().is_none());
    assert!(alice_group.pending_commit().is_none());

    // further process the deserialized message
    let processed_message = bob_group
        .process_message(provider, msg_in.try_into_protocol_message().unwrap())
        .expect("bob failed processing alice's message");

    // the processed message must be a staged commit message
    assert!(matches!(
        processed_message.content(),
        ProcessedMessageContent::StagedCommitMessage(_)
    ));

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    {
        // The commit contains only Alice's credentials, in the update path leaf node.
        for cred in staged_commit.credentials_to_verify() {
            assert_eq!(cred, &alice_credential_with_key.credential);
        }

        // bob merges alice's message
        bob_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("bob failed merging alice's empty commit (staged)");

        // finally, the state should match
        assert_eq!(
            bob_group.export_ratchet_tree(),
            alice_group.export_ratchet_tree()
        );
        assert_eq!(
            bob_group.export_secret(provider.crypto(), "test", &[], ciphersuite.hash_length()),
            alice_group.export_secret(provider.crypto(), "test", &[], ciphersuite.hash_length())
        );
    } else {
        unreachable!()
    }

    // neither should have pending commits after merging and processing
    assert!(bob_group.pending_commit().is_none());
    assert!(alice_group.pending_commit().is_none());
}

#[apply(ciphersuites_and_providers)]
fn test_commit_with_update_path_leaf_node(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential, bob_kpb, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential_with_key.clone(),
    )
    .expect("An unexpected error occurred.");

    // There should be no pending commit after group creation.
    assert!(alice_group.pending_commit().is_none());

    let bob_key_package = bob_kpb.key_package();

    // === Alice adds Bob to the group ===
    let (proposal, _) = alice_group
        .propose_add_member(provider, &alice_signer, bob_key_package)
        .expect("error creating self-update proposal");

    let alice_processed_message = alice_group
        .process_message(provider, proposal.into_protocol_message().unwrap())
        .expect("Could not process messages.");
    assert!(alice_group.pending_commit().is_none());

    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        alice_processed_message.into_content()
    {
        alice_group.store_pending_proposal(*staged_proposal);
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    println!("\nCreating commit with add proposal.");
    let (_msg, welcome_option, _group_info) = alice_group
        .self_update(provider, &alice_signer)
        .expect("error creating self-update commit");
    println!("Done creating commit.");

    // Merging the pending commit should clear the pending commit and we should
    // end up in the same state as bob.
    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");
    assert!(alice_group.pending_commit().is_none());
    assert!(alice_group.pending_proposals().next().is_none());

    let welcome: MlsMessageIn = welcome_option.expect("expected a welcome").into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("error creating group from welcome")
    .into_group(provider)
    .expect("error creating group from welcome");

    assert_eq!(
        bob_group.export_ratchet_tree(),
        alice_group.export_ratchet_tree()
    );
    assert_eq!(
        bob_group.export_secret(provider.crypto(), "test", &[], ciphersuite.hash_length()),
        alice_group.export_secret(provider.crypto(), "test", &[], ciphersuite.hash_length())
    );
    // Bob is added and the state aligns.

    // === Make a new, empty commit and check that the leaf node credentials match ===

    println!("\nCreating self-update commit.");
    let (commit_msg, _welcome_option, _group_info) = alice_group
        .self_update(provider, &alice_signer)
        .expect("error creating self-update commit");
    println!("Done creating commit.");

    // empty commits should only produce a single message
    assert!(_welcome_option.is_none());
    assert!(_group_info.is_none());

    // There should be a pending commit after issuing a self-update commit.
    let alice_pending_commit = alice_group
        .pending_commit()
        .expect("alice should have the self-update as pending commit");

    // The credential on the update_path leaf node should be set and be the same as alice's
    // credential
    let alice_update_path_leaf_node = alice_pending_commit
        .update_path_leaf_node()
        .expect("expected alice's staged commit to have an update path");
    assert_eq!(
        alice_update_path_leaf_node.credential(),
        &alice_credential_with_key.credential
    );

    // great, they match! now commit
    alice_group
        .merge_pending_commit(provider)
        .expect("alice failed to merge the pending empty commit");

    // === transfer message to bob and process it ===

    // this requires serializing and deserializing
    let mut wire_msg = Vec::<u8>::new();
    commit_msg
        .tls_serialize(&mut wire_msg)
        .expect("alice failed serializing her message");
    let msg_in = MlsMessageIn::tls_deserialize(&mut &wire_msg[..])
        .expect("bob failed deserializing alice's message");

    // neither party should have pending proposals
    assert!(alice_group.pending_proposals().next().is_none());
    assert!(bob_group.pending_proposals().next().is_none());

    // neither should have pending commits after merging and before processing
    assert!(bob_group.pending_commit().is_none());
    assert!(alice_group.pending_commit().is_none());

    // further process the deserialized message
    let processed_message = bob_group
        .process_message(provider, msg_in.try_into_protocol_message().unwrap())
        .expect("bob failed processing alice's message");

    // the processed message must be a staged commit message
    assert!(matches!(
        processed_message.content(),
        ProcessedMessageContent::StagedCommitMessage(_)
    ));

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    {
        // bob must check the credential in the leaf node of the update_path of alice's commit
        let bob_update_path_leaf_node = staged_commit
            .update_path_leaf_node()
            .expect("staged commit received by bob should carry an update path with a leaf node");
        assert_eq!(
            bob_update_path_leaf_node.credential(),
            &alice_credential_with_key.credential
        );

        // bob merges alice's message
        bob_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("bob failed merging alice's empty commit (staged)");

        // finally, the state should match
        assert_eq!(
            bob_group.export_ratchet_tree(),
            alice_group.export_ratchet_tree()
        );
        assert_eq!(
            bob_group.export_secret(provider.crypto(), "test", &[], ciphersuite.hash_length()),
            alice_group.export_secret(provider.crypto(), "test", &[], ciphersuite.hash_length())
        );
    } else {
        unreachable!()
    }

    // neither should have pending commits after merging and processing
    assert!(bob_group.pending_commit().is_none());
    assert!(alice_group.pending_commit().is_none());
}

#[apply(ciphersuites_and_providers)]
fn test_pending_commit_logic(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential, bob_kpb, bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    // There should be no pending commit after group creation.
    assert!(alice_group.pending_commit().is_none());

    let bob_key_package = bob_kpb.key_package();

    // Let's add bob
    let (proposal, _) = alice_group
        .propose_add_member(provider, &alice_signer, bob_key_package)
        .expect("error creating add-bob proposal");

    let alice_processed_message = alice_group
        .process_message(provider, proposal.into_protocol_message().unwrap())
        .expect("Could not process messages.");
    assert!(alice_group.pending_commit().is_none());

    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        alice_processed_message.into_content()
    {
        alice_group.store_pending_proposal(*staged_proposal);
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // There should be no pending commit after issuing and processing a proposal.
    assert!(alice_group.pending_commit().is_none());

    println!("\nCreating commit with add proposal.");
    let (_msg, _welcome_option, _group_info) = alice_group
        .self_update(provider, &alice_signer)
        .expect("error creating self-update commit");
    println!("Done creating commit.");

    // There should be a pending commit after issueing a proposal.
    assert!(alice_group.pending_commit().is_some());

    // If there is a pending commit, other commit- or proposal-creating actions
    // should fail.
    let error = alice_group
        .add_members(provider, &alice_signer, &[bob_key_package.clone()])
        .expect_err("no error committing while a commit is pending");
    assert!(matches!(
        error,
        AddMembersError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
    let error = alice_group
        .propose_add_member(provider, &alice_signer, bob_key_package)
        .expect_err("no error creating a proposal while a commit is pending");
    assert_eq!(
        error,
        ProposeAddMemberError::GroupStateError(MlsGroupStateError::PendingCommit)
    );
    let error = alice_group
        .remove_members(provider, &alice_signer, &[LeafNodeIndex::new(1)])
        .expect_err("no error committing while a commit is pending");
    assert!(matches!(
        error,
        RemoveMembersError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
    let error = alice_group
        .propose_remove_member(provider, &alice_signer, LeafNodeIndex::new(1))
        .expect_err("no error creating a proposal while a commit is pending");
    assert_eq!(
        error,
        ProposeRemoveMemberError::GroupStateError(MlsGroupStateError::PendingCommit)
    );
    let error = alice_group
        .commit_to_pending_proposals(provider, &alice_signer)
        .expect_err("no error committing while a commit is pending");
    assert!(matches!(
        error,
        CommitToPendingProposalsError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
    let error = alice_group
        .self_update(provider, &alice_signer)
        .expect_err("no error committing while a commit is pending");
    assert!(matches!(
        error,
        SelfUpdateError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
    let error = alice_group
        .propose_self_update(provider, &alice_signer, None)
        .expect_err("no error creating a proposal while a commit is pending");
    assert!(matches!(
        error,
        ProposeSelfUpdateError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));

    // Clearing the pending commit should actually clear it.
    alice_group.clear_pending_commit();
    assert!(alice_group.pending_commit().is_none());

    // Creating a new commit should commit the same proposals.
    let (_msg, welcome_option, _group_info) = alice_group
        .self_update(provider, &alice_signer)
        .expect("error creating self-update commit");

    // Merging the pending commit should clear the pending commit and we should
    // end up in the same state as bob.
    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");
    assert!(alice_group.pending_commit().is_none());

    let welcome: MlsMessageIn = welcome_option.expect("expected a welcome").into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("error creating group from welcome")
    .into_group(provider)
    .expect("error creating group from welcome");

    assert_eq!(
        bob_group.export_ratchet_tree(),
        alice_group.export_ratchet_tree()
    );
    assert_eq!(
        bob_group.export_secret(provider.crypto(), "test", &[], ciphersuite.hash_length()),
        alice_group.export_secret(provider.crypto(), "test", &[], ciphersuite.hash_length())
    );

    // While a commit is pending, merging Bob's commit should clear the pending commit.
    let (_msg, _welcome_option, _group_info) = alice_group
        .self_update(provider, &alice_signer)
        .expect("error creating self-update commit");

    let (msg, _welcome_option, _group_info) = bob_group
        .self_update(provider, &bob_signer)
        .expect("error creating self-update commit");

    let alice_processed_message = alice_group
        .process_message(provider, msg.into_protocol_message().unwrap())
        .expect("Could not process messages.");
    assert!(alice_group.pending_commit().is_some());

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }
    assert!(alice_group.pending_commit().is_none());
}

// Test that the key package and the corresponding private key are deleted when
// creating a new group for a welcome message.
#[apply(ciphersuites_and_providers)]
fn key_package_deletion(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_kpb, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);
    let bob_key_package = bob_kpb.key_package();

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob ===
    let (_queued_message, welcome, _group_info) = alice_group
        .add_members(provider, &alice_signer, &[bob_key_package.clone()])
        .unwrap();

    alice_group.merge_pending_commit(provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    // === Bob joins the group ===
    let _bob_group = StagedWelcome::new_from_welcome(
        provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(provider)
    .expect("Error creating group from staged join");

    // TEST: The private key must be gone from the key store.
    assert!(provider
        .key_store()
        .read::<HpkePrivateKey>(bob_key_package.hpke_init_key().as_slice())
        .is_none(),
        "The HPKE private key is still in the key store after creating a new group from the key package.");

    // TEST: The key package must be gone from the key store.
    assert!(
        provider
            .key_store()
            .read::<KeyPackage>(
                bob_key_package
                    .hash_ref(provider.crypto())
                    .unwrap()
                    .as_slice()
            )
            .is_none(),
        "The key package is still in the key store after creating a new group from it."
    );
}

#[apply(ciphersuites_and_providers)]
fn remove_prosposal_by_ref(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_kpb, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);
    let bob_key_package = bob_kpb.key_package().clone();
    let (_charlie_credential_with_key, charlie_kpb, _charlie_signer, _charlie_pk) =
        setup_client("Charlie", ciphersuite, provider);
    let charlie_key_package = charlie_kpb.key_package();

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    // alice adds bob and bob processes the welcome
    let (_, welcome, _) = alice_group
        .add_members(provider, &alice_signer, &[bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit(provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(provider)
    .unwrap();
    // alice proposes to add charlie
    let (_, reference) = alice_group
        .propose_add_member(provider, &alice_signer, charlie_key_package)
        .unwrap();

    assert_eq!(alice_group.proposal_store.proposals().count(), 1);
    // clearing the proposal by reference
    alice_group
        .remove_pending_proposal(reference.clone())
        .unwrap();
    assert!(alice_group.proposal_store.is_empty());

    // the proposal should not be stored anymore
    let err = alice_group.remove_pending_proposal(reference).unwrap_err();
    assert_eq!(err, MlsGroupStateError::PendingProposalNotFound);

    // the commit should have no proposal
    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(provider, &alice_signer)
        .unwrap();
    let msg = bob_group
        .process_message(
            provider,
            MlsMessageIn::from(commit)
                .try_into_protocol_message()
                .unwrap(),
        )
        .unwrap();
    match msg.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            // assert that no proposal was commited
            assert!(commit.add_proposals().next().is_none());
            assert!(commit.update_proposals().next().is_none());
            assert!(commit.remove_proposals().next().is_none());
            assert!(commit.psk_proposals().next().is_none());
            assert_eq!(alice_group.members().count(), 2);
        }
        _ => unreachable!("Expected a StagedCommit."),
    }
}
//
// Test that the builder pattern accurately configures the new group.
#[apply(ciphersuites_and_providers)]
fn group_context_extensions_proposal(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::builder()
        .build(provider, &alice_signer, alice_credential_with_key)
        .expect("error creating group using builder");

    // No required capabilities, so no specifically required extensions.
    assert!(alice_group
        .group()
        .context()
        .extensions()
        .required_capabilities()
        .is_none());

    let new_extensions = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[ExtensionType::RequiredCapabilities], &[], &[]),
    ));

    let new_extensions_2 = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[ExtensionType::RatchetTree], &[], &[]),
    ));

    alice_group
        .propose_group_context_extensions(provider, new_extensions.clone(), &alice_signer)
        .expect("failed to build group context extensions proposal");

    assert_eq!(alice_group.pending_proposals().count(), 1);

    alice_group
        .commit_to_pending_proposals(provider, &alice_signer)
        .expect("failed to commit to pending proposals");

    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    let required_capabilities = alice_group
        .group()
        .context()
        .extensions()
        .required_capabilities()
        .expect("couldn't get required_capabilities");

    // has required_capabilities as required capability
    assert!(required_capabilities.extension_types() == [ExtensionType::RequiredCapabilities]);

    // === committing to two group context extensions should fail

    alice_group
        .propose_group_context_extensions(provider, new_extensions, &alice_signer)
        .expect("failed to build group context extensions proposal");

    // the proposals need to be different or they will be deduplicated
    alice_group
        .propose_group_context_extensions(provider, new_extensions_2, &alice_signer)
        .expect("failed to build group context extensions proposal");

    assert_eq!(alice_group.pending_proposals().count(), 2);

    alice_group
        .commit_to_pending_proposals(provider, &alice_signer)
        .expect_err(
            "expected error when committing to multiple group context extensions proposals",
        );

    // === can't update required required_capabilities to extensions that existing group members
    //       are not capable of

    // contains unsupported extension
    let new_extensions = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf042)], &[], &[]),
    ));

    alice_group
        .propose_group_context_extensions(provider, new_extensions, &alice_signer)
        .expect_err("expected an error building GCE proposal with bad required_capabilities");

    // TODO: we need to test that processing a commit with multiple group context extensions
    //       proposal also fails. however, we can't generate this commit, because our functions for
    //       constructing commits does not permit it. See #1476
}

// Test that the builder pattern accurately configures the new group.
#[apply(ciphersuites_and_providers)]
fn builder_pattern(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);

    // Variables for the MlsGroup configuration
    let test_group_id = GroupId::from_slice(b"Test Group");
    let test_lifetime = Lifetime::new(3600);
    let test_wire_format_policy = PURE_CIPHERTEXT_WIRE_FORMAT_POLICY;
    let test_padding_size = 100;
    let test_external_senders = Extension::ExternalSenders(vec![ExternalSender::new(
        alice_credential_with_key.signature_key.clone(),
        alice_credential_with_key.credential.clone(),
    )]);
    let test_required_capabilities = Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xff00)], &[], &[]),
    );
    let test_gc_extensions = Extensions::from_vec(vec![
        test_external_senders.clone(),
        test_required_capabilities.clone(),
    ])
    .expect("error creating group context extensions");

    let test_crypto_config = CryptoConfig::with_default_version(ciphersuite);
    let test_sender_ratchet_config = SenderRatchetConfiguration::new(10, 2000);
    let test_max_past_epochs = 10;
    let test_number_of_resumption_psks = 5;
    let test_capabilities = Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::Unknown(0xff00)]),
        None,
        None,
    );
    let test_leaf_extensions = Extensions::single(Extension::Unknown(
        0xff00,
        UnknownExtension(vec![0x00, 0x01, 0x02]),
    ));

    // === Alice creates a group ===
    let alice_group = MlsGroup::builder()
        .with_group_id(test_group_id.clone())
        .padding_size(test_padding_size)
        .sender_ratchet_configuration(test_sender_ratchet_config.clone())
        .with_group_context_extensions(test_gc_extensions.clone())
        .expect("error adding group context extension to builder")
        .crypto_config(test_crypto_config)
        .with_wire_format_policy(test_wire_format_policy)
        .lifetime(test_lifetime)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(test_max_past_epochs)
        .number_of_resumption_psks(test_number_of_resumption_psks)
        .with_leaf_node_extensions(test_leaf_extensions.clone())
        .expect("error adding leaf node extension to builder")
        .with_capabilities(test_capabilities.clone())
        .build(provider, &alice_signer, alice_credential_with_key)
        .expect("error creating group using builder");

    // Check that the group was created with the correct configuration

    // first the config
    let group_config = alice_group.configuration();
    assert_eq!(group_config.padding_size(), test_padding_size);
    assert_eq!(
        group_config.sender_ratchet_configuration(),
        &test_sender_ratchet_config
    );
    assert_eq!(group_config.wire_format_policy(), test_wire_format_policy);
    assert!(group_config.use_ratchet_tree_extension);
    assert_eq!(group_config.max_past_epochs, test_max_past_epochs);
    assert_eq!(
        group_config.number_of_resumption_psks,
        test_number_of_resumption_psks
    );

    // and the rest of the parameters
    let group_context = alice_group.export_group_context();
    assert_eq!(alice_group.group_id(), &test_group_id);
    let external_senders = group_context
        .extensions()
        .external_senders()
        .expect("error getting external senders")
        .to_vec();
    assert_eq!(
        Extension::ExternalSenders(external_senders),
        test_external_senders
    );
    let crypto_config = CryptoConfig {
        ciphersuite,
        version: group_context.protocol_version(),
    };
    assert_eq!(crypto_config, test_crypto_config);
    let extensions = group_context.extensions();
    assert_eq!(extensions, &test_gc_extensions);
    let lifetime = alice_group
        .own_leaf()
        .expect("error getting own leaf")
        .life_time()
        .expect("leaf doesn't have a lifetime");
    assert_eq!(lifetime, &test_lifetime);
    let own_leaf = alice_group.own_leaf_node().expect("can't find own leaf");
    let capabilities = own_leaf.capabilities();
    assert_eq!(capabilities, &test_capabilities);
    let leaf_extensions = own_leaf.extensions();
    assert_eq!(leaf_extensions, &test_leaf_extensions);

    // Make sure that building with an invalid leaf node extension fails
    let invalid_leaf_extensions =
        Extensions::single(Extension::ApplicationId(ApplicationIdExtension::new(&[
            0x00, 0x01, 0x02,
        ])));

    let builder_err = MlsGroup::builder()
        .with_leaf_node_extensions(invalid_leaf_extensions)
        .expect_err("successfully built group with invalid leaf extensions");
    assert_eq!(builder_err, InvalidExtensionError::IllegalInLeafNodes);
}

// Test that unknown group context and leaf node extensions can be used in groups
#[apply(ciphersuites_and_providers)]
fn unknown_extensions(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);

    let unknown_gc_extension = Extension::Unknown(0xff00, UnknownExtension(vec![0, 1, 2, 3]));
    let unknown_leaf_extension = Extension::Unknown(0xff01, UnknownExtension(vec![4, 5, 6, 7]));
    let unknown_kp_extension = Extension::Unknown(0xff02, UnknownExtension(vec![8, 9, 10, 11]));
    let required_extensions = &[
        ExtensionType::Unknown(0xff00),
        ExtensionType::Unknown(0xff01),
    ];
    let required_capabilities =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&[], &[], &[]));
    let capabilities = Capabilities::new(None, None, Some(required_extensions), None, None);
    let test_gc_extensions = Extensions::from_vec(vec![
        unknown_gc_extension.clone(),
        required_capabilities.clone(),
    ])
    .expect("error creating group context extensions");
    let test_kp_extensions = Extensions::single(unknown_kp_extension.clone());

    // === Alice creates a group ===
    let config = CryptoConfig {
        ciphersuite,
        version: crate::versions::ProtocolVersion::default(),
    };
    let mut alice_group = MlsGroup::builder()
        .crypto_config(config)
        .with_capabilities(capabilities.clone())
        .with_leaf_node_extensions(Extensions::single(unknown_leaf_extension.clone()))
        .expect("error adding unknown leaf extension to builder")
        .with_group_context_extensions(test_gc_extensions.clone())
        .expect("error adding unknown extension to builder")
        .build(provider, &alice_signer, alice_credential_with_key)
        .expect("error creating group using builder");

    // Check that everything was added successfully
    let group_context = alice_group.export_group_context();
    assert_eq!(group_context.extensions(), &test_gc_extensions);
    let leaf_node = alice_group.own_leaf().expect("error getting own leaf");
    assert_eq!(
        leaf_node.extensions(),
        &Extensions::single(unknown_leaf_extension)
    );

    // Now let's add Bob to the group and make sure that he joins the group successfully

    // === Alice adds Bob ===
    let (bob_credential_with_key, _bob_kpb, bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);

    // Generate a KP that supports the unknown extensions
    let bob_key_package = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .key_package_extensions(test_kp_extensions.clone())
        .build(config, provider, &bob_signer, bob_credential_with_key)
        .expect("error building key package");

    assert_eq!(
        bob_key_package.extensions(),
        &Extensions::single(unknown_kp_extension)
    );

    // alice adds bob and bob processes the welcome to ensure that the unknown
    // extensions are processed correctly
    let (_, welcome, _) = alice_group
        .add_members(provider, &alice_signer, &[bob_key_package.clone()])
        .unwrap();
    alice_group.merge_pending_commit(provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let _bob_group = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(provider)
    .expect("Error creating group from staged join");
}

#[apply(ciphersuites_and_providers)]
fn join_multiple_groups_last_resort_extension(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) {
    // start with alice, bob, charlie, common config items
    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("alice", ciphersuite, provider);
    let (bob_credential_with_key, _bob_kpb, bob_signer, _bob_pk) =
        setup_client("bob", ciphersuite, provider);
    let (charlie_credential_with_key, _charlie_kpb, charlie_signer, _charlie_pk) =
        setup_client("charlie", ciphersuite, provider);
    let config = CryptoConfig {
        ciphersuite,
        version: crate::versions::ProtocolVersion::default(),
    };
    let leaf_capabilities =
        Capabilities::new(None, None, Some(&[ExtensionType::LastResort]), None, None);
    let keypkg_extensions = Extensions::single(Extension::LastResort(LastResortExtension::new()));
    // alice creates MlsGroup
    let mut alice_group = MlsGroup::builder()
        .crypto_config(config)
        .use_ratchet_tree_extension(true)
        .build(provider, &alice_signer, alice_credential_with_key)
        .expect("error creating group for alice using builder");
    // bob creates MlsGroup
    let mut bob_group = MlsGroup::builder()
        .crypto_config(config)
        .use_ratchet_tree_extension(true)
        .build(provider, &bob_signer, bob_credential_with_key)
        .expect("error creating group for bob using builder");
    // charlie creates KeyPackage
    let charlie_keypkg = KeyPackage::builder()
        .leaf_node_capabilities(leaf_capabilities)
        .key_package_extensions(keypkg_extensions.clone())
        .build(
            config,
            provider,
            &charlie_signer,
            charlie_credential_with_key,
        )
        .expect("error building key package for charlie");
    // alice calls add_members(...) with charlie's KeyPackage; produces Commit and Welcome messages
    let (_, alice_welcome, _) = alice_group
        .add_members(provider, &alice_signer, &[charlie_keypkg.clone()])
        .expect("error adding charlie to alice's group");
    alice_group
        .merge_pending_commit(provider)
        .expect("error merging commit for alice's group");
    // charlie calls new_from_welcome(...) with alice's Welcome message; SHOULD SUCCEED

    let alice_welcome: MlsMessageIn = alice_welcome.into();
    let alice_welcome = alice_welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        alice_welcome,
        None,
    )
    .expect("error creating staged join from welcome")
    .into_group(provider)
    .expect("error creating group from staged join");

    // bob calls add_members(...) with charlie's KeyPackage; produces Commit and Welcome messages
    let (_, bob_welcome, _) = bob_group
        .add_members(provider, &bob_signer, &[charlie_keypkg.clone()])
        .expect("error adding charlie to bob's group");
    bob_group
        .merge_pending_commit(provider)
        .expect("error merging commit for bob's group");
    // charlie calls new_from_welcome(...) with bob's Welcome message; SHOULD SUCCEED
    let bob_welcome: MlsMessageIn = bob_welcome.into();
    let bob_welcome = bob_welcome
        .into_welcome()
        .expect("expected message to be a welcome");
    StagedWelcome::new_from_welcome(provider, &MlsGroupJoinConfig::default(), bob_welcome, None)
        .expect("error creating staged join from welcome")
        .into_group(provider)
        .expect("error creating group from staged join");
    // done :-)
}
