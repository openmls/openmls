use core_group::test_core_group::setup_client;
use openmls_test::openmls_test;
use openmls_traits::OpenMlsProvider as _;
use tls_codec::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafNodeIndex,
    extensions::errors::InvalidExtensionError,
    framing::*,
    group::{errors::*, *},
    key_packages::*,
    messages::proposals::*,
    test_utils::{
        frankenstein::{self, FrankenMlsMessage},
        test_framework::{
            errors::ClientError, noop_authentication_service, ActionType::Commit, CodecUse,
            MlsGroupTestSetup,
        },
    },
    tree::sender_ratchet::SenderRatchetConfiguration,
    treesync::node::leaf_node::Capabilities,
};

#[openmls_test]
fn test_mls_group_persistence<Provider: OpenMlsProvider>() {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupCreateConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_config,
        group_id.clone(),
        alice_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    let alice_group_deserialized = MlsGroup::load(provider.storage(), &group_id)
        .expect("Could not deserialize MlsGroup: error")
        .expect("Could not deserialize MlsGroup: doesn't exist");

    assert_eq!(
        (
            alice_group.export_ratchet_tree(),
            alice_group
                .export_secret(provider, "test", &[], 32)
                .unwrap()
        ),
        (
            alice_group_deserialized.export_ratchet_tree(),
            alice_group_deserialized
                .export_secret(provider, "test", &[], 32)
                .unwrap()
        )
    );
}

// This tests if the remover is correctly passed to the callback when one member
// issues a RemoveProposal and another members issues the next Commit.
#[openmls_test]
fn remover() {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential, bob_kpb, bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);
    let (_charlie_credential, charlie_kpb, charlie_signer, _charlie_pk) =
        setup_client("Charly", ciphersuite, provider);

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
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
            charlie_group
                .store_pending_proposal(provider.storage(), *staged_proposal.clone())
                .unwrap();
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

#[openmls_test]
fn export_secret() {
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
            .export_secret(provider, "test1", &[], ciphersuite.hash_length())
            .expect("An unexpected error occurred.")
            != alice_group
                .export_secret(provider, "test2", &[], ciphersuite.hash_length())
                .expect("An unexpected error occurred.")
    );
    assert!(
        alice_group
            .export_secret(provider, "test", &[0u8], ciphersuite.hash_length())
            .expect("An unexpected error occurred.")
            != alice_group
                .export_secret(provider, "test", &[1u8], ciphersuite.hash_length())
                .expect("An unexpected error occurred.")
    )
}

#[openmls_test]
fn staged_join() {
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
            .export_secret(provider, "test", &[], ciphersuite.hash_length())
            .expect("An unexpected error occurred."),
        bob_group
            .export_secret(provider, "test", &[], ciphersuite.hash_length())
            .expect("An unexpected error occurred.")
    );
}

#[openmls_test]
fn test_invalid_plaintext() {
    // Some basic setup functions for the MlsGroup.
    let mls_group_create_config = MlsGroupCreateConfig::test_default(ciphersuite);

    let number_of_clients = 20;
    let setup = MlsGroupTestSetup::<Provider>::new(
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
                client.provider.crypto(),
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

#[openmls_test]
fn test_verify_staged_commit_credentials(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
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
        alice_group
            .store_pending_proposal(provider.storage(), *staged_proposal)
            .unwrap();
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
        bob_group
            .export_secret(provider, "test", &[], ciphersuite.hash_length())
            .unwrap(),
        alice_group
            .export_secret(provider, "test", &[], ciphersuite.hash_length())
            .unwrap()
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
            bob_group
                .export_secret(provider, "test", &[], ciphersuite.hash_length())
                .unwrap(),
            alice_group
                .export_secret(provider, "test", &[], ciphersuite.hash_length())
                .unwrap()
        );
    } else {
        unreachable!()
    }

    // neither should have pending commits after merging and processing
    assert!(bob_group.pending_commit().is_none());
    assert!(alice_group.pending_commit().is_none());
}

#[openmls_test]
fn test_commit_with_update_path_leaf_node(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
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
        alice_group
            .store_pending_proposal(provider.storage(), *staged_proposal)
            .unwrap();
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
        bob_group
            .export_secret(provider, "test", &[], ciphersuite.hash_length())
            .unwrap(),
        alice_group
            .export_secret(provider, "test", &[], ciphersuite.hash_length())
            .unwrap()
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
            bob_group
                .export_secret(provider, "test", &[], ciphersuite.hash_length())
                .unwrap(),
            alice_group
                .export_secret(provider, "test", &[], ciphersuite.hash_length())
                .unwrap()
        );
    } else {
        unreachable!()
    }

    // neither should have pending commits after merging and processing
    assert!(bob_group.pending_commit().is_none());
    assert!(alice_group.pending_commit().is_none());
}

#[openmls_test]
fn test_pending_commit_logic(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
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
        alice_group
            .store_pending_proposal(provider.storage(), *staged_proposal)
            .unwrap();
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
    assert!(matches!(
        error,
        ProposeAddMemberError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
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
    assert!(matches!(
        error,
        ProposeRemoveMemberError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
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
    alice_group
        .clear_pending_commit(provider.storage())
        .unwrap();
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
        bob_group
            .export_secret(provider, "test", &[], ciphersuite.hash_length())
            .unwrap(),
        alice_group
            .export_secret(provider, "test", &[], ciphersuite.hash_length())
            .unwrap()
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
#[openmls_test]
fn key_package_deletion() {
    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_kpb, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);
    let bob_key_package = bob_kpb.key_package();

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
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

    use openmls_traits::storage::StorageProvider;

    // TEST: The key package must be gone from the key store.
    let result: Option<KeyPackageBundle> = provider
        .storage()
        .key_package(&bob_key_package.hash_ref(provider.crypto()).unwrap())
        .unwrap();
    assert!(
        result.is_none(),
        "The key package is still in the key store after creating a new group from it."
    );
}

#[openmls_test]
fn remove_prosposal_by_ref(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
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
        .ciphersuite(ciphersuite)
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
        .remove_pending_proposal(provider.storage(), reference.clone())
        .unwrap();
    assert!(alice_group.proposal_store.is_empty());

    // the proposal should not be stored anymore
    let err = alice_group
        .remove_pending_proposal(provider.storage(), reference)
        .unwrap_err();
    assert!(matches!(err, MlsGroupStateError::PendingProposalNotFound));

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

mod group_context_extensions {
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::types::Ciphersuite;

    use self::mls_group::hash_ref::ProposalRef;

    use super::*;
    use crate::{
        credentials::CredentialWithKey, key_packages::errors::KeyPackageVerifyError,
        messages::group_info::GroupInfo,
    };

    struct MemberState<Provider> {
        party: PartyState<Provider>,
        group: MlsGroup,
    }

    #[allow(dead_code)]
    struct PartyState<Provider> {
        provider: Provider,
        credential_with_key: CredentialWithKey,
        key_package_bundle: KeyPackageBundle,
        signer: SignatureKeyPair,
        sig_pk: OpenMlsSignaturePublicKey,
        name: &'static str,
    }

    impl<Provider: crate::storage::OpenMlsProvider + Default> PartyState<Provider> {
        fn generate(name: &'static str, ciphersuite: Ciphersuite) -> Self {
            let provider = Provider::default();
            let (credential_with_key, key_package_bundle, signer, sig_pk) =
                setup_client(name, ciphersuite, &provider);

            PartyState {
                provider,
                name,
                credential_with_key,
                key_package_bundle,
                signer,
                sig_pk,
            }
        }

        fn key_package<F: FnOnce(KeyPackageBuilder) -> KeyPackageBuilder>(
            &self,
            ciphersuite: Ciphersuite,
            f: F,
        ) -> KeyPackageBundle {
            f(KeyPackage::builder())
                .build(
                    ciphersuite,
                    &self.provider,
                    &self.signer,
                    self.credential_with_key.clone(),
                )
                .unwrap_or_else(|err| panic!("failed to build key package at {}: {err}", self.name))
        }
    }

    struct TestState<Provider> {
        alice: MemberState<Provider>,
        bob: MemberState<Provider>,
    }

    /*
     * sets up a group with two parties alice and bob, where alice has capabilities for unknown
     * extensions 0xf001 and  0xf002, and bob has capabilities for extension 0xf001, 0xf002 and
     * 0xf003.
     */
    fn setup<Provider: crate::storage::OpenMlsProvider + Default>(
        ciphersuite: Ciphersuite,
    ) -> TestState<Provider> {
        let alice_party = PartyState::generate("alice", ciphersuite);
        let bob_party = PartyState::generate("bob", ciphersuite);

        // === Alice creates a group ===
        let alice_group = MlsGroup::builder()
            .ciphersuite(ciphersuite)
            .with_wire_format_policy(WireFormatPolicy::new(
                OutgoingWireFormatPolicy::AlwaysPlaintext,
                IncomingWireFormatPolicy::Mixed,
            ))
            .with_capabilities(
                Capabilities::builder()
                    .extensions(vec![
                        ExtensionType::Unknown(0xf001),
                        ExtensionType::Unknown(0xf002),
                    ])
                    .build(),
            )
            .build(
                &alice_party.provider,
                &alice_party.signer,
                alice_party.credential_with_key.clone(),
            )
            .expect("error creating group using builder");

        let mut alice = MemberState {
            party: alice_party,
            group: alice_group,
        };

        // === Alice adds Bob ===
        let bob_key_package = bob_party.key_package(ciphersuite, |builder| {
            builder.leaf_node_capabilities(
                Capabilities::builder()
                    .extensions(vec![
                        ExtensionType::Unknown(0xf001),
                        ExtensionType::Unknown(0xf002),
                        ExtensionType::Unknown(0xf003),
                    ])
                    .build(),
            )
        });

        alice.propose_add_member(bob_key_package.key_package());
        let (_, Some(welcome), _) = alice.commit_and_merge_pending() else {
            panic!("expected receiving a welcome")
        };

        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome
            .into_welcome()
            .expect("expected message to be a welcome");

        let bob_group = StagedWelcome::new_from_welcome(
            &bob_party.provider,
            alice.group.configuration(),
            welcome,
            Some(alice.group.export_ratchet_tree().into()),
        )
        .expect("Error creating staged join from Welcome")
        .into_group(&bob_party.provider)
        .expect("Error creating group from staged join");

        TestState {
            alice,
            bob: MemberState {
                party: bob_party,
                group: bob_group,
            },
        }
    }

    impl<Provider: crate::storage::OpenMlsProvider> MemberState<Provider> {
        fn propose_group_context_extensions(
            &mut self,
            extensions: Extensions,
        ) -> (MlsMessageOut, ProposalRef) {
            self.group
                .propose_group_context_extensions(
                    &self.party.provider,
                    extensions,
                    &self.party.signer,
                )
                .unwrap_or_else(|err| panic!("couldn't propose GCE at {}: {err}", self.party.name))
        }

        fn propose_add_member(&mut self, key_package: &KeyPackage) -> (MlsMessageOut, ProposalRef) {
            self.group
                .propose_add_member(&self.party.provider, &self.party.signer, key_package)
                .unwrap_or_else(|err| {
                    panic!("failed to propose member at {}: {err}", self.party.name)
                })
        }

        fn process_and_merge_commit(&mut self, msg: MlsMessageIn) {
            let msg = msg.into_protocol_message().unwrap();

            let processed_msg = self
                .group
                .process_message(&self.party.provider, msg)
                .unwrap_or_else(|err| {
                    panic!("error processing message at {}: {err}", self.party.name)
                });

            match processed_msg.into_content() {
                ProcessedMessageContent::StagedCommitMessage(staged_commit) => self
                    .group
                    .merge_staged_commit(&self.party.provider, *staged_commit)
                    .unwrap_or_else(|err| {
                        panic!("error merging staged commit at {}: {err}", self.party.name)
                    }),

                other => {
                    panic!(
                        "expected a commit message at {}, got {:?}",
                        self.party.name, other
                    )
                }
            }
        }

        fn process_and_store_proposal(&mut self, msg: MlsMessageIn) -> ProposalRef {
            let msg = msg.into_protocol_message().unwrap();

            let processed_msg = self
                .group
                .process_message(&self.party.provider, msg)
                .unwrap_or_else(|err| {
                    panic!("error processing message at {}: {err}", self.party.name)
                });

            match processed_msg.into_content() {
                ProcessedMessageContent::ProposalMessage(proposal) => {
                    let reference = proposal.proposal_reference();

                    self.group
                        .store_pending_proposal(self.party.provider.storage(), *proposal)
                        .unwrap_or_else(|err| {
                            panic!("error storing proposal at {}: {err}", self.party.name)
                        });

                    reference
                }
                other => {
                    panic!(
                        "expected a proposal message at {}, got {:?}",
                        self.party.name, other
                    )
                }
            }
        }

        fn fail_processing(
            &mut self,
            msg: MlsMessageIn,
        ) -> ProcessMessageError<Provider::StorageError> {
            let msg = msg.into_protocol_message().unwrap();
            let err_msg = format!(
                "expected an error when processing message at {}",
                self.party.name
            );

            self.group
                .process_message(&self.party.provider, msg)
                .expect_err(&err_msg)
        }

        fn commit_to_pending_proposals(
            &mut self,
        ) -> (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>) {
            self.group
                .commit_to_pending_proposals(&self.party.provider, &self.party.signer)
                .unwrap_or_else(|err| {
                    panic!(
                        "{} couldn't commit pending proposal: {err}",
                        self.party.name
                    )
                })
        }

        fn merge_pending_commit(&mut self) {
            self.group
                .merge_pending_commit(&self.party.provider)
                .unwrap_or_else(|err| panic!("{} couldn't merge commit: {err}", self.party.name));
        }

        fn commit_and_merge_pending(
            &mut self,
        ) -> (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>) {
            let commit_out = self.commit_to_pending_proposals();
            self.merge_pending_commit();
            commit_out
        }
    }

    // Test that the happy case of group context extensions works
    // 1. set up group
    // 2. alice sets gce, commits
    #[openmls_test]
    fn happy_case() {
        let TestState { mut alice, mut bob } = setup::<Provider>(ciphersuite);

        let (proposal, _) = alice.propose_group_context_extensions(Extensions::single(
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::Unknown(0xf001)],
                &[],
                &[],
            )),
        ));

        let (commit, _, _) = alice.commit_and_merge_pending();

        bob.process_and_store_proposal(proposal.into());
        bob.process_and_merge_commit(commit.into());

        let (proposal, _) = bob.propose_group_context_extensions(Extensions::single(
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[
                    ExtensionType::Unknown(0xf001),
                    ExtensionType::Unknown(0xf002),
                ],
                &[],
                &[],
            )),
        ));

        let (commit, _, _) = bob.commit_and_merge_pending();

        alice.process_and_store_proposal(proposal.into());
        alice.process_and_merge_commit(commit.into());
    }

    /// This tests makes sure that validation check 103 is performed:
    ///
    ///   Verify that the LeafNode is compatible with the group's parameters.
    ///   If the GroupContext has a required_capabilities extension, then the
    ///   required extensions, proposals, and credential types MUST be listed
    ///   in the LeafNode's capabilities field.
    ///
    /// So far, we only test whether the check is done for extensions.
    #[openmls_test]
    fn fail_insufficient_capabilities_add_valno103() {
        let TestState { mut alice, mut bob } = setup::<Provider>(ciphersuite);

        let (gce_req_cap_proposal, _) = alice.propose_group_context_extensions(Extensions::single(
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::Unknown(0xf002)],
                &[],
                &[],
            )),
        ));

        let (gce_req_cap_commit, _, _) = alice.commit_and_merge_pending();

        bob.process_and_store_proposal(gce_req_cap_proposal.clone().into());
        bob.process_and_merge_commit(gce_req_cap_commit.clone().into());

        // extract values we need later
        let frankenstein::FrankenMlsMessage {
            version,
            body:
                frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                    content:
                        frankenstein::FrankenFramedContent {
                            group_id,
                            epoch: gce_commit_epoch,
                            sender,
                            authenticated_data,
                            ..
                        },
                    ..
                }),
        } = frankenstein::FrankenMlsMessage::from(gce_req_cap_commit)
        else {
            unreachable!()
        };

        let charlie = PartyState::<Provider>::generate("charlie", ciphersuite);
        let charlie_kpb = charlie.key_package(ciphersuite, |builder| {
            builder.leaf_node_capabilities(
                Capabilities::builder()
                    .extensions(vec![ExtensionType::Unknown(0xf001)])
                    .build(),
            )
        });

        let commit_content = frankenstein::FrankenFramedContent {
            body: frankenstein::FrankenFramedContentBody::Commit(frankenstein::FrankenCommit {
                proposals: vec![frankenstein::FrankenProposalOrRef::Proposal(
                    frankenstein::FrankenProposal::Add(frankenstein::FrankenAddProposal {
                        key_package: charlie_kpb.key_package.into(),
                    }),
                )],
                path: None,
            }),
            group_id,
            epoch: gce_commit_epoch + 1,
            sender,
            authenticated_data,
        };

        let group_context = alice.group.export_group_context().clone();

        let bob_group_context = bob.group.export_group_context();
        assert_eq!(
            bob_group_context.confirmed_transcript_hash(),
            group_context.confirmed_transcript_hash()
        );

        let secrets = alice.group.group.message_secrets();
        let membership_key = secrets.membership_key().as_slice();

        let franken_commit = frankenstein::FrankenMlsMessage {
            version,
            body: frankenstein::FrankenMlsMessageBody::PublicMessage(
                frankenstein::FrankenPublicMessage::auth(
                    &alice.party.provider,
                    ciphersuite,
                    &alice.party.signer,
                    commit_content,
                    Some(&group_context.into()),
                    Some(membership_key),
                    // this is a dummy confirmation_tag:
                    Some(vec![0u8; 32].into()),
                ),
            ),
        };

        let fake_commit = MlsMessageIn::tls_deserialize(
            &mut franken_commit.tls_serialize_detached().unwrap().as_slice(),
        )
        .unwrap();

        // Note: If this starts failing, the order in which validation is checked may have changed and we
        // fail on the fact that the confirmation tag is wrong. in that case, either the check has to be
        // disabled, or the frankenstein framework needs code to properly commpute it.
        let err = bob.fail_processing(fake_commit);
        assert!(
            matches!(
                err,
                ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                    ProposalValidationError::InsufficientCapabilities
                ))
            ),
            "got wrong error: {err:#?}"
        );
    }

    #[openmls_test]
    fn self_update_happy_case() {
        let TestState { mut alice, mut bob } = setup::<Provider>(ciphersuite);

        let (update_prop, _) = bob
            .group
            .propose_self_update(
                &bob.party.provider,
                &bob.party.signer,
                bob.group.own_leaf_node().cloned(),
            )
            .unwrap();
        alice.process_and_store_proposal(update_prop.into());
        let (commit, _, _) = alice.commit_and_merge_pending();
        bob.process_and_merge_commit(commit.into())
    }

    // This test does the same as self_update_happy_case, but does not use MemberState, so we can
    // can exactly see which calls to OpenMLS are done
    #[openmls_test]
    fn self_update_happy_case_simple() {
        let alice_party = PartyState::<Provider>::generate("alice", ciphersuite);
        let bob_party = PartyState::<Provider>::generate("bob", ciphersuite);

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::builder()
            .ciphersuite(ciphersuite)
            .with_wire_format_policy(WireFormatPolicy::new(
                OutgoingWireFormatPolicy::AlwaysPlaintext,
                IncomingWireFormatPolicy::Mixed,
            ))
            .build(
                &alice_party.provider,
                &alice_party.signer,
                alice_party.credential_with_key.clone(),
            )
            .expect("error creating group using builder");

        // === Alice adds Bob ===
        let bob_key_package = bob_party.key_package(ciphersuite, |builder| builder);

        alice_group
            .propose_add_member(
                &alice_party.provider,
                &alice_party.signer,
                bob_key_package.key_package(),
            )
            .unwrap();

        let (_, Some(welcome), _) = alice_group
            .commit_to_pending_proposals(&alice_party.provider, &alice_party.signer)
            .unwrap()
        else {
            panic!("expected receiving a welcome")
        };

        alice_group
            .merge_pending_commit(&alice_party.provider)
            .unwrap();

        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome
            .into_welcome()
            .expect("expected message to be a welcome");

        let mut bob_group = StagedWelcome::new_from_welcome(
            &bob_party.provider,
            alice_group.configuration(),
            welcome,
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("Error creating staged join from Welcome")
        .into_group(&bob_party.provider)
        .expect("Error creating group from staged join");

        let (update_proposal_msg, _) = bob_group
            .propose_self_update(
                &bob_party.provider,
                &bob_party.signer,
                bob_group.own_leaf_node().cloned(),
            )
            .unwrap();

        let ProcessedMessageContent::ProposalMessage(update_proposal) = alice_group
            .process_message(
                &alice_party.provider,
                update_proposal_msg.clone().into_protocol_message().unwrap(),
            )
            .unwrap()
            .into_content()
        else {
            panic!("expected a proposal, got {update_proposal_msg:?}");
        };
        alice_group
            .store_pending_proposal(alice_party.provider.storage(), *update_proposal)
            .unwrap();

        let (commit_msg, _, _) = alice_group
            .commit_to_pending_proposals(&alice_party.provider, &alice_party.signer)
            .unwrap();

        bob_group
            .process_message(
                &bob_party.provider,
                commit_msg.into_protocol_message().unwrap(),
            )
            .unwrap();

        bob_group.merge_pending_commit(&bob_party.provider).unwrap()
    }

    // this currently doesn't work because of an issue with the conversion using the frankenstein
    // framework. I don't have time do debug this now.
    //
    // Test structure:
    // - (alice creates group, adds bob, bob accepts)
    //   - This is part of the setup function
    // - alice proposal GCE with required capabilities and commits
    // - bob adds the proposal and merges the commit
    // - bob proposes a self-update, but we tamper with it by removing
    //   an extension type from the capabilities. This makes it invalid.
    // - we craft a commit by alice, committing the invalid proposal
    //   - it can't be done by bob, because the sender of a commit
    //     containing an update proposal can not be the owner of the
    //     leaf node
    // - bob processes the invalid commit, which should give an InsufficientCapabilities error
    #[openmls_test]
    fn fail_insufficient_capabilities_update_valno103() {
        let TestState { mut alice, mut bob } = setup::<Provider>(ciphersuite);

        let (gce_req_cap_proposal, _) = alice.propose_group_context_extensions(Extensions::single(
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::Unknown(0xf002)],
                &[],
                &[],
            )),
        ));

        let (gce_req_cap_commit, _, _) = alice.commit_and_merge_pending();

        bob.process_and_store_proposal(gce_req_cap_proposal.clone().into());
        bob.process_and_merge_commit(gce_req_cap_commit.clone().into());

        let (update_prop, _) = bob
            .group
            .propose_self_update(
                &bob.party.provider,
                &bob.party.signer,
                bob.group.own_leaf_node().cloned(),
            )
            .unwrap();

        let frankenstein::FrankenMlsMessage {
            version,
            body:
                frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                    content:
                        frankenstein::FrankenFramedContent {
                            group_id,
                            epoch,
                            sender: bob_sender,
                            authenticated_data,
                            body:
                                frankenstein::FrankenFramedContentBody::Proposal(
                                    frankenstein::FrankenProposal::Update(
                                        frankenstein::FrankenUpdateProposal {
                                            leaf_node: mut bob_franken_leaf_node,
                                        },
                                    ),
                                ),
                        },
                    ..
                }),
        } = frankenstein::FrankenMlsMessage::from(update_prop.clone())
        else {
            unreachable!()
        };

        assert_eq!(bob_sender, frankenstein::FrankenSender::Member(1));
        let alice_sender = frankenstein::FrankenSender::Member(0);

        // Remove the extension type from the capabilities that is part of required capabilities
        assert_eq!(bob_franken_leaf_node.capabilities.extensions[1], 0xf002);
        bob_franken_leaf_node.capabilities.extensions.remove(1);

        // make it pass validation again
        bob_franken_leaf_node.leaf_node_source = frankenstein::FrankenLeafNodeSource::Update;
        bob_franken_leaf_node.resign(
            Some(frankenstein::FrankenTreePosition {
                group_id: bob.group.group_id().as_slice().to_vec().into(),
                leaf_index: bob.group.own_leaf_index().u32(),
            }),
            &bob.party.signer,
        );

        // Note: the sender of an Update proposal may not be the same as the commiter to the
        // proposal. That's why we only make sure that nobody accepts an invalid update proposal.

        // build invalid proposal content
        let proposal_content = frankenstein::FrankenFramedContent {
            group_id: group_id.clone(),
            epoch,
            sender: bob_sender.clone(),
            authenticated_data: authenticated_data.clone(),
            body: frankenstein::FrankenFramedContentBody::Proposal(
                frankenstein::FrankenProposal::Update(frankenstein::FrankenUpdateProposal {
                    leaf_node: bob_franken_leaf_node,
                }),
            ),
        };

        // prepare data needed for proposal
        let group_context = alice.group.export_group_context().clone();

        let bob_group_context = bob.group.export_group_context();
        assert_eq!(
            bob_group_context.confirmed_transcript_hash(),
            group_context.confirmed_transcript_hash()
        );

        let secrets = bob.group.group.message_secrets();
        let membership_key = secrets.membership_key().as_slice();

        // build proposal
        let franken_proposal = frankenstein::FrankenPublicMessage::auth(
            &bob.party.provider,
            ciphersuite,
            &bob.party.signer,
            proposal_content,
            Some(&group_context.into()),
            Some(membership_key),
            // proposals don't have confirmation tags
            None,
        );

        let franken_proposal = frankenstein::FrankenMlsMessage {
            version,
            body: frankenstein::FrankenMlsMessageBody::PublicMessage(franken_proposal),
        };

        let fake_proposal = MlsMessageIn::tls_deserialize(
            &mut franken_proposal
                .tls_serialize_detached()
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        alice.process_and_store_proposal(fake_proposal.clone());

        bob.group
            .clear_pending_proposals(bob.party.provider.storage())
            .unwrap();
        let proposal_ref = bob.process_and_store_proposal(fake_proposal);

        let commit_content = frankenstein::FrankenFramedContent {
            group_id,
            epoch,
            sender: alice_sender,
            authenticated_data,
            body: frankenstein::FrankenFramedContentBody::Commit(frankenstein::FrankenCommit {
                proposals: vec![frankenstein::FrankenProposalOrRef::Reference(
                    proposal_ref.as_slice().to_vec().into(),
                )],
                path: None,
            }),
        };

        // prepare data needed for proposal
        let group_context = alice.group.export_group_context().clone();
        let secrets = alice.group.group.message_secrets();
        let membership_key = secrets.membership_key().as_slice();

        let franken_commit = frankenstein::FrankenMlsMessage {
            version,
            body: frankenstein::FrankenMlsMessageBody::PublicMessage(
                frankenstein::FrankenPublicMessage::auth(
                    &alice.party.provider,
                    ciphersuite,
                    &alice.party.signer,
                    commit_content,
                    Some(&group_context.into()),
                    Some(membership_key),
                    Some(vec![0; 32].into()),
                ),
            ),
        };

        let fake_commit = MlsMessageIn::tls_deserialize(
            &mut franken_commit.tls_serialize_detached().unwrap().as_slice(),
        )
        .unwrap();

        let err = bob.fail_processing(fake_commit);

        // Note: If this starts failing, the order in which validation is checked may have changed and we
        // fail on the fact that the confirmation tag is wrong. in that case, either the check has to be
        // disabled, or the frankenstein framework yet yet needs code to properly commpute it.
        assert!(
            matches!(
                err,
                ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                    ProposalValidationError::InsufficientCapabilities
                ))
            ),
            "expected a different error, got: {err} ({err:#?})"
        );
    }

    // This test doesn't belong here, but it's nice to have. It would be nice to factor it out, but
    // it relies on the testing functions.
    //
    // I suppose we need to talk about which test framework is the one we need.
    #[openmls_test]
    fn fail_key_package_version_valno201() {
        let TestState { mut alice, mut bob } = setup::<Provider>(ciphersuite);

        let charlie = PartyState::<Provider>::generate("charlie", ciphersuite);
        let charlie_key_package_bundle = charlie.key_package(ciphersuite, |b| b);
        let charlie_key_package = charlie_key_package_bundle.key_package();

        let (original_proposal, _) = alice.propose_add_member(charlie_key_package);

        alice
            .group
            .clear_pending_proposals(alice.party.provider.storage())
            .unwrap();

        let Ok(frankenstein::FrankenMlsMessage {
            version,
            body:
                frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                    content:
                        frankenstein::FrankenFramedContent {
                            group_id,
                            epoch,
                            sender,
                            authenticated_data,
                            body:
                                frankenstein::FrankenFramedContentBody::Proposal(
                                    frankenstein::FrankenProposal::Add(
                                        frankenstein::FrankenAddProposal { mut key_package },
                                    ),
                                ),
                        },
                    ..
                }),
        }) = frankenstein::FrankenMlsMessage::tls_deserialize(
            &mut original_proposal
                .tls_serialize_detached()
                .unwrap()
                .as_slice(),
        )
        else {
            panic!("proposal message has unexpected format: {original_proposal:#?}")
        };

        key_package.protocol_version = 2;
        key_package.resign(&charlie.signer);

        let group_context = alice.group.export_group_context();
        let membership_key = alice.group.group.message_secrets().membership_key();

        let franken_commit_message = frankenstein::FrankenMlsMessage {
            version,
            body: frankenstein::FrankenMlsMessageBody::PublicMessage(
                frankenstein::FrankenPublicMessage::auth(
                    &alice.party.provider,
                    ciphersuite,
                    &alice.party.signer,
                    frankenstein::FrankenFramedContent {
                        group_id,
                        epoch,
                        sender,
                        authenticated_data,
                        body: frankenstein::FrankenFramedContentBody::Commit(
                            frankenstein::FrankenCommit {
                                proposals: vec![frankenstein::FrankenProposalOrRef::Proposal(
                                    frankenstein::FrankenProposal::Add(
                                        frankenstein::FrankenAddProposal { key_package },
                                    ),
                                )],
                                path: None,
                            },
                        ),
                    },
                    Some(&group_context.clone().into()),
                    Some(membership_key.as_slice()),
                    // dummy value
                    Some(vec![0; 32].into()),
                ),
            ),
        };

        let fake_commit_message = MlsMessageIn::tls_deserialize(
            &mut franken_commit_message
                .tls_serialize_detached()
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let err = {
            let validation_skip_handle = crate::skip_validation::checks::confirmation_tag::handle();
            validation_skip_handle
                .with_disabled(|| bob.fail_processing(fake_commit_message.clone()))
        };

        assert!(matches!(
            err,
            ProcessMessageError::ValidationError(ValidationError::KeyPackageVerifyError(
                KeyPackageVerifyError::InvalidProtocolVersion
            ))
        ));
    }

    // This tests that a commit containing more than one GCE Proposals does not pass validation.
    #[openmls_test]
    fn fail_2_gce_proposals_1_commit_valno308() {
        let TestState { mut alice, mut bob } = setup::<Provider>(ciphersuite);

        // No required capabilities, so no specifically required extensions.
        assert!(alice
            .group
            .group()
            .context()
            .extensions()
            .required_capabilities()
            .is_none());

        let new_extensions = Extensions::single(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf001)], &[], &[]),
        ));

        let (proposal, _) = alice.propose_group_context_extensions(new_extensions.clone());
        bob.process_and_store_proposal(proposal.into());

        assert_eq!(alice.group.pending_proposals().count(), 1);

        let (commit, _, _) = alice.commit_to_pending_proposals();

        // we'll change the commit we feed to bob to include two GCE proposals
        let mut franken_commit = FrankenMlsMessage::tls_deserialize(
            &mut commit.tls_serialize_detached().unwrap().as_slice(),
        )
        .unwrap();

        // Craft a commit that has two GroupContextExtension proposals. This is forbidden by the RFC.
        // Change the commit before alice commits, so alice's state is still in the old epoch and we can
        // use her state to forge the macs and signatures
        match &mut franken_commit.body {
            frankenstein::FrankenMlsMessageBody::PublicMessage(msg) => {
                match &mut msg.content.body {
                    frankenstein::FrankenFramedContentBody::Commit(commit) => {
                        let second_gces = frankenstein::FrankenProposalOrRef::Proposal(
                            frankenstein::FrankenProposal::GroupContextExtensions(vec![
                                // ideally this should be some unknown extension, but it's tricky
                                // to get the payload set up correctly so we'll just go with this
                                frankenstein::FrankenExtension::LastResort,
                            ]),
                        );

                        commit.proposals.push(second_gces);
                    }
                    _ => unreachable!(),
                }

                let group_context = alice.group.export_group_context().clone();

                let bob_group_context = bob.group.export_group_context();
                assert_eq!(
                    bob_group_context.confirmed_transcript_hash(),
                    group_context.confirmed_transcript_hash()
                );

                let secrets = alice.group.group.message_secrets();
                let membership_key = secrets.membership_key().as_slice();

                *msg = frankenstein::FrankenPublicMessage::auth(
                    &alice.party.provider,
                    group_context.ciphersuite(),
                    &alice.party.signer,
                    msg.content.clone(),
                    Some(&group_context.into()),
                    Some(membership_key),
                    // this is a dummy confirmation_tag:
                    Some(vec![0u8; 32].into()),
                );
            }
            _ => unreachable!(),
        }

        let fake_commit = MlsMessageIn::tls_deserialize(
            &mut franken_commit.tls_serialize_detached().unwrap().as_slice(),
        )
        .unwrap();

        let err = {
            let validation_skip_handle = crate::skip_validation::checks::confirmation_tag::handle();
            validation_skip_handle.with_disabled(|| bob.fail_processing(fake_commit.clone()))
        };

        assert!(matches!(
            err,
            ProcessMessageError::InvalidCommit(
                StageCommitError::GroupContextExtensionsProposalValidationError(
                    GroupContextExtensionsProposalValidationError::TooManyGCEProposals
                )
            )
        ));
    }

    /// This test makes sure that a commit to a GCE proposal with required_capabilities that are
    /// not satisfied by all members' capabilities does not pass validation.
    ///
    // Test structure:
    // - (alice creates group, adds bob, bob accepts)
    //   - This is part of the setup function
    // - bob proposes updating the GC to have required_capabilities with extensions 0xf001
    //   - both alice and bob support this extension
    // - we modify the proposal and add 0xf003 - this is only supported by bob (see setup function)
    // - we craft a commit to the proposal, signed by bob
    // - alice processes the commit expecting an error, and the error should be that the GCE is
    //   invalid
    #[openmls_test]
    fn fail_unsupported_gces_add_valno1001() {
        let TestState { mut alice, mut bob }: TestState<Provider> = setup(ciphersuite);

        // No required capabilities, so no specifically required extensions.
        assert!(alice
            .group
            .group()
            .context()
            .extensions()
            .required_capabilities()
            .is_none());

        let new_extensions = Extensions::single(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf001)], &[], &[]),
        ));

        let (original_proposal, _) = bob.propose_group_context_extensions(new_extensions.clone());

        assert_eq!(bob.group.pending_proposals().count(), 1);
        bob.group
            .clear_pending_proposals(bob.party.provider.storage())
            .unwrap();

        let Ok(frankenstein::FrankenMlsMessage {
            version,
            body:
                frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                    content:
                        frankenstein::FrankenFramedContent {
                            group_id,
                            epoch,
                            sender: bob_sender,
                            authenticated_data,
                            body:
                                frankenstein::FrankenFramedContentBody::Proposal(
                                    frankenstein::FrankenProposal::GroupContextExtensions(mut gces),
                                ),
                        },
                    ..
                }),
        }) = frankenstein::FrankenMlsMessage::tls_deserialize(
            &mut original_proposal
                .tls_serialize_detached()
                .unwrap()
                .as_slice(),
        )
        else {
            panic!("proposal message has unexpected format: {original_proposal:#?}")
        };

        let Some(frankenstein::FrankenExtension::RequiredCapabilities(
            frankenstein::FrankenRequiredCapabilitiesExtension {
                extension_types, ..
            },
        )) = gces.get_mut(0)
        else {
            panic!("required capabilities are malformed")
        };

        // this one is supported by bob, but not alice
        extension_types.push(0xf003);

        let group_context = bob.group.export_group_context().clone();
        let secrets = bob.group.group.message_secrets();
        let membership_key = secrets.membership_key().as_slice();

        let franken_commit_message = frankenstein::FrankenMlsMessage {
            version,
            body: frankenstein::FrankenMlsMessageBody::PublicMessage(
                frankenstein::FrankenPublicMessage::auth(
                    &bob.party.provider,
                    ciphersuite,
                    &bob.party.signer,
                    frankenstein::FrankenFramedContent {
                        group_id,
                        epoch,
                        sender: bob_sender,
                        authenticated_data,
                        body: frankenstein::FrankenFramedContentBody::Commit(
                            frankenstein::FrankenCommit {
                                proposals: vec![frankenstein::FrankenProposalOrRef::Proposal(
                                    frankenstein::FrankenProposal::GroupContextExtensions(gces),
                                )],
                                path: None,
                            },
                        ),
                    },
                    Some(&group_context.into()),
                    Some(membership_key),
                    // this is a dummy confirmation_tag:
                    Some(vec![0u8; 32].into()),
                ),
            ),
        };

        let fake_commit = MlsMessageIn::tls_deserialize(
            &mut franken_commit_message
                .tls_serialize_detached()
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let err = {
            let validation_skip_handle = crate::skip_validation::checks::confirmation_tag::handle();
            validation_skip_handle.with_disabled(|| alice.fail_processing(fake_commit.clone()))
        };

        assert!(
            matches!(
                err,
                ProcessMessageError::InvalidCommit(
                    StageCommitError::GroupContextExtensionsProposalValidationError(
                        GroupContextExtensionsProposalValidationError::RequiredExtensionNotSupportedByAllMembers
                    )
                )
            ),
            "expected different error. got {err:?}"
        );
    }

    // Test that the builder pattern accurately configures the new group.
    #[openmls_test]
    fn proposal() {
        let TestState { mut alice, mut bob }: TestState<Provider> = setup(ciphersuite);

        // No required capabilities, so no specifically required extensions.
        assert!(alice
            .group
            .group()
            .context()
            .extensions()
            .required_capabilities()
            .is_none());

        let new_extensions = Extensions::single(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf001)], &[], &[]),
        ));

        let (proposal, _) = alice.propose_group_context_extensions(new_extensions.clone());
        bob.process_and_store_proposal(proposal.into());

        assert_eq!(alice.group.pending_proposals().count(), 1);

        let (commit, _, _) = alice.commit_and_merge_pending();
        bob.process_and_merge_commit(commit.into());
        assert_eq!(alice.group.pending_proposals().count(), 0);

        let required_capabilities = alice
            .group
            .group()
            .context()
            .extensions()
            .required_capabilities()
            .expect("couldn't get required_capabilities");

        // has required_capabilities as required capability
        assert!(required_capabilities.extension_types() == [ExtensionType::Unknown(0xf001)]);

        // === committing to two group context extensions should fail
        let new_extensions_2 = Extensions::single(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(&[ExtensionType::RatchetTree], &[], &[]),
        ));

        alice
            .group
            .propose_group_context_extensions(
                &alice.party.provider,
                new_extensions,
                &alice.party.signer,
            )
            .expect("failed to build group context extensions proposal");

        // the proposals need to be different or they will be deduplicated
        alice
            .group
            .propose_group_context_extensions(
                &alice.party.provider,
                new_extensions_2,
                &alice.party.signer,
            )
            .expect("failed to build group context extensions proposal");

        assert_eq!(alice.group.pending_proposals().count(), 2);

        alice
            .group
            .commit_to_pending_proposals(&alice.party.provider, &alice.party.signer)
            .expect_err(
                "expected error when committing to multiple group context extensions proposals",
            );

        // === can't update required required_capabilities to extensions that existing group members
        //       are not capable of

        // contains unsupported extension
        let new_extensions = Extensions::single(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0xf042)], &[], &[]),
        ));

        alice
            .group
            .propose_group_context_extensions(
                &alice.party.provider,
                new_extensions,
                &alice.party.signer,
            )
            .expect_err("expected an error building GCE proposal with bad required_capabilities");
    }
}

// Test that the builder pattern accurately configures the new group.
#[openmls_test]
fn builder_pattern() {
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

    let test_ciphersuite = ciphersuite;
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
        .ciphersuite(test_ciphersuite)
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
    assert_eq!(ciphersuite, test_ciphersuite);
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

// Test the successful update of Group Context Extension with type Extension::Unknown(0xff11)
#[openmls_test]
fn update_group_context_with_unknown_extension<Provider: OpenMlsProvider + Default>() {
    let alice_provider = Provider::default();
    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, &alice_provider);

    // === Define the unknown group context extension and initial data ===
    const UNKNOWN_EXTENSION_TYPE: u16 = 0xff11;
    let unknown_extension_data = vec![1, 2];
    let unknown_gc_extension = Extension::Unknown(
        UNKNOWN_EXTENSION_TYPE,
        UnknownExtension(unknown_extension_data),
    );
    let required_extension_types = &[ExtensionType::Unknown(UNKNOWN_EXTENSION_TYPE)];
    let required_capabilities = Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(required_extension_types, &[], &[]),
    );
    let capabilities = Capabilities::new(None, None, Some(required_extension_types), None, None);
    let test_gc_extensions = Extensions::from_vec(vec![
        unknown_gc_extension.clone(),
        required_capabilities.clone(),
    ])
    .expect("error creating test group context extensions");
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .with_group_context_extensions(test_gc_extensions.clone())
        .expect("error adding unknown extension to config")
        .capabilities(capabilities.clone())
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice_signer,
        &mls_group_create_config,
        alice_credential_with_key,
    )
    .expect("error creating group");

    // === Verify the initial group context extension data is correct ===
    let group_context_extensions = alice_group.group().context().extensions();
    let mut extracted_data = None;
    for extension in group_context_extensions.iter() {
        if let Extension::Unknown(UNKNOWN_EXTENSION_TYPE, UnknownExtension(data)) = extension {
            extracted_data = Some(data.clone());
        }
    }
    assert_eq!(
        extracted_data.unwrap(),
        vec![1, 2],
        "The data of Extension::Unknown(0xff11) does not match the expected data"
    );

    // === Alice adds Bob ===
    let bob_provider: Provider = Default::default();
    let (bob_credential_with_key, _bob_kpb, bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, &bob_provider);

    let bob_key_package = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(
            ciphersuite,
            &bob_provider,
            &bob_signer,
            bob_credential_with_key,
        )
        .expect("error building key package");

    let (_, welcome, _) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(&bob_provider)
    .expect("Error creating group from staged join");

    // === Verify Bob's initial group context extension data is correct ===
    let group_context_extensions = bob_group.group().context().extensions();
    let mut extracted_data_2 = None;
    for extension in group_context_extensions.iter() {
        if let Extension::Unknown(UNKNOWN_EXTENSION_TYPE, UnknownExtension(data)) = extension {
            extracted_data_2 = Some(data.clone());
        }
    }
    assert_eq!(
        extracted_data_2.unwrap(),
        vec![1, 2],
        "The data of Extension::Unknown(0xff11) does not match the expected data"
    );

    // === Propose the new group context extension ===
    let updated_unknown_extension_data = vec![3, 4]; // Sample data for the extension
    let updated_unknown_gc_extension = Extension::Unknown(
        UNKNOWN_EXTENSION_TYPE,
        UnknownExtension(updated_unknown_extension_data.clone()),
    );

    let mut updated_extensions = test_gc_extensions.clone();
    updated_extensions.add_or_replace(updated_unknown_gc_extension);
    let (update_proposal, _) = alice_group
        .propose_group_context_extensions(provider, updated_extensions, &alice_signer)
        .expect("failed to propose group context extensions with unknown extension");

    assert_eq!(
        alice_group.pending_proposals().count(),
        1,
        "Expected one pending proposal"
    );

    // === Commit to the proposed group context extension ===
    let (update_commit, _, _) = alice_group
        .commit_to_pending_proposals(provider, &alice_signer)
        .expect("failed to commit to pending group context extensions");

    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // === let bob process the updates  ===
    assert_eq!(
        bob_group.pending_proposals().count(),
        0,
        "Expected no pending proposals"
    );

    let processed_update_message = bob_group
        .process_message(
            &bob_provider,
            update_proposal.into_protocol_message().unwrap(),
        )
        .expect("bob failed processing the update");

    match processed_update_message.into_content() {
        ProcessedMessageContent::ProposalMessage(msg) => {
            bob_group
                .store_pending_proposal(bob_provider.storage(), *msg)
                .unwrap();
        }
        other => panic!("expected proposal, got {other:?}"),
    }

    assert_eq!(
        bob_group.pending_proposals().count(),
        1,
        "Expected one pending proposal"
    );

    let processed_commit_message = bob_group
        .process_message(
            &bob_provider,
            update_commit.into_protocol_message().unwrap(),
        )
        .expect("bob failed processing the update");

    match processed_commit_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => bob_group
            .merge_staged_commit(&bob_provider, *staged_commit)
            .expect("error merging group context update commit"),
        other => panic!("expected commit, got {other:?}"),
    };

    // === Verify the group context extension was updated ===
    let group_context_extensions = alice_group.group().context().extensions();
    let mut extracted_data_updated = None;
    for extension in group_context_extensions.iter() {
        if let Extension::Unknown(UNKNOWN_EXTENSION_TYPE, UnknownExtension(data)) = extension {
            extracted_data_updated = Some(data.clone());
        }
    }
    assert_eq!(
        extracted_data_updated.unwrap(),
        vec![3, 4],
        "The data of Extension::Unknown(0xff11) does not match the expected data"
    );

    // === Verify Bob sees the group context extension updated ===
    let bob_group_loaded = MlsGroup::load(bob_provider.storage(), bob_group.group().group_id())
        .expect("error loading group")
        .expect("no such group");
    let group_context_extensions_2 = bob_group_loaded.export_group_context().extensions();
    let mut extracted_data_2 = None;
    for extension in group_context_extensions_2.iter() {
        if let Extension::Unknown(UNKNOWN_EXTENSION_TYPE, UnknownExtension(data)) = extension {
            extracted_data_2 = Some(data.clone());
        }
    }
    assert_eq!(
        extracted_data_2.unwrap(),
        vec![3, 4],
        "The data of Extension::Unknown(0xff11) does not match the expected data"
    );
}

#[openmls_test]
fn test_update_group_context_with_unknown_extension_using_update_function<
    Provider: OpenMlsProvider + Default,
>() {
    let alice_provider = Provider::default();
    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, &alice_provider);

    // === Define the unknown group context extension and initial data ===
    const UNKNOWN_EXTENSION_TYPE: u16 = 0xff11;
    let unknown_extension_data = vec![1, 2];
    let unknown_gc_extension = Extension::Unknown(
        UNKNOWN_EXTENSION_TYPE,
        UnknownExtension(unknown_extension_data),
    );
    let required_extension_types = &[ExtensionType::Unknown(UNKNOWN_EXTENSION_TYPE)];
    let required_capabilities = Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(required_extension_types, &[], &[]),
    );
    let capabilities = Capabilities::new(None, None, Some(required_extension_types), None, None);
    let test_gc_extensions = Extensions::from_vec(vec![
        unknown_gc_extension.clone(),
        required_capabilities.clone(),
    ])
    .expect("error creating test group context extensions");
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .with_group_context_extensions(test_gc_extensions.clone())
        .expect("error adding unknown extension to config")
        .capabilities(capabilities.clone())
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice_signer,
        &mls_group_create_config,
        alice_credential_with_key,
    )
    .expect("error creating group");

    // === Verify the initial group context extension data is correct ===
    let group_context_extensions = alice_group.group().context().extensions();
    let mut extracted_data = None;
    for extension in group_context_extensions.iter() {
        if let Extension::Unknown(UNKNOWN_EXTENSION_TYPE, UnknownExtension(data)) = extension {
            extracted_data = Some(data.clone());
        }
    }
    assert_eq!(
        extracted_data.unwrap(),
        vec![1, 2],
        "The data of Extension::Unknown(0xff11) does not match the expected data"
    );

    // === Propose the new group context extension using update_group_context_extensions ===
    let updated_unknown_extension_data = vec![3, 4];
    let updated_unknown_gc_extension = Extension::Unknown(
        UNKNOWN_EXTENSION_TYPE,
        UnknownExtension(updated_unknown_extension_data.clone()),
    );

    let mut updated_extensions = test_gc_extensions.clone();
    updated_extensions.add_or_replace(updated_unknown_gc_extension);

    let update_result = alice_group.update_group_context_extensions(
        &alice_provider,
        updated_extensions,
        &alice_signer,
    );
    assert!(
        update_result.is_ok(),
        "Failed to update group context extensions: {:?}",
        update_result.err()
    );

    // === Test clearing staged commit before merge, verify context shows expected data ===
    alice_group
        .clear_pending_commit(provider.storage())
        .unwrap();
    let group_context_extensions = alice_group.group().context().extensions();
    let mut extracted_data = None;
    for extension in group_context_extensions.iter() {
        if let Extension::Unknown(UNKNOWN_EXTENSION_TYPE, UnknownExtension(data)) = extension {
            extracted_data = Some(data.clone());
        }
    }
    assert_eq!(
        extracted_data.unwrap(),
        vec![1, 2],
        "The data of Extension::Unknown(0xff11) does not match the expected data"
    );

    // === Propose the new group context extension using update_group_context_extensions ===
    let updated_unknown_extension_data = vec![4, 5]; // Sample data for the extension
    let updated_unknown_gc_extension = Extension::Unknown(
        UNKNOWN_EXTENSION_TYPE,
        UnknownExtension(updated_unknown_extension_data.clone()),
    );

    let mut updated_extensions = test_gc_extensions.clone();
    updated_extensions.add_or_replace(updated_unknown_gc_extension);
    let update_result = alice_group.update_group_context_extensions(
        &alice_provider,
        updated_extensions,
        &alice_signer,
    );
    assert!(
        update_result.is_ok(),
        "Failed to update group context extensions: {:?}",
        update_result.err()
    );

    // === Merge Pending Commit ===
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    // === Verify the group context extension was updated ===
    let group_context_extensions = alice_group.group().context().extensions();
    let mut extracted_data_updated = None;
    for extension in group_context_extensions.iter() {
        if let Extension::Unknown(UNKNOWN_EXTENSION_TYPE, UnknownExtension(data)) = extension {
            extracted_data_updated = Some(data.clone());
        }
    }
    assert_eq!(
        extracted_data_updated.unwrap(),
        vec![4, 5],
        "The data of Extension::Unknown(0xff11) does not match the expected data"
    );
}

// Test that unknown group context and leaf node extensions can be used in groups
#[openmls_test]
fn unknown_extensions() {
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
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
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
        .build(ciphersuite, provider, &bob_signer, bob_credential_with_key)
        .expect("error building key package");

    assert_eq!(
        bob_key_package.key_package().extensions(),
        &Extensions::single(unknown_kp_extension)
    );

    // alice adds bob and bob processes the welcome to ensure that the unknown
    // extensions are processed correctly
    let (_, welcome, _) = alice_group
        .add_members(
            provider,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        )
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

#[openmls_test]
fn join_multiple_groups_last_resort_extension(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // start with alice, bob, charlie, common config items
    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("alice", ciphersuite, provider);
    let (bob_credential_with_key, _bob_kpb, bob_signer, _bob_pk) =
        setup_client("bob", ciphersuite, provider);
    let (charlie_credential_with_key, _charlie_kpb, charlie_signer, _charlie_pk) =
        setup_client("charlie", ciphersuite, provider);
    let leaf_capabilities =
        Capabilities::new(None, None, Some(&[ExtensionType::LastResort]), None, None);
    let keypkg_extensions = Extensions::single(Extension::LastResort(LastResortExtension::new()));
    // alice creates MlsGroup
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build(provider, &alice_signer, alice_credential_with_key)
        .expect("error creating group for alice using builder");
    // bob creates MlsGroup
    let mut bob_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build(provider, &bob_signer, bob_credential_with_key)
        .expect("error creating group for bob using builder");
    // charlie creates KeyPackage
    let charlie_keypkg = KeyPackage::builder()
        .leaf_node_capabilities(leaf_capabilities)
        .key_package_extensions(keypkg_extensions.clone())
        .build(
            ciphersuite,
            provider,
            &charlie_signer,
            charlie_credential_with_key,
        )
        .expect("error building key package for charlie");
    // alice calls add_members(...) with charlie's KeyPackage; produces Commit and Welcome messages
    let (_, alice_welcome, _) = alice_group
        .add_members(
            provider,
            &alice_signer,
            &[charlie_keypkg.key_package().clone()],
        )
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
        .add_members(
            provider,
            &bob_signer,
            &[charlie_keypkg.key_package().clone()],
        )
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
