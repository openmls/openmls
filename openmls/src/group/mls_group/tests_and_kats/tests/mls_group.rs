use mls_group::tests_and_kats::utils::{
    flip_last_byte, setup_alice_bob, setup_alice_bob_group, setup_client,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::MemoryStorage;
use openmls_test::openmls_test;
use openmls_traits::{storage::CURRENT_VERSION, OpenMlsProvider as _};
use signable::Signable;
use tls_codec::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafNodeIndex,
    credentials::test_utils::new_credential,
    framing::*,
    group::{errors::*, *},
    key_packages::*,
    messages::{
        group_info::GroupInfoTBS, proposals::*, EncryptedGroupSecrets, GroupSecretsError, Welcome,
    },
    prelude::ConfirmationTag,
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    test_utils::{
        frankenstein::{FrankenFramedContentBody, FrankenPublicMessage},
        test_framework::{
            errors::ClientError, noop_authentication_service, ActionType::Commit, CodecUse,
            MlsGroupTestSetup,
        },
    },
    tree::sender_ratchet::SenderRatchetConfiguration,
    treesync::{
        errors::{ApplyUpdatePathError, LeafNodeValidationError},
        node::leaf_node::Capabilities,
        LeafNodeParameters,
    },
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
        .self_update(Commit, &group_id, LeafNodeParameters::default())
        .expect("error creating self update");

    // Store the context and membership key so that we can re-compute the membership tag later.
    let client_groups = client.groups.read().unwrap();
    let client_group = client_groups.get(&group_id).unwrap();
    let membership_key = client_group.message_secrets().membership_key();

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
                client_group.message_secrets().serialized_context(),
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
        .self_update(provider, &alice_signer, LeafNodeParameters::default())
        .expect("error creating self-update commit")
        .into_messages();

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
        .self_update(provider, &alice_signer, LeafNodeParameters::default())
        .expect("error creating self-update commit")
        .into_contents();

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
        .self_update(provider, &alice_signer, LeafNodeParameters::default())
        .expect("error creating self-update commit")
        .into_messages();
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
        .self_update(provider, &alice_signer, LeafNodeParameters::default())
        .expect("error creating self-update commit")
        .into_messages();
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
        .self_update(provider, &alice_signer, LeafNodeParameters::default())
        .expect("error creating self-update commit")
        .into_messages();
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
        .self_update(provider, &alice_signer, LeafNodeParameters::default())
        .expect_err("no error committing while a commit is pending");
    assert!(matches!(
        error,
        SelfUpdateError::GroupStateError(MlsGroupStateError::PendingCommit)
    ));
    let error = alice_group
        .propose_self_update(provider, &alice_signer, LeafNodeParameters::default())
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
        .self_update(provider, &alice_signer, LeafNodeParameters::default())
        .expect("error creating self-update commit")
        .into_messages();

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
        .self_update(provider, &alice_signer, LeafNodeParameters::default())
        .expect("error creating self-update commit")
        .into_messages();

    let (msg, _welcome_option, _group_info) = bob_group
        .self_update(provider, &bob_signer, LeafNodeParameters::default())
        .expect("error creating self-update commit")
        .into_messages();

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

    assert_eq!(alice_group.proposal_store().proposals().count(), 1);
    // clearing the proposal by reference
    alice_group
        .remove_pending_proposal(provider.storage(), &reference)
        .unwrap();
    assert!(alice_group.proposal_store().is_empty());

    // the proposal should not be stored anymore
    let err = alice_group
        .remove_pending_proposal(provider.storage(), &reference)
        .unwrap_err();
    assert!(matches!(err, RemoveProposalError::ProposalNotFound));

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

#[openmls_test]
fn max_past_epochs_join_config(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    let max_past_epochs = 10;

    let create_config = MlsGroupCreateConfig::builder()
        .max_past_epochs(max_past_epochs)
        .build();

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);

    let alice_group = MlsGroup::new(
        provider,
        &alice_signer,
        &create_config,
        alice_credential_with_key,
    )
    .expect("failed to create group");

    assert_eq!(
        alice_group.message_secrets_store.max_epochs,
        max_past_epochs
    );
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
        .with_capabilities(test_capabilities.clone())
        .with_leaf_node_extensions(test_leaf_extensions.clone())
        .expect("error adding leaf node extension to builder")
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
    assert_eq!(builder_err, LeafNodeValidationError::UnsupportedExtensions);
}

// Test the successful update of Group Context Extension with type Extension::Unknown(0xff11)
#[openmls_test]
fn update_group_context_with_unknown_extension<Provider: OpenMlsProvider + Default>() {
    let alice_provider = Provider::default();
    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);

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
        provider,
        &alice_signer,
        &mls_group_create_config,
        alice_credential_with_key,
    )
    .expect("error creating group");

    // === Verify the initial group context extension data is correct ===
    let group_context_extensions = alice_group.context().extensions();
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
    let group_context_extensions = bob_group.context().extensions();
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
    let group_context_extensions = alice_group.context().extensions();
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
    let bob_group_loaded = MlsGroup::load(bob_provider.storage(), bob_group.group_id())
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
fn update_proposal_bob() {
    let alice_provider = Provider::default();
    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, &alice_provider);

    let mls_group_create_config = MlsGroupCreateConfig::builder()
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

    // === Alice adds Bob ===
    let bob_provider: Provider = Default::default();
    let (bob_credential_with_key, _bob_kpb, bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, &bob_provider);

    let bob_key_package = KeyPackage::builder()
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

    // === Bob proposes an update ===
    let (update_proposal, _proposal_reference) = bob_group
        .propose_self_update(
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::builder().build(),
        )
        .unwrap();

    // === Alice processes the update proposal from Bob ===
    let processed_message = alice_group
        .process_message(
            &alice_provider,
            update_proposal.into_protocol_message().unwrap(),
        )
        .unwrap();

    let ProcessedMessageContent::ProposalMessage(proposal_msg) = processed_message.into_content()
    else {
        panic!("expected proposal");
    };
    bob_group
        .store_pending_proposal(bob_provider.storage(), *proposal_msg)
        .unwrap();

    // === Alice commits to the proposal ===
    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(&alice_provider, &alice_signer)
        .expect("failed to commit to pending group context extensions");

    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("error merging pending commit");

    // === Bob processes the commit  ===
    let processed_message = bob_group
        .process_message(&bob_provider, commit.into_protocol_message().unwrap())
        .expect("bob failed processing the update");

    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    else {
        panic!("Expected a commit");
    };
    bob_group
        .merge_staged_commit(&bob_provider, *staged_commit)
        .expect("error merging commit to own update proposal");
}

#[openmls_test]
fn update_proposal_alice() {
    let alice_provider = Provider::default();
    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, &alice_provider);

    let mls_group_create_config = MlsGroupCreateConfig::builder()
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

    // === Alice adds Bob ===
    let bob_provider: Provider = Default::default();
    let (bob_credential_with_key, _bob_kpb, bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, &bob_provider);

    let bob_key_package = KeyPackage::builder()
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

    // === Alice proposes an update ===
    let (update_proposal, _proposal_reference) = alice_group
        .propose_self_update(
            &alice_provider,
            &alice_signer,
            LeafNodeParameters::builder().build(),
        )
        .unwrap();

    // === Bob processes the update proposal from Alice ===
    let processed_message = bob_group
        .process_message(
            &bob_provider,
            update_proposal.into_protocol_message().unwrap(),
        )
        .unwrap();

    let ProcessedMessageContent::ProposalMessage(proposal_msg) = processed_message.into_content()
    else {
        panic!("expected proposal");
    };
    bob_group
        .store_pending_proposal(bob_provider.storage(), *proposal_msg)
        .unwrap();

    // === Bob commits to the proposal ===
    let (commit, _, _) = bob_group
        .commit_to_pending_proposals(&bob_provider, &bob_signer)
        .expect("failed to commit to pending group context extensions");

    bob_group
        .merge_pending_commit(&bob_provider)
        .expect("error merging pending commit");

    // === Alice processes the commit  ===
    let processed_message = alice_group
        .process_message(&alice_provider, commit.into_protocol_message().unwrap())
        .expect("bob failed processing the update");

    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    else {
        panic!("Expected a commit");
    };
    alice_group
        .merge_staged_commit(&alice_provider, *staged_commit)
        .expect("error merging commit to own update proposal");

    assert_eq!(
        alice_group.epoch_authenticator(),
        bob_group.epoch_authenticator()
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
    let group_context_extensions = alice_group.context().extensions();
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
    let group_context_extensions = alice_group.context().extensions();
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
    let group_context_extensions = alice_group.context().extensions();
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

#[openmls_test]
fn deletion() {
    let alice_provider = provider;
    let (alice_credential_with_key, alice_kpb, alice_signer, alice_pk) =
        setup_client("alice", ciphersuite, provider);

    // delete the kpb from the provider, as we don't need it
    <MemoryStorage as openmls_traits::storage::StorageProvider<CURRENT_VERSION>>::
        delete_key_package(alice_provider.storage(),&alice_kpb.key_package().hash_ref(provider.crypto()).unwrap())
        .unwrap();
    <MemoryStorage as openmls_traits::storage::StorageProvider<CURRENT_VERSION>>::
        delete_encryption_key_pair(alice_provider.storage(),alice_kpb.key_package().leaf_node().encryption_key()).unwrap();

    // alice creates MlsGroup
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build(provider, &alice_signer, alice_credential_with_key)
        .expect("error creating group for alice using builder");

    SignatureKeyPair::delete(
        alice_provider.storage(),
        alice_pk.as_slice(),
        ciphersuite.signature_algorithm(),
    )
    .unwrap();

    // alice deletes the group
    alice_group.delete(alice_provider.storage()).unwrap();

    assert!(alice_provider.storage().values.read().unwrap().is_empty());
}

#[openmls_test::openmls_test]
fn failed_groupinfo_decryption(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    let epoch = 123;
    let group_id = GroupId::random(provider.rand());
    let tree_hash = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let confirmed_transcript_hash = vec![1, 1, 1];
    let extensions = Extensions::empty();
    let confirmation_tag = ConfirmationTag(Mac {
        mac_value: vec![1, 2, 3, 4, 5, 6, 7, 8, 9].into(),
    });

    // Create credentials and keys
    let (alice_credential_with_key, alice_signature_keys) =
        new_credential(provider, b"Alice", ciphersuite.signature_algorithm());

    let key_package_bundle = KeyPackageBundle::generate(
        provider,
        &alice_signature_keys,
        ciphersuite,
        alice_credential_with_key,
    );

    let group_info_tbs = {
        let group_context = GroupContext::new(
            ciphersuite,
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            Extensions::empty(),
        );

        GroupInfoTBS::new(
            group_context,
            extensions,
            confirmation_tag,
            LeafNodeIndex::new(0),
        )
    };

    // Generate key and nonce for the symmetric cipher.
    let welcome_key = AeadKey::random(ciphersuite, provider.rand());
    let welcome_nonce = AeadNonce::random(provider.rand());

    // Generate receiver key pair.
    let receiver_key_pair = provider
        .crypto()
        .derive_hpke_keypair(
            ciphersuite.hpke_config(),
            Secret::random(ciphersuite, provider.rand())
                .expect("Not enough randomness.")
                .as_slice(),
        )
        .expect("error deriving receiver hpke key pair");
    let hpke_context = b"group info welcome test info";
    let group_secrets = b"these should be the group secrets";
    let mut encrypted_group_secrets = hpke::encrypt_with_label(
        receiver_key_pair.public.as_slice(),
        "Welcome",
        hpke_context,
        group_secrets,
        ciphersuite,
        provider.crypto(),
    )
    .unwrap();

    let group_info = group_info_tbs
        .sign(&alice_signature_keys)
        .expect("Error signing group info");

    // Mess with the ciphertext by flipping the last byte.
    flip_last_byte(&mut encrypted_group_secrets);

    let broken_secrets = vec![EncryptedGroupSecrets::new(
        key_package_bundle
            .key_package
            .hash_ref(provider.crypto())
            .expect("Could not hash KeyPackage."),
        encrypted_group_secrets,
    )];

    // Encrypt the group info.
    let encrypted_group_info = welcome_key
        .aead_seal(
            provider.crypto(),
            &group_info
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
            &[],
            &welcome_nonce,
        )
        .expect("An unexpected error occurred.");

    // Now build the welcome message.
    let broken_welcome = Welcome::new(ciphersuite, broken_secrets, encrypted_group_info);

    let error = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        broken_welcome,
        None,
    )
    .and_then(|staged_join| staged_join.into_group(provider))
    .expect_err("Creation of mls group from a broken Welcome was successful.");

    assert!(matches!(
        error,
        WelcomeError::GroupSecrets(GroupSecretsError::DecryptionFailed)
    ))
}

/// Test what happens if the KEM ciphertext for the receiver in the UpdatePath
/// is broken.
#[openmls_test::openmls_test]
fn update_path() {
    // === Alice creates a group with her and Bob ===
    let (
        mut group_alice,
        _alice_signature_keys,
        mut group_bob,
        bob_signature_keys,
        _bob_credential_with_key,
    ) = setup_alice_bob_group(ciphersuite, provider);

    // === Bob updates and commits ===
    let mut bob_new_leaf_node = group_bob.own_leaf_node().unwrap().clone();
    bob_new_leaf_node
        .update(
            ciphersuite,
            provider,
            &bob_signature_keys,
            group_bob.group_id().clone(),
            group_bob.own_leaf_index(),
            LeafNodeParameters::default(),
        )
        .unwrap();

    let (update_bob, _welcome_option, _group_info_option) = group_bob
        .self_update(provider, &bob_signature_keys, LeafNodeParameters::default())
        .expect("Could not create proposal.")
        .into_contents();

    // Now we break Alice's HPKE ciphertext in Bob's commit by breaking
    // apart the commit, manipulating the ciphertexts and the piecing it
    // back together.
    let pm = match update_bob.body {
        mls_group::MlsMessageBodyOut::PublicMessage(pm) => pm,
        _ => panic!("Wrong message type"),
    };

    let franken_pm = FrankenPublicMessage::from(pm.clone());
    let mut content = franken_pm.content.clone();
    let FrankenFramedContentBody::Commit(ref mut commit) = content.body else {
        panic!("Unexpected content type");
    };
    let Some(ref mut path) = commit.path else {
        panic!("No path in commit.");
    };

    for node in &mut path.nodes {
        for eps in &mut node.encrypted_path_secrets {
            let mut eps_ctxt_vec = Vec::<u8>::from(eps.ciphertext.clone());
            eps_ctxt_vec[0] ^= 0xff;
            eps.ciphertext = eps_ctxt_vec.into();
        }
    }

    // Rebuild the PublicMessage with the new content
    let group_context = group_bob.export_group_context().clone();
    let membership_key = group_bob.message_secrets().membership_key().as_slice();

    let broken_message = FrankenPublicMessage::auth(
        provider,
        ciphersuite,
        &bob_signature_keys,
        content,
        Some(&group_context.into()),
        Some(membership_key),
        Some(pm.confirmation_tag().unwrap().0.mac_value.clone()),
    );

    let protocol_message = ProtocolMessage::from(PublicMessage::from(broken_message));

    let result = group_alice.process_message(provider, protocol_message);
    assert_eq!(
        result.expect_err("Successful processing of a broken commit."),
        ProcessMessageError::InvalidCommit(StageCommitError::UpdatePathError(
            ApplyUpdatePathError::UnableToDecrypt
        ))
    );
}

// Test several scenarios when PSKs are used in a group
#[openmls_test::openmls_test]
fn psks() {
    // Basic group setup.
    let (
        alice_credential_with_key,
        alice_signature_keys,
        bob_key_package_bundle,
        bob_signature_keys,
    ) = setup_alice_bob(ciphersuite, provider);

    // === Alice creates a group with a PSK ===
    let psk_id = vec![1u8, 2, 3];

    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let external_psk = ExternalPsk::new(psk_id);
    let preshared_key_id =
        PreSharedKeyId::new(ciphersuite, provider.rand(), Psk::External(external_psk))
            .expect("An unexpected error occured.");
    preshared_key_id.store(provider, secret.as_slice()).unwrap();
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(provider, &alice_signature_keys, alice_credential_with_key)
        .expect("Error creating group.");

    // === Alice creates a PSK proposal ===
    log::info!(" >>> Creating psk proposal ...");
    let (_psk_proposal, _proposal_ref) = alice_group
        .propose_external_psk(provider, &alice_signature_keys, preshared_key_id)
        .expect("Could not create PSK proposal");

    // === Alice adds Bob (and commits to PSK proposal) ===
    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[bob_key_package_bundle.key_package().clone()],
        )
        .expect("Could not create commit");

    log::info!(" >>> Merging commit ...");

    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit");

    let ratchet_tree = alice_group.export_ratchet_tree();

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Could not stage welcome")
    .into_group(provider)
    .expect("Could not create group from welcome");

    // === Bob updates and commits ===
    let (_commit, _welcome_option, _group_info_option) = bob_group
        .self_update(provider, &bob_signature_keys, LeafNodeParameters::default())
        .expect("An unexpected error occurred.")
        .into_contents();
}

// Test several scenarios when PSKs are used in a group
#[openmls_test::openmls_test]
fn staged_commit_creation(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Basic group setup.
    let (alice_credential_with_key, alice_signature_keys, bob_key_package_bundle, _) =
        setup_alice_bob(ciphersuite, provider);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(provider, &alice_signature_keys, alice_credential_with_key)
        .expect("Error creating group.");

    // === Alice adds Bob ===
    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[bob_key_package_bundle.key_package().clone()],
        )
        .expect("Could not create commit");

    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit");

    let ratchet_tree = alice_group.export_ratchet_tree();

    let bob_group = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Could not stage welcome")
    .into_group(provider)
    .expect("Could not create group from welcome");

    // Let's make sure we end up in the same group state.
    assert_eq!(
        bob_group.epoch_authenticator(),
        alice_group.epoch_authenticator()
    );
    assert_eq!(
        bob_group.export_ratchet_tree(),
        alice_group.export_ratchet_tree()
    )
}

// Test processing of own commits
#[openmls_test::openmls_test]
fn own_commit_processing(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Basic group setup.
    let (alice_credential_with_key, alice_signature_keys) =
        new_credential(provider, b"Alice", ciphersuite.signature_algorithm());

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(provider, &alice_signature_keys, alice_credential_with_key)
        .expect("Error creating group.");

    // Alice creates a commit
    let (commit_out, _welcome_option, _group_info_option) = alice_group
        .self_update(
            provider,
            &alice_signature_keys,
            LeafNodeParameters::default(),
        )
        .expect("Could not create commit")
        .into_contents();

    let commit_in = MlsMessageIn::from(commit_out);

    // Alice attempts to process her own commit
    let error = alice_group
        .process_message(provider, commit_in.into_protocol_message().unwrap())
        .expect_err("no error while processing own commit");
    assert_eq!(
        error,
        ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit)
    );
}

#[openmls_test::openmls_test]
fn proposal_application_after_self_was_removed(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // We're going to test if proposals are still applied, even after a client
    // notices that it was removed from a group.  We do so by having Alice
    // create a group, add Bob and then create a commit where Bob is removed and
    // Charlie is added in a single commit (by Alice). We then check if
    // everyone's membership list is as expected.

    // Basic group setup.
    let (alice_credential_with_key, _, alice_signature_keys, _pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_, bob_kpb, _, _) = setup_client("Bob", ciphersuite, provider);
    let (_, charlie_kpb, _, _) = setup_client("Charlie", ciphersuite, provider);

    let join_group_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(provider, &alice_signature_keys, alice_credential_with_key)
        .expect("Error creating group.");

    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[bob_kpb.key_package().clone()],
        )
        .expect("Could not create commit");

    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit");

    let ratchet_tree = alice_group.export_ratchet_tree();

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        &join_group_config,
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Could not stage welcome")
    .into_group(provider)
    .expect("Could not create group from welcome");

    // Alice adds Charlie and removes Bob in the same commit.
    // She first creates a proposal to remove Bob
    let bob_index = alice_group
        .members()
        .find(
            |Member {
                 index: _,
                 credential,
                 ..
             }| { credential.serialized_content() == b"Bob" },
        )
        .expect("Couldn't find Bob in tree.")
        .index;

    assert_eq!(bob_index.u32(), 1);

    let (bob_remove_proposal, _bob_remove_proposal_ref) = alice_group
        .propose_remove_member(provider, &alice_signature_keys, bob_index)
        .expect("Could not create proposal");

    // Bob processes the proposal
    let processed_message = bob_group
        .process_message(
            provider,
            bob_remove_proposal.into_protocol_message().unwrap(),
        )
        .unwrap();

    let staged_proposal = match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(proposal) => *proposal,
        _ => panic!("Wrong message type"),
    };

    bob_group
        .store_pending_proposal(provider.storage(), staged_proposal)
        .expect("Error storing proposal");

    // Alice then commit to the proposal and at the same time adds Charlie
    let (commit, welcome, _group_info_option) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[charlie_kpb.key_package().clone()],
        )
        .expect("Could not create commit");

    // Alice merges her own commit
    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit");

    // Bob processes the commit
    println!("Bob processes the commit");
    let processed_message = bob_group
        .process_message(provider, commit.into_protocol_message().unwrap())
        .unwrap();

    let staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => *commit,
        _ => panic!("Wrong message type"),
    };

    bob_group
        .merge_staged_commit(provider, staged_commit)
        .expect("Error merging commit.");

    // Charlie processes the welcome
    println!("Charlie processes the commit");
    let ratchet_tree = alice_group.export_ratchet_tree();

    let charlie_group = StagedWelcome::new_from_welcome(
        provider,
        &join_group_config,
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Error staging welcome.")
    .into_group(provider)
    .expect("Error creating group from welcome.");

    // We can now check that Bob correctly processed his commit and applied the changes
    // to his tree after he was removed by comparing membership lists. In
    // particular, Bob's list should show that he was removed and Charlie was
    // added.
    let alice_members = alice_group.members();

    let bob_members = bob_group.members();

    let charlie_members = charlie_group.members();

    for (alice_member, (bob_member, charlie_member)) in
        alice_members.zip(bob_members.zip(charlie_members))
    {
        // Note that we can't compare encryption keys for Bob because they
        // didn't get updated.
        assert_eq!(alice_member.index, bob_member.index);

        let alice_id = alice_member.credential.serialized_content();
        let bob_id = bob_member.credential.serialized_content();
        let charlie_id = charlie_member.credential.serialized_content();
        assert_eq!(alice_id, bob_id);
        assert_eq!(alice_member.signature_key, bob_member.signature_key);
        assert_eq!(charlie_member.index, bob_member.index);
        assert_eq!(charlie_id, bob_id);
        assert_eq!(charlie_member.signature_key, bob_member.signature_key);
        assert_eq!(charlie_member.encryption_key, alice_member.encryption_key);
    }

    let mut bob_members = bob_group.members();

    let member = bob_members.next().unwrap();
    let bob_next_id = member.credential.serialized_content();
    assert_eq!(bob_next_id, b"Alice");
    let member = bob_members.next().unwrap();
    let bob_next_id = member.credential.serialized_content();
    assert_eq!(bob_next_id, b"Charlie");
}

#[openmls_test::openmls_test]
fn proposal_application_after_self_was_removed_ref(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // We're going to test if proposals are still applied, even after a client
    // notices that it was removed from a group.  We do so by having Alice
    // create a group, add Bob and then create a commit where Bob is removed and
    // Charlie is added in a single commit (by Alice). We then check if
    // everyone's membership list is as expected.

    // Basic group setup.
    let (alice_credential_with_key, _, alice_signature_keys, _pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_, bob_kpb, _, _) = setup_client("Bob", ciphersuite, provider);
    let (_, charlie_kpb, _, _) = setup_client("Charlie", ciphersuite, provider);

    let join_group_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(provider, &alice_signature_keys, alice_credential_with_key)
        .expect("Error creating group.");

    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[bob_kpb.key_package().clone()],
        )
        .expect("Could not create commit");

    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit");

    let ratchet_tree = alice_group.export_ratchet_tree();

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        &join_group_config,
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Could not stage welcome")
    .into_group(provider)
    .expect("Could not create group from welcome");

    // Alice adds Charlie and removes Bob in the same commit.
    // She first creates a proposal to remove Bob
    let bob_index = alice_group
        .members()
        .find(
            |Member {
                 index: _,
                 credential,
                 ..
             }| { credential.serialized_content() == b"Bob" },
        )
        .expect("Couldn't find Bob in tree.")
        .index;

    assert_eq!(bob_index.u32(), 1);

    let (bob_remove_proposal, _bob_remove_proposal_ref) = alice_group
        .propose_remove_member(provider, &alice_signature_keys, bob_index)
        .expect("Could not create proposal");

    let (charlie_add_proposal, _charlie_add_proposal_ref) = alice_group
        .propose_add_member(provider, &alice_signature_keys, charlie_kpb.key_package())
        .expect("Could not create proposal");

    // Bob processes the proposals
    let processed_message = bob_group
        .process_message(
            provider,
            bob_remove_proposal.into_protocol_message().unwrap(),
        )
        .unwrap();

    let staged_proposal = match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(proposal) => *proposal,
        _ => panic!("Wrong message type"),
    };

    bob_group
        .store_pending_proposal(provider.storage(), staged_proposal)
        .expect("Error storing proposal");

    let processed_message = bob_group
        .process_message(
            provider,
            charlie_add_proposal.into_protocol_message().unwrap(),
        )
        .unwrap();

    let staged_proposal = match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(proposal) => *proposal,
        _ => panic!("Wrong message type"),
    };

    bob_group
        .store_pending_proposal(provider.storage(), staged_proposal)
        .expect("Error storing proposal");

    // Alice then commits to the proposal and at the same time adds Charlie
    alice_group.print_ratchet_tree("Alice's tree before commit\n");
    let alice_rt_before = alice_group.export_ratchet_tree();
    let (commit, welcome, _group_info_option) = alice_group
        .commit_to_pending_proposals(provider, &alice_signature_keys)
        .expect("Could not create commit");

    // Alice merges her own commit
    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit");
    alice_group.print_ratchet_tree("Alice's tree after commit\n");

    // Bob processes the commit
    println!("Bob processes the commit");
    bob_group.print_ratchet_tree("Bob's tree before processing the commit\n");
    let bob_rt_before = bob_group.export_ratchet_tree();
    assert_eq!(alice_rt_before, bob_rt_before);
    let processed_message = bob_group
        .process_message(provider, commit.into_protocol_message().unwrap())
        .unwrap();
    println!("Bob finished processesing the commit");

    let staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => *commit,
        _ => panic!("Wrong message type"),
    };

    bob_group
        .merge_staged_commit(provider, staged_commit)
        .expect("Error merging commit.");

    // Charlie processes the welcome
    println!("Charlie processes the commit");
    let ratchet_tree = alice_group.export_ratchet_tree();

    let charlie_group = StagedWelcome::new_from_welcome(
        provider,
        &join_group_config,
        welcome.unwrap().into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Error staging welcome.")
    .into_group(provider)
    .expect("Error creating group from welcome.");

    // We can now check that Bob correctly processed his and applied the changes
    // to his tree after he was removed by comparing membership lists. In
    // particular, Bob's list should show that he was removed and Charlie was
    // added.
    let alice_members = alice_group.members();

    let bob_members = bob_group.members();

    let charlie_members = charlie_group.members();

    for (alice_member, (bob_member, charlie_member)) in
        alice_members.zip(bob_members.zip(charlie_members))
    {
        // Note that we can't compare encryption keys for Bob because they
        // didn't get updated.
        assert_eq!(alice_member.index, bob_member.index);

        let alice_id = alice_member.credential.serialized_content();
        let bob_id = bob_member.credential.serialized_content();
        let charlie_id = charlie_member.credential.serialized_content();
        assert_eq!(alice_id, bob_id);
        assert_eq!(alice_member.signature_key, bob_member.signature_key);
        assert_eq!(charlie_member.index, bob_member.index);
        assert_eq!(charlie_id, bob_id);
        assert_eq!(charlie_member.signature_key, bob_member.signature_key);
        assert_eq!(charlie_member.encryption_key, alice_member.encryption_key);
    }

    let mut bob_members = bob_group.members();

    let member = bob_members.next().unwrap();
    let bob_next_id = member.credential.serialized_content();
    assert_eq!(bob_next_id, b"Alice");
    let member = bob_members.next().unwrap();
    let bob_next_id = member.credential.serialized_content();
    assert_eq!(bob_next_id, b"Charlie");
}
