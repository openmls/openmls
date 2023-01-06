use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme, OpenMlsCryptoProvider};
use tls_codec::Serialize;

use crate::{
    binary_tree::LeafNodeIndex,
    credentials::{errors::CredentialError, *},
    framing::*,
    group::{config::CryptoConfig, errors::*, *},
    key_packages::*,
    messages::proposals::*,
    test_utils::test_framework::{
        errors::ClientError, ActionType::Commit, CodecUse, MlsGroupTestSetup,
    },
    test_utils::*,
    versions::ProtocolVersion,
};

fn generate_credential_bundle(
    key_store: &impl OpenMlsCryptoProvider,
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_scheme: SignatureScheme,
) -> Result<Credential, CredentialError> {
    let cb = CredentialBundle::new(identity, credential_type, signature_scheme, key_store)?;
    let credential = cb.credential().clone();
    key_store
        .key_store()
        .store(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
            &cb,
        )
        .expect("An unexpected error occurred.");
    Ok(credential)
}

fn generate_key_package(
    backend: &impl OpenMlsCryptoProvider,
    ciphersuites: &[Ciphersuite],
    credential: &Credential,
    extensions: Vec<Extension>, // TODO[FK]: #819 allow setting leaf node extensions
) -> KeyPackage {
    let credential_bundle = backend
        .key_store()
        .read(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
        )
        .expect("An unexpected error occurred.");

    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(
            CryptoConfig {
                ciphersuite: ciphersuites[0],
                version: ProtocolVersion::default(),
            },
            backend,
            &credential_bundle,
        )
        .unwrap()
}

#[apply(ciphersuites_and_backends)]
fn test_mls_group_persistence(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        backend,
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package(backend, &[ciphersuite], &alice_credential, vec![]);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package.leaf_node().signature_key(),
    )
    .expect("An unexpected error occurred.");

    // Check the internal state has changed
    assert_eq!(alice_group.state_changed(), InnerState::Changed);

    let mut file_out = tempfile::NamedTempFile::new().expect("Could not create file");
    alice_group
        .save(&mut file_out)
        .expect("Could not write group state to file");

    let file_in = file_out
        .reopen()
        .expect("Error re-opening serialized group state file");
    let alice_group_deserialized = MlsGroup::load(file_in).expect("Could not deserialize MlsGroup");

    assert_eq!(
        (
            alice_group.export_ratchet_tree(),
            alice_group.export_secret(backend, "test", &[], 32)
        ),
        (
            alice_group_deserialized.export_ratchet_tree(),
            alice_group_deserialized.export_secret(backend, "test", &[], 32)
        )
    );
}

// This tests if the remover is correctly passed to the callback when one member
// issues a RemoveProposal and another members issues the next Commit.
#[apply(ciphersuites_and_backends)]
fn remover(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        backend,
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    )
    .expect("An unexpected error occurred.");

    let bob_credential = generate_credential_bundle(
        backend,
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    )
    .expect("An unexpected error occurred.");

    let charlie_credential = generate_credential_bundle(
        backend,
        "Charly".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package(backend, &[ciphersuite], &alice_credential, vec![]);

    let bob_key_package = generate_key_package(backend, &[ciphersuite], &bob_credential, vec![]);

    let charlie_key_package =
        generate_key_package(backend, &[ciphersuite], &charlie_credential, vec![]);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfigBuilder::new()
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package.leaf_node().signature_key(),
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob ===
    let (_queued_message, welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member to group.");

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome.into_welcome().expect("Unexpected message type."),
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    // === Bob adds Charlie ===
    let (queued_messages, welcome) = match bob_group.add_members(backend, &[charlie_key_package]) {
        Ok((qm, welcome)) => (qm, welcome),
        Err(e) => panic!("Could not add member to group: {:?}", e),
    };

    let alice_processed_message = alice_group
        .process_message(
            backend,
            queued_messages
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process messages.");
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group.merge_staged_commit(*staged_commit);
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    bob_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    let mut charlie_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome.into_welcome().expect("Unexpected message type."),
        Some(bob_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    // === Alice removes Bob & Charlie commits ===

    let queued_messages = alice_group
        .propose_remove_member(backend, LeafNodeIndex::new(1))
        .expect("Could not propose removal");

    let charlie_processed_message = charlie_group
        .process_message(
            backend,
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
    let (_queued_messages, _welcome) = charlie_group
        .commit_to_pending_proposals(backend)
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
        .merge_pending_commit()
        .expect("error merging pending commit");

    // TODO #524: Check that Alice removed Bob
}

#[apply(ciphersuites_and_backends)]
fn export_secret(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        backend,
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package(backend, &[ciphersuite], &alice_credential, vec![]);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let alice_group = MlsGroup::new_with_group_id(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package.leaf_node().signature_key(),
    )
    .expect("An unexpected error occurred.");

    assert!(
        alice_group
            .export_secret(backend, "test1", &[], ciphersuite.hash_length())
            .expect("An unexpected error occurred.")
            != alice_group
                .export_secret(backend, "test2", &[], ciphersuite.hash_length())
                .expect("An unexpected error occurred.")
    );
    assert!(
        alice_group
            .export_secret(backend, "test", &[0u8], ciphersuite.hash_length())
            .expect("An unexpected error occurred.")
            != alice_group
                .export_secret(backend, "test", &[1u8], ciphersuite.hash_length())
                .expect("An unexpected error occurred.")
    )
}

#[apply(ciphersuites_and_backends)]
fn test_invalid_plaintext(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Some basic setup functions for the MlsGroup.
    let mls_group_config = MlsGroupConfig::test_default(ciphersuite);

    let number_of_clients = 20;
    let setup = MlsGroupTestSetup::new(
        mls_group_config,
        number_of_clients,
        CodecUse::StructMessages,
    );
    // Create a basic group with more than 4 members to create a tree with intermediate nodes.
    let group_id = setup
        .create_random_group(10, ciphersuite)
        .expect("An unexpected error occurred.");
    let mut groups = setup.groups.write().expect("An unexpected error occurred.");
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    let (_, client_id) = &group
        .members
        .iter()
        .find(|(index, _)| index == &0)
        .expect("An unexpected error occurred.")
        .clone();

    let clients = setup.clients.read().expect("An unexpected error occurred.");
    let client = clients
        .get(client_id)
        .expect("An unexpected error occurred.")
        .read()
        .expect("An unexpected error occurred.");

    let (mls_message, _welcome_option) = client
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
    if let MlsMessageOutBody::PublicMessage(ref mut pt) = msg_invalid_signature.body {
        pt.invalidate_signature()
    };

    // Tamper with the message such that sender lookup fails
    let mut msg_invalid_sender = mls_message;
    let random_sender = Sender::build_member(LeafNodeIndex::new(987543210));
    match &mut msg_invalid_sender.body {
        MlsMessageOutBody::PublicMessage(pt) => {
            pt.set_sender(random_sender);
            pt.set_membership_tag(backend, membership_key).unwrap()
        }
        _ => panic!("This should be a plaintext!"),
    };

    drop(client_groups);
    drop(client);
    drop(clients);

    let error = setup
        // We're the "no_client" id to prevent the original sender from treating
        // this message as his own and merging the pending commit.
        .distribute_to_members("no_client".as_bytes(), group, &msg_invalid_signature.into())
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
        .distribute_to_members("no_client".as_bytes(), group, &msg_invalid_sender.into())
        .expect_err("No error when distributing message with invalid signature.");

    assert_eq!(
        ClientError::ProcessMessageError(ProcessMessageError::ValidationError(
            ValidationError::UnknownMember
        )),
        error
    );
}

#[apply(ciphersuites_and_backends)]
fn test_pending_commit_logic(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        backend,
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    )
    .expect("An unexpected error occurred.");

    let bob_credential = generate_credential_bundle(
        backend,
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package(backend, &[ciphersuite], &alice_credential, vec![]);

    let bob_key_package = generate_key_package(backend, &[ciphersuite], &bob_credential, vec![]);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package.leaf_node().signature_key(),
    )
    .expect("An unexpected error occurred.");

    // There should be no pending commit after group creation.
    assert!(alice_group.pending_commit().is_none());

    // Let's add bob
    let proposal = alice_group
        .propose_add_member(backend, &bob_key_package)
        .expect("error creating self-update proposal");

    let alice_processed_message = alice_group
        .process_message(backend, proposal.into_protocol_message().unwrap())
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
    let (_msg, _welcome_option) = alice_group
        .self_update(backend, None)
        .expect("error creating self-update commit");
    println!("Done creating commit.");

    // There should be a pending commit after issueing a proposal.
    assert!(alice_group.pending_commit().is_some());

    // If there is a pending commit, other commit- or proposal-creating actions
    // should fail.
    let error = alice_group
        .add_members(backend, &[bob_key_package.clone()])
        .expect_err("no error committing while a commit is pending");
    assert_eq!(
        error,
        AddMembersError::GroupStateError(MlsGroupStateError::PendingCommit)
    );
    let error = alice_group
        .propose_add_member(backend, &bob_key_package)
        .expect_err("no error creating a proposal while a commit is pending");
    assert_eq!(
        error,
        ProposeAddMemberError::GroupStateError(MlsGroupStateError::PendingCommit)
    );
    let error = alice_group
        .remove_members(backend, &[LeafNodeIndex::new(1)])
        .expect_err("no error committing while a commit is pending");
    assert_eq!(
        error,
        RemoveMembersError::GroupStateError(MlsGroupStateError::PendingCommit)
    );
    let error = alice_group
        .propose_remove_member(backend, LeafNodeIndex::new(1))
        .expect_err("no error creating a proposal while a commit is pending");
    assert_eq!(
        error,
        ProposeRemoveMemberError::GroupStateError(MlsGroupStateError::PendingCommit)
    );
    let error = alice_group
        .commit_to_pending_proposals(backend)
        .expect_err("no error committing while a commit is pending");
    assert_eq!(
        error,
        CommitToPendingProposalsError::GroupStateError(MlsGroupStateError::PendingCommit)
    );
    let error = alice_group
        .self_update(backend, None)
        .expect_err("no error committing while a commit is pending");
    assert_eq!(
        error,
        SelfUpdateError::GroupStateError(MlsGroupStateError::PendingCommit)
    );
    let error = alice_group
        .propose_self_update(backend, None)
        .expect_err("no error creating a proposal while a commit is pending");
    assert_eq!(
        error,
        ProposeSelfUpdateError::GroupStateError(MlsGroupStateError::PendingCommit)
    );

    // Clearing the pending commit should actually clear it.
    alice_group.clear_pending_commit();
    assert!(alice_group.pending_commit().is_none());

    // Creating a new commit should commit the same proposals.
    let (_msg, welcome_option) = alice_group
        .self_update(backend, None)
        .expect("error creating self-update commit");

    // Merging the pending commit should clear the pending commit and we should
    // end up in the same state as bob.
    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");
    assert!(alice_group.pending_commit().is_none());

    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome_option
            .expect("no welcome after commit")
            .into_welcome()
            .expect("Unexpected message type."),
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("error creating group from welcome");

    assert_eq!(
        bob_group.export_ratchet_tree(),
        alice_group.export_ratchet_tree()
    );
    assert_eq!(
        bob_group.export_secret(backend, "test", &[], ciphersuite.hash_length()),
        alice_group.export_secret(backend, "test", &[], ciphersuite.hash_length())
    );

    // While a commit is pending, merging Bob's commit should clear the pending commit.
    let (_msg, _welcome_option) = alice_group
        .self_update(backend, None)
        .expect("error creating self-update commit");

    let (msg, _welcome_option) = bob_group
        .self_update(backend, None)
        .expect("error creating self-update commit");

    let alice_processed_message = alice_group
        .process_message(backend, msg.into_protocol_message().unwrap())
        .expect("Could not process messages.");
    assert!(alice_group.pending_commit().is_some());

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group.merge_staged_commit(*staged_commit);
    } else {
        unreachable!("Expected a StagedCommit.");
    }
    assert!(alice_group.pending_commit().is_none());
}

// Test that the key package and the corresponding private key are deleted when
// creating a new group for a welcome message.
#[apply(ciphersuites_and_backends)]
fn key_package_deletion(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        backend,
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    )
    .expect("An unexpected error occurred.");

    let bob_credential = generate_credential_bundle(
        backend,
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package(backend, &[ciphersuite], &alice_credential, vec![]);

    let bob_key_package = generate_key_package(backend, &[ciphersuite], &bob_credential, vec![]);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfigBuilder::new()
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package.leaf_node().signature_key(),
    )
    .unwrap();

    // === Alice adds Bob ===
    let (_queued_message, welcome) = alice_group
        .add_members(backend, &[bob_key_package.clone()])
        .unwrap();

    alice_group.merge_pending_commit().unwrap();

    // === Bob joins the group ===
    let _bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome.into_welcome().expect("Unexpected message type."),
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    // TEST: The private key must be gone from the key store.
    assert!(backend
        .key_store()
        .read::<Vec<u8>>(bob_key_package.hpke_init_key().as_slice())
        .is_none(),
        "The HPKE private key is still in the key store after creating a new group from the key package.");

    // TEST: The key package must be gone from the key store.
    assert!(
        backend
            .key_store()
            .read::<KeyPackage>(
                bob_key_package
                    .hash_ref(backend.crypto())
                    .unwrap()
                    .as_slice()
            )
            .is_none(),
        "The key package is still in the key store after creating a new group from it."
    );
}
