use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme, OpenMlsCryptoProvider};
use tls_codec::Serialize;

use crate::{
    ciphersuite::hash_ref::KeyPackageRef,
    credentials::{errors::CredentialError, *},
    framing::*,
    group::{errors::*, *},
    key_packages::{errors::*, *},
    messages::proposals::*,
    test_utils::test_framework::{
        errors::ClientError, ActionType::Commit, CodecUse, MlsGroupTestSetup,
    },
    test_utils::*,
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

fn generate_key_package_bundle(
    key_store: &impl OpenMlsCryptoProvider,
    ciphersuites: &[Ciphersuite],
    credential: &Credential,
    extensions: Vec<Extension>,
) -> Result<KeyPackage, KeyPackageBundleNewError> {
    let credential_bundle = key_store
        .key_store()
        .read(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
        )
        .expect("An unexpected error occurred.");
    let kpb = KeyPackageBundle::new(ciphersuites, &credential_bundle, key_store, extensions)?;
    let kp = kpb.key_package().clone();
    key_store
        .key_store()
        .store(
            kp.hash_ref(key_store.crypto())
                .expect("Could not hash KeyPackage.")
                .as_slice(),
            &kpb,
        )
        .expect("An unexpected error occurred.");
    Ok(kp)
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
        generate_key_package_bundle(backend, &[ciphersuite], &alice_credential, vec![])
            .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default();

    // === Alice creates a group ===

    let mut alice_group = MlsGroup::new(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice(),
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
        generate_key_package_bundle(backend, &[ciphersuite], &alice_credential, vec![])
            .expect("An unexpected error occurred.");

    let bob_key_package =
        generate_key_package_bundle(backend, &[ciphersuite], &bob_credential, vec![])
            .expect("An unexpected error occurred.");

    let charlie_key_package =
        generate_key_package_bundle(backend, &[ciphersuite], &charlie_credential, vec![])
            .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::default();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice(),
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
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    // === Bob adds Charlie ===
    let (queued_messages, welcome) = match bob_group.add_members(backend, &[charlie_key_package]) {
        Ok((qm, welcome)) => (qm, welcome),
        Err(e) => panic!("Could not add member to group: {:?}", e),
    };

    let unverified_message = alice_group
        .parse_message(queued_messages.into(), backend)
        .expect("Could not parse message.");
    let alice_processed_message = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Could not process unverified message.");
    if let ProcessedMessage::StagedCommitMessage(staged_commit) = alice_processed_message {
        alice_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge StagedCommit");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    bob_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    let mut charlie_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome,
        Some(bob_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    // === Alice removes Bob & Charlie commits ===

    let bob_kpr = bob_group
        .key_package_ref()
        .expect("Error getting key package reference.");
    let alice_kpr = &alice_group
        .key_package_ref()
        .expect("An unexpected error occurred.")
        .clone();
    let queued_messages = alice_group
        .propose_remove_member(backend, bob_kpr)
        .expect("Could not propose removal");

    let unverified_message = charlie_group
        .parse_message(queued_messages.into(), backend)
        .expect("Could not parse message.");
    let charlie_processed_message = charlie_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Could not process unverified message.");

    // Check that we received the correct proposals
    if let ProcessedMessage::ProposalMessage(staged_proposal) = charlie_processed_message {
        if let Proposal::Remove(ref remove_proposal) = staged_proposal.proposal() {
            // Check that Bob was removed
            assert_eq!(remove_proposal.removed(), bob_kpr);
            // Store proposal
            charlie_group.store_pending_proposal(*staged_proposal.clone());
        } else {
            unreachable!("Expected a Proposal.");
        }

        // Check that Alice removed Bob
        assert!(matches!(
            staged_proposal.sender(),
            Sender::Member(member) if member == alice_kpr
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
        assert_eq!(remove.remove_proposal().removed(), bob_kpr);
        // Check that Alice removed Bob
        assert!(matches!(remove.sender(), Sender::Member(member) if member == alice_kpr));
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
        generate_key_package_bundle(backend, &[ciphersuite], &alice_credential, vec![])
            .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default();

    // === Alice creates a group ===
    let alice_group = MlsGroup::new(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice(),
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
    let mls_group_config = MlsGroupConfig::test_default();

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

    drop(client);
    drop(clients);

    // Tamper with the message such that signature verification fails
    // Once #574 is addressed the new function from there should be used to manipulate the signature.
    // Right now the membership tag is verified first, wihich yields `VerificationError::InvalidMembershipTag`
    // error instead of a `CredentialError:InvalidSignature`.
    let mut msg_invalid_signature = mls_message.clone();
    if let MlsMessage::Plaintext(ref mut pt) = msg_invalid_signature.mls_message {
        pt.invalidate_signature()
    };

    let error = setup
        // We're the "no_client" id to prevent the original sender from treating
        // this message as his own and merging the pending commit.
        .distribute_to_members("no_client".as_bytes(), group, &msg_invalid_signature)
        .expect_err("No error when distributing message with invalid signature.");

    assert_eq!(
        ClientError::UnverifiedMessageError(UnverifiedMessageError::InvalidMembershipTag),
        error
    );

    // Tamper with the message such that sender lookup fails
    let mut msg_invalid_sender = mls_message;
    let random_sender = Sender::build_member(&KeyPackageRef::from_slice(
        &backend
            .rand()
            .random_vec(16)
            .expect("An unexpected error occurred."),
    ));
    match &mut msg_invalid_sender.mls_message {
        MlsMessage::Plaintext(pt) => pt.set_sender(random_sender),
        MlsMessage::Ciphertext(_) => panic!("This should be a plaintext!"),
    };

    let error = setup
        // We're the "no_client" id to prevent the original sender from treating
        // this message as his own and merging the pending commit.
        .distribute_to_members("no_client".as_bytes(), group, &msg_invalid_sender)
        .expect_err("No error when distributing message with invalid signature.");

    assert_eq!(
        ClientError::ParseMessageError(ParseMessageError::ValidationError(
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
        generate_key_package_bundle(backend, &[ciphersuite], &alice_credential, vec![])
            .expect("An unexpected error occurred.");

    let bob_key_package =
        generate_key_package_bundle(backend, &[ciphersuite], &bob_credential, vec![])
            .expect("An unexpected error occurred.");

    let bob_kpr = KeyPackageRef::new(
        &bob_key_package
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
        ciphersuite,
        backend.crypto(),
    )
    .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice(),
    )
    .expect("An unexpected error occurred.");

    // There should be no pending commit after group creation.
    assert!(alice_group.pending_commit().is_none());

    // Let's add bob
    let proposal = alice_group
        .propose_add_member(backend, &bob_key_package)
        .expect("error creating self-update proposal");

    let unverified_message = alice_group
        .parse_message(proposal.into(), backend)
        .expect("An unexpected error occurred.");
    assert!(alice_group.pending_commit().is_none());

    let alice_processed_message = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("An unexpected error occurred.");
    assert!(alice_group.pending_commit().is_none());

    if let ProcessedMessage::ProposalMessage(staged_proposal) = alice_processed_message {
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
        .remove_members(backend, &[bob_kpr])
        .expect_err("no error committing while a commit is pending");
    assert_eq!(
        error,
        RemoveMembersError::GroupStateError(MlsGroupStateError::PendingCommit)
    );
    let error = alice_group
        .propose_remove_member(backend, &bob_kpr)
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
        welcome_option.expect("no welcome after commit"),
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

    let unverified_message = alice_group
        .parse_message(msg.into(), backend)
        .expect("An unexpected error occurred.");
    assert!(alice_group.pending_commit().is_some());

    let alice_processed_message = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("An unexpected error occurred.");
    assert!(alice_group.pending_commit().is_some());

    if let ProcessedMessage::StagedCommitMessage(staged_commit) = alice_processed_message {
        alice_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge StagedCommit");
    } else {
        unreachable!("Expected a StagedCommit.");
    }
    assert!(alice_group.pending_commit().is_none());
}
