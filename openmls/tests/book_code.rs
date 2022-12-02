use openmls::{prelude::*, test_utils::*, *};

use lazy_static::lazy_static;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme, OpenMlsCryptoProvider};
use std::fs::File;

lazy_static! {
    static ref TEMP_DIR: tempfile::TempDir =
        tempfile::tempdir().expect("Error creating temp directory");
}

#[test]
fn create_backend_rust_crypto() {
    // ANCHOR: create_backend_rust_crypto
    use openmls_rust_crypto::OpenMlsRustCrypto;

    let backend = OpenMlsRustCrypto::default();
    // ANCHOR_END: create_backend_rust_crypto

    // Suppress warning.
    let _backend = backend;
}

#[cfg(feature = "evercrypt")]
#[test]
fn create_backend_evercrypt() {
    // ANCHOR: create_backend_evercrypt
    use openmls_evercrypt::OpenMlsEvercrypt;

    let backend = OpenMlsEvercrypt::default();
    // ANCHOR_END: create_backend_evercrypt

    // Suppress warning.
    let _backend = backend;
}

fn generate_credential_bundle(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<Credential, CredentialError> {
    // ANCHOR: create_credential_bundle
    let credential_bundle =
        CredentialBundle::new(identity, credential_type, signature_algorithm, backend)?;
    // ANCHOR_END: create_credential_bundle
    // ANCHOR: store_credential_bundle
    let credential = credential_bundle.credential().clone();
    backend
        .key_store()
        .store(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
            &credential_bundle,
        )
        .expect("An unexpected error occurred.");
    // ANCHOR_END: store_credential_bundle
    Ok(credential)
}

fn get_credential_bundle(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<CredentialBundle, CredentialError> {
    let credential_bundle =
        CredentialBundle::new(identity, credential_type, signature_algorithm, backend)?;
    let credential = credential_bundle.credential().clone();
    backend
        .key_store()
        .store(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
            &credential_bundle,
        )
        .expect("An unexpected error occurred.");
    Ok(credential_bundle)
}

fn generate_key_package_bundle(
    ciphersuite: Ciphersuite,
    credential: &Credential,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<KeyPackage, KeyPackageBundleNewError> {
    // ANCHOR: create_key_package_bundle
    // Define extensions
    let lifetime = Lifetime::new(
        60 * 60 * 24 * 90, // Maximum lifetime of 90 days, expressed in seconds
    );

    // Fetch the credential bundle from the key store
    let credential_bundle = backend
        .key_store()
        .read(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
        )
        .expect("An unexpected error occurred.");

    // Create the key package bundle
    let key_package_bundle =
        KeyPackageBundle::new(ciphersuite, &credential_bundle, backend, lifetime, vec![])?;
    // ANCHOR_END: create_key_package_bundle
    // ANCHOR: store_key_package_bundle
    let key_package = key_package_bundle.key_package().clone();

    // Store it in the key store
    backend
        .key_store()
        .store(
            key_package
                .hash_ref(backend.crypto())
                .expect("Could not hash KeyPackage.")
                .as_slice(),
            &key_package_bundle,
        )
        .expect("An unexpected error occurred.");
    // ANCHOR_END: store_key_package_bundle
    Ok(key_package)
}

/// This test simulates various group operations like Add, Update, Remove in a
/// small group
///  - Alice creates a group
///  - Alice adds Bob
///  - Alice sends a message to Bob
///  - Bob updates and commits
///  - Alice updates and commits
///  - Bob adds Charlie
///  - Charlie sends a message to the group
///  - Charlie updates and commits
///  - Charlie removes Bob
///  - Alice removes Charlie and adds Bob
///  - Bob leaves
///  - Test saving the group state
#[apply(ciphersuites_and_backends)]
fn book_operations(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let bob_credential = generate_credential_bundle(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let charlie_credential = generate_credential_bundle(
        "Charlie".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package = generate_key_package_bundle(ciphersuite, &alice_credential, backend)
        .expect("An unexpected error occurred.");

    let bob_key_package = generate_key_package_bundle(ciphersuite, &bob_credential, backend)
        .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration
    // ANCHOR: mls_group_config_example
    let mls_group_config = MlsGroupConfig::builder()
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            10,   // out_of_order_tolerance
            2000, // maximum_forward_distance
        ))
        .use_ratchet_tree_extension(true)
        .build();
    // ANCHOR_END: mls_group_config_example

    // ANCHOR: alice_create_group
    let mut alice_group = MlsGroup::new(
        backend,
        &mls_group_config,
        alice_key_package
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice(),
    )
    .expect("An unexpected error occurred.");
    // ANCHOR_END: alice_create_group

    {
        // Note: This is required because the previous call to `MlsGroup::new()` deletes the other
        // key package bundle and `MlsGroup::new_with_group_id` would fail.
        let alice_key_package =
            generate_key_package_bundle(ciphersuite, &alice_credential, backend)
                .expect("An unexpected error occurred.");

        // ANCHOR: alice_create_group_with_group_id
        // Some specific group ID generated by someone else.
        let group_id = GroupId::from_slice(b"123e4567e89b");

        let mut alice_group = MlsGroup::new_with_group_id(
            backend,
            &mls_group_config,
            group_id,
            alice_key_package
                .hash_ref(backend.crypto())
                .expect("Could not hash KeyPackage.")
                .as_slice(),
        )
        .expect("An unexpected error occurred.");
        // ANCHOR_END: alice_create_group_with_group_id

        // Silence "unused variable" and "does not need to be mutable" warnings.
        let _ignore_mut_warning = &mut alice_group;
    }

    // === Alice adds Bob ===
    // ANCHOR: alice_adds_bob
    let (mls_message_out, welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add members.");
    // ANCHOR_END: alice_adds_bob

    // Suppress warning
    let _mls_message_out = mls_message_out;

    // Check that we received the correct proposals
    if let Some(staged_commit) = alice_group.pending_commit() {
        let add = staged_commit
            .add_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was added
        assert_eq!(
            add.add_proposal().key_package().credential(),
            &bob_credential
        );
        // Check that Alice added Bob
        assert!(matches!(
            add.sender(),
            Sender::Member(member) if *member == alice_group.own_leaf_index()
        ));
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    // Check that the group now has two members
    assert_eq!(
        alice_group
            .members()
            .expect("Library error getting group member list")
            .len(),
        2
    );

    // Check that Alice & Bob are the members of the group
    let members = alice_group
        .members()
        .expect("Library error getting group member list");
    assert_eq!(members[0].identity, b"Alice");
    assert_eq!(members[1].identity, b"Bob");

    // ANCHOR: bob_joins_with_welcome
    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome,
        None, // We use the ratchet tree extension, so we don't provide a ratchet tree here
    )
    .expect("Error joining group from Welcome");
    // ANCHOR_END: bob_joins_with_welcome

    // Make sure that both groups have the same members
    assert_eq!(
        alice_group
            .members()
            .expect("Library error getting group member list"),
        bob_group
            .members()
            .expect("Library error getting group member list")
    );

    // Make sure that both groups have the same epoch authenticator
    assert_eq!(
        alice_group.epoch_authenticator().as_slice(),
        bob_group.epoch_authenticator().as_slice()
    );

    // === Alice sends a message to Bob ===
    // ANCHOR: create_application_message
    let message_alice = b"Hi, I'm Alice!";
    let mls_message_out = alice_group
        .create_message(backend, message_alice)
        .expect("Error creating application message.");
    // ANCHOR_END: create_application_message

    // Message serialization

    let bytes = mls_message_out
        .to_bytes()
        .expect("Could not serialize message.");

    // ANCHOR: mls_message_in_from_bytes
    let mls_message_in =
        MlsMessageIn::try_from_bytes(&bytes).expect("Could not deserialize message.");
    // ANCHOR_END: mls_message_in_from_bytes

    // ANCHOR: process_message
    let processed_message = bob_group
        .process_message(backend, mls_message_in)
        .expect("Could not process message.");
    // ANCHOR_END: process_message

    // Check that we received the correct message
    // ANCHOR: inspect_application_message
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    {
        // Check the message
        assert_eq!(application_message.into_bytes(), b"Hi, I'm Alice!");
    }
    // ANCHOR_END: inspect_application_message
    else {
        unreachable!("Expected an ApplicationMessage.");
    }

    // === Bob updates and commits ===
    // ANCHOR: self_update
    let (mls_message_out, welcome_option) = bob_group
        .self_update(
            backend,
            None, // We don't provide a key package, it will be created on the fly instead
        )
        .expect("Could not update own key package.");
    // ANCHOR_END: self_update

    let alice_processed_message = alice_group
        .process_message(backend, mls_message_out.into())
        .expect("Could not process message.");

    // Check that we received the correct message
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        let update = staged_commit
            .commit_update_key_package()
            .expect("Expected a KeyPackage.");
        // Check that Bob updated
        assert_eq!(update.credential(), &bob_credential);

        // Merge staged Commit
        alice_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge Commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    bob_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    // Check we didn't receive a Welcome message
    assert!(welcome_option.is_none());

    // Check that both groups have the same state
    assert_eq!(
        alice_group.export_secret(backend, "", &[], 32),
        bob_group.export_secret(backend, "", &[], 32)
    );

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // === Alice updates and commits ===
    // ANCHOR: propose_self_update
    let mls_message_out = alice_group
        .propose_self_update(
            backend,
            None, // We don't provide a key package, it will be created on the fly instead
        )
        .expect("Could not create update proposal.");
    // ANCHOR_END: propose_self_update

    let bob_processed_message = bob_group
        .process_message(backend, mls_message_out.into())
        .expect("Could not process message.");

    // Check that we received the correct proposals
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        bob_processed_message.into_content()
    {
        if let Proposal::Update(ref update_proposal) = staged_proposal.proposal() {
            // Check that Alice updated
            assert_eq!(update_proposal.leaf_node().credential(), &alice_credential);
            // Store proposal
            alice_group.store_pending_proposal(*staged_proposal.clone());
        } else {
            unreachable!("Expected a Proposal.");
        }

        // Check that Alice sent the proposal
        assert!(matches!(
            staged_proposal.sender(),
            Sender::Member(member) if *member == alice_group.own_leaf_index()
        ));
        bob_group.store_pending_proposal(*staged_proposal);
    } else {
        unreachable!("Expected a QueuedProposal.");
    }

    // ANCHOR: commit_to_proposals
    let (mls_message_out, welcome_option) = alice_group
        .commit_to_pending_proposals(backend)
        .expect("Could not commit to pending proposals.");
    // ANCHOR_END: commit_to_proposals

    // Suppress warning
    let _welcome_option = welcome_option;

    let bob_processed_message = bob_group
        .process_message(backend, mls_message_out.into())
        .expect("Could not process message.");

    // Check that we received the correct message
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        let update = staged_commit
            .commit_update_key_package()
            .expect("Expected a KeyPackage.");
        // Check that Alice updated
        assert_eq!(update.credential(), &alice_credential);

        bob_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge StagedCommit");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    // Check that both groups have the same state
    assert_eq!(
        alice_group.export_secret(backend, "", &[], 32),
        bob_group.export_secret(backend, "", &[], 32)
    );

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // === Bob adds Charlie ===
    let charlie_key_package =
        generate_key_package_bundle(ciphersuite, &charlie_credential, backend)
            .expect("An unexpected error occurred.");

    let (queued_message, welcome) = match bob_group.add_members(backend, &[charlie_key_package]) {
        Ok((qm, welcome)) => (qm, welcome),
        Err(e) => panic!("Could not add member to group: {:?}", e),
    };

    let alice_processed_message = alice_group
        .process_message(backend, queued_message.into())
        .expect("Could not process message.");
    bob_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge StagedCommit");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    let mut charlie_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome,
        Some(bob_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree(),
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // Check that Alice, Bob & Charlie are the members of the group
    let members = alice_group
        .members()
        .expect("Library error getting group member list");
    assert_eq!(members[0].identity, b"Alice");
    assert_eq!(members[1].identity, b"Bob");
    assert_eq!(members[2].identity, b"Charlie");
    assert_eq!(members.len(), 3);

    // === Charlie sends a message to the group ===
    let message_charlie = b"Hi, I'm Charlie!";
    let queued_message = charlie_group
        .create_message(backend, message_charlie)
        .expect("Error creating application message");

    let _alice_processed_message = alice_group
        .process_message(backend, queued_message.clone().into())
        .expect("Could not process message.");
    let _bob_processed_message = bob_group
        .process_message(backend, queued_message.into())
        .expect("Could not process message.");

    // === Charlie updates and commits ===
    let (queued_message, welcome_option) = match charlie_group.self_update(backend, None) {
        Ok(qm) => qm,
        Err(e) => panic!("Error performing self-update: {:?}", e),
    };

    let alice_processed_message = alice_group
        .process_message(backend, queued_message.clone().into())
        .expect("Could not process message.");
    let bob_processed_message = bob_group
        .process_message(backend, queued_message.into())
        .expect("Could not process message.");
    charlie_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge StagedCommit");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        bob_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge StagedCommit");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check we didn't receive a Welcome message
    assert!(welcome_option.is_none());

    // Check that all groups have the same state
    assert_eq!(
        alice_group.export_secret(backend, "", &[], 32),
        bob_group.export_secret(backend, "", &[], 32)
    );
    assert_eq!(
        alice_group.export_secret(backend, "", &[], 32),
        charlie_group.export_secret(backend, "", &[], 32)
    );

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree(),
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // ANCHOR: retrieve_members
    let charlie_members = charlie_group
        .members()
        .expect("Library error getting group member list");
    // ANCHOR_END: retrieve_members

    let bob_member = charlie_members
        .iter()
        .find(
            |Member {
                 index: _, identity, ..
             }| identity == b"Bob",
        )
        .expect("Couldn't find Bob in the list of group members.");

    // Make sure that this is Bob's actual KP reference.
    assert_eq!(
        bob_member.identity,
        bob_group
            .own_identity()
            .expect("An unexpected error occurred.")
    );

    // === Charlie removes Bob ===
    // ANCHOR: charlie_removes_bob
    let (mls_message_out, welcome_option) = charlie_group
        .remove_members(backend, &[bob_member.index])
        .expect("Could not remove Bob from group.");
    // ANCHOR_END: charlie_removes_bob

    // Check that Bob's group is still active
    assert!(bob_group.is_active());

    let alice_processed_message = alice_group
        .process_message(backend, mls_message_out.clone().into())
        .expect("Could not process message.");

    // Check that alice can use the member list to check if the message is
    // actually from Charlie.
    let alice_members = alice_group
        .members()
        .expect("Library error getting group member list");
    let sender_credential = alice_processed_message
        .credential()
        .expect("Couldn't retrieve credential from message.");

    assert!(alice_members.iter().any(
        |Member {
             index: _,
             identity: _,
             encryption_key: _,
             signature_key,
         }| signature_key.as_slice() == sender_credential.signature_key().as_slice()
    ));

    assert_eq!(sender_credential, &charlie_credential);

    let bob_processed_message = bob_group
        .process_message(backend, mls_message_out.into())
        .expect("Could not process message.");
    let charlies_leaf_index = charlie_group.own_leaf_index();
    charlie_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    // Check that we receive the correct proposal for Alice
    // ANCHOR: inspect_staged_commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        // We expect a remove proposal
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        assert_eq!(
            remove.remove_proposal().removed(),
            bob_group.own_leaf_index()
        );
        // Check that Charlie removed Bob
        assert!(matches!(
            remove.sender(),
            Sender::Member(member) if *member == charlies_leaf_index
        ));
        // Merge staged commit
        alice_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge Commit.");
    }
    // ANCHOR_END: inspect_staged_commit
    else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check that we receive the correct proposal for Bob
    // ANCHOR: remove_operation
    // ANCHOR: getting_removed
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        let remove_proposal = staged_commit
            .remove_proposals()
            .next()
            .expect("An unexpected error occurred.");

        // We construct a RemoveOperation enum to help us interpret the remove operation
        let remove_operation = RemoveOperation::new(remove_proposal, &bob_group)
            .expect("An unexpected Error occurred.");

        match remove_operation {
            RemoveOperation::WeLeft => unreachable!(),
            // We expect this variant, since Bob was removed by Charlie
            RemoveOperation::WeWereRemovedBy(member) => {
                assert!(matches!(member, Sender::Member(member) if member == charlies_leaf_index));
            }
            RemoveOperation::TheyLeft(_) => unreachable!(),
            RemoveOperation::TheyWereRemovedBy(_) => unreachable!(),
            RemoveOperation::WeRemovedThem(_) => unreachable!(),
        }

        // Merge staged Commit
        bob_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge Commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }
    // ANCHOR_END: remove_operation

    // Check we didn't receive a Welcome message
    assert!(welcome_option.is_none());

    // Check that Bob's group is no longer active
    assert!(!bob_group.is_active());
    let members = bob_group
        .members()
        .expect("Library error getting group member list");
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].identity, b"Alice");
    assert_eq!(members[1].identity, b"Charlie");
    // ANCHOR_END: getting_removed

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // Make sure the group only contains two members
    assert_eq!(
        alice_group
            .members()
            .expect("Library error getting group member list")
            .len(),
        2
    );

    // Check that Alice & Charlie are the members of the group
    let members = alice_group
        .members()
        .expect("Library error getting group member list");
    assert_eq!(members[0].identity, b"Alice");
    assert_eq!(members[1].identity, b"Charlie");

    // Check that Bob can no longer send messages
    assert!(bob_group
        .create_message(backend, b"Should not go through")
        .is_err());

    // === Alice removes Charlie and re-adds Bob ===

    // Create a new KeyPackageBundle for Bob
    let bob_key_package = generate_key_package_bundle(ciphersuite, &bob_credential, backend)
        .expect("An unexpected error occurred.");

    // Create RemoveProposal and process it
    // ANCHOR: propose_remove
    let mls_message_out = alice_group
        .propose_remove_member(backend, charlie_group.own_leaf_index())
        .expect("Could not create proposal to remove Charlie.");
    // ANCHOR_END: propose_remove

    let charlie_processed_message = charlie_group
        .process_message(backend, mls_message_out.into())
        .expect("Could not process message.");

    // Check that we received the correct proposals
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        charlie_processed_message.into_content()
    {
        if let Proposal::Remove(ref remove_proposal) = staged_proposal.proposal() {
            // Check that Charlie was removed
            assert_eq!(remove_proposal.removed(), charlie_group.own_leaf_index());
            // Store proposal
            charlie_group.store_pending_proposal(*staged_proposal.clone());
        } else {
            unreachable!("Expected a Proposal.");
        }

        // Check that Alice removed Charlie
        assert!(matches!(
            staged_proposal.sender(),
            Sender::Member(member) if *member == alice_group.own_leaf_index()
        ));
    } else {
        unreachable!("Expected a QueuedProposal.");
    }

    // Create AddProposal and process it
    // ANCHOR: propose_add
    let mls_message_out = alice_group
        .propose_add_member(backend, &bob_key_package)
        .expect("Could not create proposal to add Bob");
    // ANCHOR_END: propose_add

    let charlie_processed_message = charlie_group
        .process_message(backend, mls_message_out.into())
        .expect("Could not process message.");

    // Check that we received the correct proposals
    // ANCHOR: inspect_add_proposal
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        charlie_processed_message.into_content()
    {
        // In the case we received an Add Proposal
        if let Proposal::Add(add_proposal) = staged_proposal.proposal() {
            // Check that Bob was added
            assert_eq!(add_proposal.key_package().credential(), &bob_credential);
        } else {
            panic!("Expected an AddProposal.");
        }

        // Check that Alice added Bob
        assert!(matches!(
            staged_proposal.sender(),
            Sender::Member(member) if *member == alice_group.own_leaf_index()
        ));
        // Store proposal
        charlie_group.store_pending_proposal(*staged_proposal);
    }
    // ANCHOR_END: inspect_add_proposal
    else {
        unreachable!("Expected a QueuedProposal.");
    }

    // Commit to the proposals and process it
    let (queued_message, welcome_option) = alice_group
        .commit_to_pending_proposals(backend)
        .expect("Could not flush proposals");

    let charlie_processed_message = charlie_group
        .process_message(backend, queued_message.into())
        .expect("Could not process message.");

    // Merge Commit
    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        charlie_processed_message.into_content()
    {
        charlie_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge StagedCommit");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Make sure the group contains two members
    assert_eq!(
        alice_group
            .members()
            .expect("Library error getting group member list")
            .len(),
        2
    );

    // Check that Alice & Bob are the members of the group
    let members = alice_group
        .members()
        .expect("Library error getting group member list");
    assert_eq!(members[0].identity, b"Alice");
    assert_eq!(members[1].identity, b"Bob");

    // Bob creates a new group
    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome_option.expect("Welcome was not returned"),
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    // Make sure the group contains two members
    assert_eq!(
        alice_group
            .members()
            .expect("Library error getting group member list")
            .len(),
        2
    );

    // Check that Alice & Bob are the members of the group
    let members = alice_group
        .members()
        .expect("Library error getting group member list");
    assert_eq!(members[0].identity, b"Alice");
    assert_eq!(members[1].identity, b"Bob");

    // Make sure the group contains two members
    assert_eq!(
        bob_group
            .members()
            .expect("Library error getting group member list")
            .len(),
        2
    );

    // Check that Alice & Bob are the members of the group
    let members = bob_group
        .members()
        .expect("Library error getting group member list");
    assert_eq!(members[0].identity, b"Alice");
    assert_eq!(members[1].identity, b"Bob");

    // === Alice sends a message to the group ===
    let message_alice = b"Hi, I'm Alice!";
    let queued_message = alice_group
        .create_message(backend, message_alice)
        .expect("Error creating application message");

    let bob_processed_message = bob_group
        .process_message(backend, queued_message.into())
        .expect("Could not process message.");

    // Get sender information
    // As provided by the processed message
    let sender_cred_from_msg = bob_processed_message
        .credential()
        .expect("Expected a credential.")
        .clone();

    // As provided by looking up the sender manually via the `member()` function
    // ANCHOR: member_lookup
    let sender_cred_from_group =
        if let Sender::Member(sender_index) = bob_processed_message.sender() {
            bob_group
                .member(*sender_index)
                .expect("Could not find sender in group.")
                .clone()
        } else {
            unreachable!("Expected sender type to be `Member`.")
        };
    // ANCHOR_END: member_lookup

    // Check that we received the correct message
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        bob_processed_message.into_content()
    {
        // Check the message
        assert_eq!(application_message.into_bytes(), message_alice);
        // Check that Alice sent the message
        assert_eq!(sender_cred_from_msg, sender_cred_from_group);
        assert_eq!(
            &sender_cred_from_msg,
            alice_group.credential().expect("Expected a credential.")
        );
    } else {
        unreachable!("Expected an ApplicationMessage.");
    }

    // === Bob leaves the group ===

    // ANCHOR: leaving
    let queued_message = bob_group
        .leave_group(backend)
        .expect("Could not leave group");
    // ANCHOR_END: leaving

    let alice_processed_message = alice_group
        .process_message(backend, queued_message.into())
        .expect("Could not process message.");

    // Store proposal
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        alice_processed_message.into_content()
    {
        // Store proposal
        alice_group.store_pending_proposal(*staged_proposal);
    } else {
        unreachable!("Expected a QueuedProposal.");
    }

    // Should fail because you cannot remove yourself from a group
    assert_eq!(
        bob_group.commit_to_pending_proposals(backend,),
        Err(CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::CannotRemoveSelf
        ))
    );

    let (queued_message, _welcome_option) = alice_group
        .commit_to_pending_proposals(backend)
        .expect("Could not commit to proposals.");

    // Check that Bob's group is still active
    assert!(bob_group.is_active());

    // Check that we received the correct proposals
    if let Some(staged_commit) = alice_group.pending_commit() {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        assert_eq!(
            remove.remove_proposal().removed(),
            bob_group.own_leaf_index()
        );
        // Check that Bob removed himself
        assert!(matches!(
            remove.sender(),
            Sender::Member(member) if *member == bob_group.own_leaf_index()
        ));
        // Merge staged Commit
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    alice_group
        .merge_pending_commit()
        .expect("Could not merge Commit.");

    let bob_processed_message = bob_group
        .process_message(backend, queued_message.into())
        .expect("Could not process message.");

    // Check that we received the correct proposals
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        assert_eq!(
            remove.remove_proposal().removed(),
            bob_group.own_leaf_index()
        );
        // Check that Bob removed himself
        assert!(matches!(
            remove.sender(),
            Sender::Member(member) if *member == bob_group.own_leaf_index()
        ));
        assert!(staged_commit.self_removed());
        // Merge staged Commit
        bob_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge Commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check that Bob's group is no longer active
    assert!(!bob_group.is_active());

    // Make sure the group contains one member
    assert_eq!(
        alice_group
            .members()
            .expect("Library error getting group member list")
            .len(),
        1
    );

    // Check that Alice is the only member of the group
    let members = alice_group
        .members()
        .expect("Library error getting group member list");
    assert_eq!(members[0].identity, b"Alice");

    // === Re-Add Bob with external Add proposal ===

    // Create a new KeyPackageBundle for Bob
    let bob_credential_bundle = get_credential_bundle(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("Could not get CredentialBundle");
    let bob_key_package =
        generate_key_package_bundle(ciphersuite, bob_credential_bundle.credential(), backend)
            .expect("An unexpected error occurred.");

    // ANCHOR: external_join_proposal
    let proposal = JoinProposal::new(
        bob_key_package,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &bob_credential_bundle,
        backend,
    )
    .expect("Could not create external Add proposal");
    // ANCHOR_END: external_join_proposal

    // ANCHOR: decrypt_external_join_proposal
    let alice_processed_message = alice_group
        .process_message(backend, proposal.into())
        .expect("Could not process message.");
    match alice_processed_message.into_content() {
        ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
            alice_group.store_pending_proposal(*proposal);
            let (_commit, welcome) = alice_group
                .commit_to_pending_proposals(backend)
                .expect("Could not commit");
            assert_eq!(alice_group.members().unwrap().len(), 1);
            alice_group
                .merge_pending_commit()
                .expect("Could not merge commit");
            assert_eq!(alice_group.members().unwrap().len(), 2);

            let bob_group =
                MlsGroup::new_from_welcome(backend, &mls_group_config, welcome.unwrap(), None)
                    .expect("Bob could not join the group");
            assert_eq!(bob_group.members().unwrap().len(), 2);
        }
        _ => unreachable!(),
    }
    // ANCHOR_END: decrypt_external_join_proposal
    // now cleanup
    alice_group
        .remove_members(backend, &[1])
        .expect("Could not remove Bob");
    alice_group
        .merge_pending_commit()
        .expect("Could not nerge commit");
    assert_eq!(alice_group.members().unwrap().len(), 1);

    // === Save the group state ===

    // Create a new KeyPackageBundle for Bob
    let bob_key_package = generate_key_package_bundle(ciphersuite, &bob_credential, backend)
        .expect("An unexpected error occurred.");

    // Add Bob to the group
    let (_queued_message, welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add Bob");

    // Merge Commit
    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("Could not create group from Welcome");

    assert_eq!(
        alice_group.export_secret(backend, "before load", &[], 32),
        bob_group.export_secret(backend, "before load", &[], 32)
    );

    // Check that the state flag gets reset when saving
    assert_eq!(bob_group.state_changed(), InnerState::Changed);
    //save(&mut bob_group);

    let name = bytes_to_hex(
        bob_group
            .credential()
            .expect("An unexpected error occurred.")
            .signature_key()
            .as_slice(),
    )
    .to_lowercase();
    let path = TEMP_DIR
        .path()
        .join(format!("test_mls_group_{}.json", &name));
    let out_file = &mut File::create(path.clone()).expect("Could not create file");
    bob_group
        .save(out_file)
        .expect("Could not write group state to file");

    // Check that the state flag gets reset when saving
    assert_eq!(bob_group.state_changed(), InnerState::Persisted);

    let file = File::open(path).expect("Could not open file");
    let bob_group = MlsGroup::load(file).expect("Could not load group from file");

    // Make sure the state is still the same
    assert_eq!(
        alice_group.export_secret(backend, "after load", &[], 32),
        bob_group.export_secret(backend, "after load", &[], 32)
    );
}

#[apply(ciphersuites_and_backends)]
fn test_empty_input_errors(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package = generate_key_package_bundle(ciphersuite, &alice_credential, backend)
        .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::test_default();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice(),
    )
    .expect("An unexpected error occurred.");

    assert_eq!(
        alice_group
            .add_members(backend, &[])
            .expect_err("No EmptyInputError when trying to pass an empty slice to `add_members`."),
        AddMembersError::EmptyInput(EmptyInputError::AddMembers)
    );
    assert_eq!(
        alice_group.remove_members(backend, &[]).expect_err(
            "No EmptyInputError when trying to pass an empty slice to `remove_members`."
        ),
        RemoveMembersError::EmptyInput(EmptyInputError::RemoveMembers)
    );
}
