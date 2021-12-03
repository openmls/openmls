use openmls::{
    group::{EmptyInputError, InnerState},
    prelude::*,
};

use lazy_static::lazy_static;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme, OpenMlsCryptoProvider};
use std::fs::File;

lazy_static! {
    static ref TEMP_DIR: tempfile::TempDir =
        tempfile::tempdir().expect("Error creating temp directory");
}

fn own_identity(managed_group: &ManagedGroup) -> Vec<u8> {
    match managed_group.credential() {
        Ok(credential) => credential.identity().to_vec(),
        Err(_) => "us".as_bytes().to_vec(),
    }
}

fn generate_credential_bundle(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_scheme: SignatureScheme,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<Credential, CredentialError> {
    let cb = CredentialBundle::new(identity, credential_type, signature_scheme, backend)?;
    let credential = cb.credential().clone();
    backend
        .key_store()
        .store(credential.signature_key(), &cb)
        .expect("An unexpected error occurred.");
    Ok(credential)
}

fn generate_key_package_bundle(
    ciphersuites: &[CiphersuiteName],
    credential: &Credential,
    extensions: Vec<Extension>,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<KeyPackage, KeyPackageError> {
    let credential_bundle = backend
        .key_store()
        .read(credential.signature_key())
        .expect("An unexpected error occurred.");
    let kpb = KeyPackageBundle::new(ciphersuites, &credential_bundle, backend, extensions)?;
    let kp = kpb.key_package().clone();
    backend
        .key_store()
        .store(&kp.hash(backend).expect("Could not hash KeyPackage."), &kpb)
        .expect("An unexpected error occurred.");
    Ok(kp)
}

/// Save the group state
/// `(managed_group: &ManagedGroup)`
fn save(managed_group: &mut ManagedGroup) {
    let name = String::from_utf8(own_identity(managed_group))
        .expect("Could not create name from identity")
        .to_lowercase();
    let path = TEMP_DIR
        .path()
        .join(format!("test_managed_group_{}.json", &name));
    let out_file = &mut File::create(path).expect("Could not create file");
    managed_group
        .save(out_file)
        .expect("Could not write group state to file");
}

// The following enables the OpenMlsEvercrypt provider on machines that support
// it. This is a basic check to ensure that the provider generally works.
// TODO: #520 - Better tests for Evercrypt backend
#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "macos"),
    not(target_family = "wasm")
))]
use evercrypt_backend::OpenMlsEvercrypt;
#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "macos"),
    not(target_family = "wasm")
))]
fn crypto() -> impl OpenMlsCryptoProvider {
    OpenMlsEvercrypt::default()
}

#[cfg(any(
    not(target_arch = "x86_64"),
    target_os = "macos",
    target_family = "wasm"
))]
fn crypto() -> impl OpenMlsCryptoProvider {
    OpenMlsRustCrypto::default()
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
#[test]
fn managed_group_operations() {
    let crypto = crypto();
    for ciphersuite in Config::supported_ciphersuites() {
        for wire_format in vec![WireFormat::MlsPlaintext, WireFormat::MlsCiphertext].into_iter() {
            let group_id = GroupId::from_slice(b"Test Group");

            // Generate credential bundles
            let alice_credential = generate_credential_bundle(
                "Alice".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .expect("An unexpected error occurred.");

            let bob_credential = generate_credential_bundle(
                "Bob".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .expect("An unexpected error occurred.");

            let charlie_credential = generate_credential_bundle(
                "Charlie".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .expect("An unexpected error occurred.");

            // Generate KeyPackages
            let alice_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &alice_credential,
                vec![],
                &crypto,
            )
            .expect("An unexpected error occurred.");

            let bob_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &bob_credential,
                vec![],
                &crypto,
            )
            .expect("An unexpected error occurred.");

            // Define the managed group configuration

            let managed_group_config = ManagedGroupConfig::builder()
                .wire_format(wire_format)
                .build();

            // === Alice creates a group ===
            let mut alice_group = ManagedGroup::new(
                &crypto,
                &managed_group_config,
                group_id,
                &alice_key_package
                    .hash(&crypto)
                    .expect("Could not hash KeyPackage."),
            )
            .expect("An unexpected error occurred.");

            // === Alice adds Bob ===
            let (queued_message, welcome) =
                match alice_group.add_members(&crypto, &[bob_key_package]) {
                    Ok((qm, welcome)) => (qm, welcome),
                    Err(e) => panic!("Could not add member to group: {:?}", e),
                };

            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");

            // Check that Alice is the sender of the message
            assert_eq!(
                unverified_message
                    .credential()
                    .expect("Expected a credential."),
                &alice_credential
            );

            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we received the correct proposals
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = alice_processed_message {
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
                // TODO #575: Replace this with the adequate API call
                assert_eq!(add.sender().to_leaf_index(), LeafIndex::from(0u32));
                // Merge staged Commit
                alice_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge Commit.");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Check that the group now has two members
            assert_eq!(alice_group.members().len(), 2);

            // Check that Alice & Bob are the members of the group
            let members = alice_group.members();
            assert_eq!(members[0].identity(), b"Alice");
            assert_eq!(members[1].identity(), b"Bob");

            let mut bob_group = ManagedGroup::new_from_welcome(
                &crypto,
                &managed_group_config,
                welcome,
                Some(alice_group.export_ratchet_tree()),
            )
            .expect("Error creating group from Welcome");

            // Make sure that both groups have the same members
            assert_eq!(alice_group.members(), bob_group.members());

            // Make sure that both groups have the same authentication secret
            assert_eq!(
                alice_group.authentication_secret(),
                bob_group.authentication_secret()
            );

            // === Alice sends a message to Bob ===
            let message_alice = b"Hi, I'm Alice!";
            let queued_message = alice_group
                .create_message(&crypto, message_alice)
                .expect("Error creating application message");

            let unverified_message = bob_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let processed_message = bob_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we received the correct message
            if let ProcessedMessage::ApplicationMessage(application_message) = processed_message {
                // Check the message
                assert_eq!(application_message.message(), message_alice);
                // Check that Alice sent the message
                // TODO #575: Replace this with the adequate API call
                assert_eq!(
                    application_message.sender().to_leaf_index(),
                    LeafIndex::from(0u32)
                );
            } else {
                unreachable!("Expected an ApplicationMessage.");
            }

            // === Bob updates and commits ===
            let (queued_message, welcome_option) = match bob_group.self_update(&crypto, None) {
                Ok(qm) => qm,
                Err(e) => panic!("Error performing self-update: {:?}", e),
            };

            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");
            let unverified_message = bob_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let bob_processed_message = bob_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we received the correct proposals
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = alice_processed_message {
                let update = staged_commit
                    .update_proposals()
                    .next()
                    .expect("Expected a proposal.");
                // Check that Bob updated
                assert_eq!(
                    update.update_proposal().key_package().credential(),
                    &bob_credential
                );
                // Check that Alice added Bob
                // TODO #575: Replace this with the adequate API call
                assert_eq!(update.sender().to_leaf_index(), LeafIndex::from(1u32));
                // Merge staged Commit
                alice_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge Commit.");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Merge Commit
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = bob_processed_message {
                bob_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge StagedCommit");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Check we didn't receive a Welcome message
            assert!(welcome_option.is_none());

            // Check that both groups have the same state
            assert_eq!(
                alice_group.export_secret(&crypto, "", &[], 32),
                bob_group.export_secret(&crypto, "", &[], 32)
            );

            // Make sure that both groups have the same public tree
            assert_eq!(
                alice_group.export_ratchet_tree(),
                bob_group.export_ratchet_tree()
            );

            // === Alice updates and commits ===
            let queued_message = match alice_group.propose_self_update(&crypto, None) {
                Ok(qm) => qm,
                Err(e) => panic!("Error performing self-update: {:?}", e),
            };
            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");
            let unverified_message = bob_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let bob_processed_message = bob_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we received the correct proposals
            if let ProcessedMessage::ProposalMessage(staged_proposal) = alice_processed_message {
                if let Proposal::Update(ref update_proposal) = staged_proposal.proposal() {
                    // Check that Alice updated
                    assert_eq!(
                        update_proposal.key_package().credential(),
                        &alice_credential
                    );
                    // Store proposal
                    alice_group.store_pending_proposal(*staged_proposal.clone());
                } else {
                    unreachable!("Expected a Proposal.");
                }

                // Check that Alice added bob
                // TODO #575: Replace this with the adequate API call
                assert_eq!(
                    staged_proposal.sender().to_leaf_index(),
                    LeafIndex::from(0u32)
                );
            } else {
                unreachable!("Expected a StagedProposal.");
            }

            // Merge Commit
            if let ProcessedMessage::ProposalMessage(staged_proposal) = bob_processed_message {
                bob_group.store_pending_proposal(*staged_proposal);
            } else {
                unreachable!("Expected a StagedProposal.");
            }

            let (queued_message, _welcome_option) =
                match alice_group.commit_to_pending_proposals(&crypto) {
                    Ok(qm) => qm,
                    Err(e) => panic!("Error performing self-update: {:?}", e),
                };
            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");
            let unverified_message = bob_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let bob_processed_message = bob_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we received the correct proposals
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = alice_processed_message {
                let update = staged_commit
                    .update_proposals()
                    .next()
                    .expect("Expected a proposal.");
                // Check that Alice updated
                assert_eq!(
                    update.update_proposal().key_package().credential(),
                    &alice_credential
                );
                // Check that Alice added Bob
                // TODO #575: Replace this with the adequate API call
                assert_eq!(update.sender().to_leaf_index(), LeafIndex::from(0u32));
                // Merge staged Commit
                alice_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge Commit.");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Merge Commit
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = bob_processed_message {
                bob_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge StagedCommit");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Check that both groups have the same state
            assert_eq!(
                alice_group.export_secret(&crypto, "", &[], 32),
                bob_group.export_secret(&crypto, "", &[], 32)
            );

            // Make sure that both groups have the same public tree
            assert_eq!(
                alice_group.export_ratchet_tree(),
                bob_group.export_ratchet_tree()
            );

            // === Bob adds Charlie ===
            let charlie_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &charlie_credential,
                vec![],
                &crypto,
            )
            .expect("An unexpected error occurred.");

            let (queued_message, welcome) =
                match bob_group.add_members(&crypto, &[charlie_key_package]) {
                    Ok((qm, welcome)) => (qm, welcome),
                    Err(e) => panic!("Could not add member to group: {:?}", e),
                };

            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");
            let unverified_message = bob_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let bob_processed_message = bob_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Merge Commit
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = alice_processed_message {
                alice_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge StagedCommit");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Merge Commit
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = bob_processed_message {
                bob_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge StagedCommit");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            let mut charlie_group = ManagedGroup::new_from_welcome(
                &crypto,
                &managed_group_config,
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
            let members = alice_group.members();
            assert_eq!(members[0].identity(), b"Alice");
            assert_eq!(members[1].identity(), b"Bob");
            assert_eq!(members[2].identity(), b"Charlie");

            // === Charlie sends a message to the group ===
            let message_charlie = b"Hi, I'm Charlie!";
            let queued_message = charlie_group
                .create_message(&crypto, message_charlie)
                .expect("Error creating application message");

            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let _alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");
            let unverified_message = bob_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let _bob_processed_message = bob_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // === Charlie updates and commits ===
            let (queued_message, welcome_option) = match charlie_group.self_update(&crypto, None) {
                Ok(qm) => qm,
                Err(e) => panic!("Error performing self-update: {:?}", e),
            };

            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");
            let unverified_message = bob_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let bob_processed_message = bob_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");
            let unverified_message = charlie_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let charlie_processed_message = charlie_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Merge Commit
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = alice_processed_message {
                alice_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge StagedCommit");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Merge Commit
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = bob_processed_message {
                bob_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge StagedCommit");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Merge Commit
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = charlie_processed_message
            {
                charlie_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge StagedCommit");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Check we didn't receive a Welcome message
            assert!(welcome_option.is_none());

            // Check that all groups have the same state
            assert_eq!(
                alice_group.export_secret(&crypto, "", &[], 32),
                bob_group.export_secret(&crypto, "", &[], 32)
            );
            assert_eq!(
                alice_group.export_secret(&crypto, "", &[], 32),
                charlie_group.export_secret(&crypto, "", &[], 32)
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

            // === Charlie removes Bob ===
            let (queued_message, welcome_option) = charlie_group
                .remove_members(&crypto, &[1])
                .expect("Could not remove member from group.");

            // Check that Bob's group is still active
            assert!(bob_group.is_active());

            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");
            let unverified_message = bob_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let bob_processed_message = bob_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");
            let unverified_message = charlie_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let charlie_processed_message = charlie_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we receive the correct proposal for Alice
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = alice_processed_message {
                let remove = staged_commit
                    .remove_proposals()
                    .next()
                    .expect("Expected a proposal.");
                // Check that Bob was removed
                // TODO #575: Replace this with the adequate API call
                assert_eq!(remove.remove_proposal().removed(), 1u32);
                // Check that Charlie removed Bob
                // TODO #575: Replace this with the adequate API call
                assert_eq!(remove.sender().to_leaf_index(), LeafIndex::from(2u32));
                // Merge staged Commit
                alice_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge Commit.");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Check that we receive the correct proposal for Alice
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = bob_processed_message {
                let remove = staged_commit
                    .remove_proposals()
                    .next()
                    .expect("Expected a proposal.");
                // Check that Bob was removed
                // TODO #575: Replace this with the adequate API call
                assert_eq!(remove.remove_proposal().removed(), 1u32);
                // Check that Charlie removed Bob
                // TODO #575: Replace this with the adequate API call
                assert_eq!(remove.sender().to_leaf_index(), LeafIndex::from(2u32));
                // Merge staged Commit
                bob_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge Commit.");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Merge Commit
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = charlie_processed_message
            {
                charlie_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge StagedCommit");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Check we didn't receive a Welcome message
            assert!(welcome_option.is_none());

            // Check that Bob's group is no longer active
            assert!(!bob_group.is_active());

            // Make sure that all groups have the same public tree
            assert_eq!(
                alice_group.export_ratchet_tree(),
                charlie_group.export_ratchet_tree()
            );

            // Make sure the group only contains two members
            assert_eq!(alice_group.members().len(), 2);

            // Check that Alice & Charlie are the members of the group
            let members = alice_group.members();
            assert_eq!(members[0].identity(), b"Alice");
            assert_eq!(members[1].identity(), b"Charlie");

            // Check that Bob can no longer send messages
            assert!(bob_group
                .create_message(&crypto, b"Should not go through")
                .is_err());

            // === Alice removes Charlie and re-adds Bob ===

            // Create a new KeyPackageBundle for Bob
            let bob_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &bob_credential,
                vec![],
                &crypto,
            )
            .expect("An unexpected error occurred.");

            // Create RemoveProposal and process it
            let queued_message = alice_group
                .propose_remove_member(&crypto, 2)
                .expect("Could not create proposal to remove Charlie");
            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we received the correct proposals
            if let ProcessedMessage::ProposalMessage(staged_proposal) = alice_processed_message {
                if let Proposal::Remove(ref remove_proposal) = staged_proposal.proposal() {
                    // Check that Charlie was removed
                    // TODO #575: Replace this with the adequate API call
                    assert_eq!(remove_proposal.removed(), 2u32);
                    // Store proposal
                    alice_group.store_pending_proposal(*staged_proposal.clone());
                } else {
                    unreachable!("Expected a Proposal.");
                }

                // Check that Alice removed Charlie
                // TODO #575: Replace this with the adequate API call
                assert_eq!(
                    staged_proposal.sender().to_leaf_index(),
                    LeafIndex::from(0u32)
                );
            } else {
                unreachable!("Expected a StagedProposal.");
            }

            let unverified_message = charlie_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let charlie_processed_message = charlie_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we received the correct proposals
            if let ProcessedMessage::ProposalMessage(staged_proposal) = charlie_processed_message {
                if let Proposal::Remove(ref remove_proposal) = staged_proposal.proposal() {
                    // Check that Charlie was removed
                    // TODO #575: Replace this with the adequate API call
                    assert_eq!(remove_proposal.removed(), 2u32);
                    // Store proposal
                    charlie_group.store_pending_proposal(*staged_proposal.clone());
                } else {
                    unreachable!("Expected a Proposal.");
                }

                // Check that Alice removed Charlie
                // TODO #575: Replace this with the adequate API call
                assert_eq!(
                    staged_proposal.sender().to_leaf_index(),
                    LeafIndex::from(0u32)
                );
            } else {
                unreachable!("Expected a StagedProposal.");
            }

            // Create AddProposal and process it
            let queued_message = alice_group
                .propose_add_member(&crypto, &bob_key_package)
                .expect("Could not create proposal to add Bob");
            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we received the correct proposals
            if let ProcessedMessage::ProposalMessage(staged_proposal) = alice_processed_message {
                if let Proposal::Add(add_proposal) = staged_proposal.proposal() {
                    // Check that Bob was added
                    assert_eq!(add_proposal.key_package().credential(), &bob_credential);
                } else {
                    unreachable!("Expected an AddProposal.");
                }

                // Check that Alice added Bob
                // TODO #575: Replace this with the adequate API call
                assert_eq!(
                    staged_proposal.sender().to_leaf_index(),
                    LeafIndex::from(0u32)
                );
                // Store proposal
                alice_group.store_pending_proposal(*staged_proposal);
            } else {
                unreachable!("Expected a StagedProposal.");
            }

            let unverified_message = charlie_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let charlie_processed_message = charlie_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we received the correct proposals
            if let ProcessedMessage::ProposalMessage(staged_proposal) = charlie_processed_message {
                if let Proposal::Add(add_proposal) = staged_proposal.proposal() {
                    // Check that Bob was added
                    assert_eq!(add_proposal.key_package().credential(), &bob_credential);
                } else {
                    unreachable!("Expected an AddProposal.");
                }

                // Check that Alice added Bob
                // TODO #575: Replace this with the adequate API call
                assert_eq!(
                    staged_proposal.sender().to_leaf_index(),
                    LeafIndex::from(0u32)
                );
                // Store proposal
                charlie_group.store_pending_proposal(*staged_proposal);
            } else {
                unreachable!("Expected a StagedProposal.");
            }

            // Commit to the proposals and process it
            let (queued_message, welcome_option) = alice_group
                .commit_to_pending_proposals(&crypto)
                .expect("Could not flush proposals");

            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");
            let unverified_message = charlie_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let charlie_processed_message = charlie_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Merge Commit
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = alice_processed_message {
                alice_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge StagedCommit");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Merge Commit
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = charlie_processed_message
            {
                charlie_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge StagedCommit");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            // Make sure the group contains two members
            assert_eq!(alice_group.members().len(), 2);

            // Check that Alice & Bob are the members of the group
            let members = alice_group.members();
            assert_eq!(members[0].identity(), b"Alice");
            assert_eq!(members[1].identity(), b"Bob");

            // Bob creates a new group
            let mut bob_group = ManagedGroup::new_from_welcome(
                &crypto,
                &managed_group_config,
                welcome_option.expect("Welcome was not returned"),
                Some(alice_group.export_ratchet_tree()),
            )
            .expect("Error creating group from Welcome");

            // Make sure the group contains two members
            assert_eq!(alice_group.members().len(), 2);

            // Check that Alice & Bob are the members of the group
            let members = alice_group.members();
            assert_eq!(members[0].identity(), b"Alice");
            assert_eq!(members[1].identity(), b"Bob");

            // Make sure the group contains two members
            assert_eq!(bob_group.members().len(), 2);

            // Check that Alice & Bob are the members of the group
            let members = bob_group.members();
            assert_eq!(members[0].identity(), b"Alice");
            assert_eq!(members[1].identity(), b"Bob");

            // === Alice sends a message to the group ===
            let message_alice = b"Hi, I'm Alice!";
            let queued_message = alice_group
                .create_message(&crypto, message_alice)
                .expect("Error creating application message");
            let unverified_message = bob_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let bob_processed_message = bob_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we received the correct message
            if let ProcessedMessage::ApplicationMessage(application_message) = bob_processed_message
            {
                // Check the message
                assert_eq!(application_message.message(), message_alice);
                // Check that Alice sent the message
                // TODO #575: Replace this with the adequate API call
                assert_eq!(
                    application_message.sender().to_leaf_index(),
                    LeafIndex::from(0u32)
                );
            } else {
                unreachable!("Expected an ApplicationMessage.");
            }

            // === Bob leaves the group ===

            let queued_message = bob_group
                .leave_group(&crypto)
                .expect("Could not leave group");

            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");
            let unverified_message = bob_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let bob_processed_message = bob_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Store proposal
            if let ProcessedMessage::ProposalMessage(staged_proposal) = alice_processed_message {
                // Store proposal
                alice_group.store_pending_proposal(*staged_proposal);
            } else {
                unreachable!("Expected a StagedProposal.");
            }

            // Store proposal
            if let ProcessedMessage::ProposalMessage(staged_proposal) = bob_processed_message {
                // Store proposal
                bob_group.store_pending_proposal(*staged_proposal);
            } else {
                unreachable!("Expected a StagedProposal.");
            }

            // Should fail because you cannot remove yourself from a group
            assert_eq!(
                bob_group.commit_to_pending_proposals(&crypto,),
                Err(ManagedGroupError::Group(MlsGroupError::CreateCommitError(
                    CreateCommitError::CannotRemoveSelf
                )))
            );

            let (queued_message, _welcome_option) = alice_group
                .commit_to_pending_proposals(&crypto)
                .expect("Could not commit to proposals.");

            // Check that Bob's group is still active
            assert!(bob_group.is_active());

            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we received the correct proposals
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = alice_processed_message {
                let remove = staged_commit
                    .remove_proposals()
                    .next()
                    .expect("Expected a proposal.");
                // Check that Bob was removed
                assert_eq!(remove.remove_proposal().removed(), 1u32);
                // Check that Bob removed himself
                // TODO #575: Replace this with the adequate API call
                assert_eq!(remove.sender().to_leaf_index(), LeafIndex::from(1u32));
                // Merge staged Commit
                alice_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge Commit.");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            let unverified_message = bob_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let bob_processed_message = bob_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Check that we received the correct proposals
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = bob_processed_message {
                let remove = staged_commit
                    .remove_proposals()
                    .next()
                    .expect("Expected a proposal.");
                // Check that Bob was removed
                assert_eq!(remove.remove_proposal().removed(), 1u32);
                // Check that Bob removed himself
                // TODO #575: Replace this with the adequate API call
                assert_eq!(remove.sender().to_leaf_index(), LeafIndex::from(1u32));
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
            assert_eq!(alice_group.members().len(), 1);

            // Check that Alice is the only member of the group
            let members = alice_group.members();
            assert_eq!(members[0].identity(), b"Alice");

            // === Save the group state ===

            // Create a new KeyPackageBundle for Bob
            let bob_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &bob_credential,
                vec![],
                &crypto,
            )
            .expect("An unexpected error occurred.");

            // Add Bob to the group
            let (queued_message, welcome) = alice_group
                .add_members(&crypto, &[bob_key_package])
                .expect("Could not add Bob");

            let unverified_message = alice_group
                .parse_message(queued_message.clone().into(), &crypto)
                .expect("Could not parse message.");
            let alice_processed_message = alice_group
                .process_unverified_message(unverified_message, None, &crypto)
                .expect("Could not process unverified message.");

            // Merge Commit
            if let ProcessedMessage::StagedCommitMessage(staged_commit) = alice_processed_message {
                alice_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge StagedCommit");
            } else {
                unreachable!("Expected a StagedCommit.");
            }

            let mut bob_group = ManagedGroup::new_from_welcome(
                &crypto,
                &managed_group_config,
                welcome,
                Some(alice_group.export_ratchet_tree()),
            )
            .expect("Could not create group from Welcome");

            assert_eq!(
                alice_group.export_secret(&crypto, "before load", &[], 32),
                bob_group.export_secret(&crypto, "before load", &[], 32)
            );

            // Check that the state flag gets reset when saving
            assert_eq!(bob_group.state_changed(), InnerState::Changed);
            save(&mut bob_group);
            assert_eq!(bob_group.state_changed(), InnerState::Persisted);

            // Re-load Bob's state from file
            let path = TEMP_DIR.path().join("test_managed_group_bob.json");
            let file = File::open(path).expect("Could not open file");
            let bob_group = ManagedGroup::load(file).expect("Could not load group from file");

            // Make sure the state is still the same
            assert_eq!(
                alice_group.export_secret(&crypto, "after load", &[], 32),
                bob_group.export_secret(&crypto, "after load", &[], 32)
            );
        }
    }
}

#[test]
fn test_empty_input_errors() {
    let crypto = OpenMlsRustCrypto::default();
    let ciphersuite = &Config::supported_ciphersuites()[0];
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        &crypto,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package_bundle(&[ciphersuite.name()], &alice_credential, vec![], &crypto)
            .expect("An unexpected error occurred.");

    // Define the managed group configuration
    let managed_group_config = ManagedGroupConfig::test_default();

    // === Alice creates a group ===
    let mut alice_group = ManagedGroup::new(
        &crypto,
        &managed_group_config,
        group_id,
        &alice_key_package
            .hash(&crypto)
            .expect("Could not hash KeyPackage."),
    )
    .expect("An unexpected error occurred.");

    assert_eq!(
        alice_group
            .add_members(&crypto, &[])
            .expect_err("No EmptyInputError when trying to pass an empty slice to `add_members`."),
        ManagedGroupError::EmptyInput(EmptyInputError::AddMembers)
    );
    assert_eq!(
        alice_group.remove_members(&crypto, &[]).expect_err(
            "No EmptyInputError when trying to pass an empty slice to `remove_members`."
        ),
        ManagedGroupError::EmptyInput(EmptyInputError::RemoveMembers)
    );
}

// This tests the ratchet tree extension usage flag in the configuration
#[test]
fn managed_group_ratchet_tree_extension() {
    let crypto = OpenMlsRustCrypto::default();
    for ciphersuite in Config::supported_ciphersuites() {
        for wire_format in vec![WireFormat::MlsPlaintext, WireFormat::MlsCiphertext].into_iter() {
            let group_id = GroupId::from_slice(b"Test Group");

            // === Positive case: using the ratchet tree extension ===

            // Generate credential bundles
            let alice_credential = generate_credential_bundle(
                "Alice".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .expect("An unexpected error occurred.");

            let bob_credential = generate_credential_bundle(
                "Bob".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .expect("An unexpected error occurred.");

            // Generate KeyPackages
            let alice_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &alice_credential,
                vec![],
                &crypto,
            )
            .expect("An unexpected error occurred.");

            let bob_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &bob_credential,
                vec![],
                &crypto,
            )
            .expect("An unexpected error occurred.");

            let managed_group_config = ManagedGroupConfig::builder()
                .wire_format(wire_format)
                .use_ratchet_tree_extension(true)
                .build();

            // === Alice creates a group ===
            let mut alice_group = ManagedGroup::new(
                &crypto,
                &managed_group_config,
                group_id.clone(),
                &alice_key_package
                    .hash(&crypto)
                    .expect("Could not hash KeyPackage."),
            )
            .expect("An unexpected error occurred.");

            // === Alice adds Bob ===
            let (_queued_message, welcome) =
                match alice_group.add_members(&crypto, &[bob_key_package.clone()]) {
                    Ok((qm, welcome)) => (qm, welcome),
                    Err(e) => panic!("Could not add member to group: {:?}", e),
                };

            // === Bob joins using the ratchet tree extension ===
            let _bob_group =
                ManagedGroup::new_from_welcome(&crypto, &managed_group_config, welcome, None)
                    .expect("Error creating group from Welcome");

            // === Negative case: not using the ratchet tree extension ===

            // Generate credential bundles
            let alice_credential = generate_credential_bundle(
                "Alice".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .expect("An unexpected error occurred.");

            let bob_credential = generate_credential_bundle(
                "Bob".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .expect("An unexpected error occurred.");

            // Generate KeyPackages
            let alice_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &alice_credential,
                vec![],
                &crypto,
            )
            .expect("An unexpected error occurred.");

            let bob_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &bob_credential,
                vec![],
                &crypto,
            )
            .expect("An unexpected error occurred.");

            let managed_group_config = ManagedGroupConfig::test_default();

            // === Alice creates a group ===
            let mut alice_group = ManagedGroup::new(
                &crypto,
                &managed_group_config,
                group_id,
                &alice_key_package
                    .hash(&crypto)
                    .expect("Could not hash KeyPackage."),
            )
            .expect("An unexpected error occurred.");

            // === Alice adds Bob ===
            let (_queued_message, welcome) =
                match alice_group.add_members(&crypto, &[bob_key_package]) {
                    Ok((qm, welcome)) => (qm, welcome),
                    Err(e) => panic!("Could not add member to group: {:?}", e),
                };

            // === Bob tries to join without the ratchet tree extension ===
            let error =
                ManagedGroup::new_from_welcome(&crypto, &managed_group_config, welcome, None)
                    .expect_err("Could join a group without a ratchet tree");

            assert_eq!(
                error,
                ManagedGroupError::Group(MlsGroupError::WelcomeError(
                    WelcomeError::MissingRatchetTree
                ))
            );
        }
    }
}
