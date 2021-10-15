use openmls::{group::EmptyInputError, prelude::*};

use lazy_static::lazy_static;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme, OpenMlsCryptoProvider};
use std::fs::File;

lazy_static! {
    static ref TEMP_DIR: tempfile::TempDir =
        tempfile::tempdir().expect("Error creating temp directory");
}

/// Validator function for AddProposals
/// `(managed_group: &ManagedGroup, sender: &Credential, added_member:
/// &Credential) -> bool`
fn validate_add(
    _managed_group: &ManagedGroup,
    _sender: &Credential,
    _added_member: &Credential,
) -> bool {
    true
}
/// Validator function for RemoveProposals
/// `(managed_group: &ManagedGroup, sender: &Credential, removed_member:
/// &Credential) -> bool`
fn validate_remove(
    _managed_group: &ManagedGroup,
    _sender: &Credential,
    _removed_member: &Credential,
) -> bool {
    true
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
        .unwrap();
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
        .unwrap();
    let kpb = KeyPackageBundle::new(ciphersuites, &credential_bundle, backend, extensions)?;
    let kp = kpb.key_package().clone();
    backend.key_store().store(&kp.hash(backend), &kpb).unwrap();
    Ok(kp)
}

/// Auto-save
/// `(managed_group: &ManagedGroup)`
fn auto_save(managed_group: &ManagedGroup) {
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

#[cfg(all(target_arch = "x86_64", not(target_os = "macos")))]
use evercrypt_backend::OpenMlsEvercrypt;
#[cfg(all(target_arch = "x86_64", not(target_os = "macos")))]
fn crypto() -> impl OpenMlsCryptoProvider {
    OpenMlsEvercrypt::default()
}

#[cfg(any(not(target_arch = "x86_64"), target_os = "macos"))]
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
///  - Test auto-save
#[test]
fn managed_group_operations() {
    let crypto = crypto();
    for ciphersuite in Config::supported_ciphersuites() {
        for handshake_message_format in
            vec![WireFormat::MlsPlaintext, WireFormat::MlsCiphertext].into_iter()
        {
            let group_id = GroupId::from_slice(b"Test Group");

            // Generate credential bundles
            let alice_credential = generate_credential_bundle(
                "Alice".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .unwrap();

            let bob_credential = generate_credential_bundle(
                "Bob".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .unwrap();

            let charlie_credential = generate_credential_bundle(
                "Charlie".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .unwrap();

            // Generate KeyPackages
            let alice_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &alice_credential,
                vec![],
                &crypto,
            )
            .unwrap();

            let bob_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &bob_credential,
                vec![],
                &crypto,
            )
            .unwrap();

            // Define the managed group configuration

            let update_policy = UpdatePolicy::default();
            let callbacks = ManagedGroupCallbacks::new()
                .with_validate_add(validate_add)
                .with_validate_remove(validate_remove)
                .with_auto_save(auto_save);
            let managed_group_config = ManagedGroupConfig::new(
                handshake_message_format,
                update_policy,
                0,
                0,
                false, // use_ratchet_tree_extension
                callbacks,
            );

            // === Alice creates a group ===
            let mut alice_group = ManagedGroup::new(
                &crypto,
                &managed_group_config,
                group_id,
                &alice_key_package.hash(&crypto),
            )
            .unwrap();

            // === Alice adds Bob ===
            let (queued_messages, welcome) =
                match alice_group.add_members(&crypto, &[bob_key_package]) {
                    Ok((qm, welcome)) => (qm, welcome),
                    Err(e) => panic!("Could not add member to group: {:?}", e),
                };

            let mut events = alice_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");

            // Check that we received the correct events

            // Since the add also triggered an update, we expect this to be the
            // last event in the queue. We expect this update to be from alice.
            match events.pop().expect("Expected an event to be returned") {
                GroupEvent::MemberUpdated(member_updated_event) => {
                    assert_eq!(member_updated_event.updated_member(), &alice_credential);
                }
                _ => unreachable!("Expected a MemberUpdated event"),
            }
            // Finally, we expect the event queue to contain an even reflecting
            // the fact that bob was indeed added by alice.
            match events.pop().expect("Expected an event to be returned") {
                GroupEvent::MemberAdded(member_added_event) => {
                    assert_eq!(member_added_event.sender(), &alice_credential);
                    assert_eq!(member_added_event.added_member(), &bob_credential);
                }
                _ => unreachable!("Expected a MemberAdded event"),
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
            let events = bob_group
                .process_message(queued_message.into(), &crypto)
                .expect("The group is no longer active");

            // Check that we received the correct event
            match events.last().expect("Expected an event to be returned") {
                GroupEvent::ApplicationMessage(application_message_event) => {
                    assert_eq!(application_message_event.sender(), &alice_credential);
                    assert_eq!(application_message_event.message(), message_alice);
                }
                _ => unreachable!("Expected an ApplicationMessage event"),
            }

            // === Bob updates and commits ===
            let (queued_messages, welcome_option) = match bob_group.self_update(&crypto, None) {
                Ok(qm) => qm,
                Err(e) => panic!("Error performing self-update: {:?}", e),
            };
            let alice_events = alice_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            let bob_events = bob_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");

            // Check that the events are equal
            assert_eq!(alice_events, bob_events);

            // Check that we received the correct event
            match alice_events
                .last()
                .expect("Expected an event to be returned")
            {
                GroupEvent::MemberUpdated(member_updated_event) => {
                    assert_eq!(member_updated_event.updated_member(), &bob_credential);
                }
                _ => unreachable!("Expected an ApplicationMessage event"),
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
            let queued_messages = match alice_group.propose_self_update(&crypto, None) {
                Ok(qm) => qm,
                Err(e) => panic!("Error performing self-update: {:?}", e),
            };
            alice_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            bob_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");

            let (queued_messages, _welcome_option) =
                match alice_group.process_pending_proposals(&crypto) {
                    Ok(qm) => qm,
                    Err(e) => panic!("Error performing self-update: {:?}", e),
                };
            let alice_events = alice_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            let bob_events = bob_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");

            // Check that the events are equel
            assert_eq!(alice_events, bob_events);

            // Check that we received the correct event
            match alice_events
                .last()
                .expect("Expected an event to be returned")
            {
                GroupEvent::MemberUpdated(member_updated_event) => {
                    assert_eq!(member_updated_event.updated_member(), &alice_credential);
                }
                _ => unreachable!("Expected a MemberUpdated event"),
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
            .unwrap();

            let (queued_messages, welcome) =
                match bob_group.add_members(&crypto, &[charlie_key_package]) {
                    Ok((qm, welcome)) => (qm, welcome),
                    Err(e) => panic!("Could not add member to group: {:?}", e),
                };

            alice_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            bob_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");

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
            alice_group
                .process_message(queued_message.clone().into(), &crypto)
                .expect("The group is no longer active");
            bob_group
                .process_message(queued_message.into(), &crypto)
                .expect("The group is no longer active");

            // === Charlie updates and commits ===
            let (queued_messages, welcome_option) = match charlie_group.self_update(&crypto, None) {
                Ok(qm) => qm,
                Err(e) => panic!("Error performing self-update: {:?}", e),
            };
            alice_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            bob_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            charlie_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");

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
            let (queued_messages, welcome_option) =
                match charlie_group.remove_members(&crypto, &[1]) {
                    Ok(qm) => qm,
                    Err(e) => panic!("Could not remove member from group: {:?}", e),
                };

            // Check that Bob's group is still active
            assert!(bob_group.is_active());

            let alice_events = alice_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            let bob_events = bob_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            charlie_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");

            // Check that we receive the correct event for Alice
            match alice_events
                .first()
                .expect("Expected an event to be returned")
            {
                GroupEvent::MemberRemoved(member_removed_event) => {
                    match member_removed_event.removal() {
                        Removal::TheyWereRemovedBy(leaver, remover) => {
                            assert_eq!(remover, &charlie_credential);
                            assert_eq!(leaver, &bob_credential);
                        }
                        _ => {
                            unreachable!("We should not be here")
                        }
                    }
                }
                _ => unreachable!("Expected a MemberRemoved event"),
            }

            // Check that we receive the correct event for Bob
            match bob_events
                .first()
                .expect("Expected an event to be returned")
            {
                GroupEvent::MemberRemoved(member_removed_event) => {
                    match member_removed_event.removal() {
                        Removal::WeWereRemovedBy(remover) => {
                            assert_eq!(remover, &charlie_credential);
                        }
                        _ => {
                            unreachable!("We should not be here")
                        }
                    }
                }
                _ => unreachable!("Expected a MemberRemoved event"),
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
            .unwrap();

            // Create RemoveProposal and process it
            let queued_messages = alice_group
                .propose_remove_member(&crypto, 2)
                .expect("Could not create proposal to remove Charlie");
            alice_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            charlie_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");

            // Create AddProposal and process it
            let queued_messages = alice_group
                .propose_add_member(&crypto, &bob_key_package)
                .expect("Could not create proposal to add Bob");
            alice_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            charlie_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");

            // Commit to the proposals and process it
            let (queued_messages, welcome_option) = alice_group
                .process_pending_proposals(&crypto)
                .expect("Could not flush proposals");
            alice_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            charlie_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");

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

            // === lice sends a message to the group ===
            let message_alice = b"Hi, I'm Alice!";
            let queued_message = alice_group
                .create_message(&crypto, message_alice)
                .expect("Error creating application message");
            bob_group
                .process_message(queued_message.clone().into(), &crypto)
                .expect("The group is no longer active");

            // === Bob leaves the group ===

            let queued_messages = bob_group
                .leave_group(&crypto)
                .expect("Could not leave group");

            alice_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            bob_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");

            // Should fail because you cannot remove yourself from a group
            assert_eq!(
                bob_group.process_pending_proposals(&crypto,),
                Err(ManagedGroupError::Group(MlsGroupError::CreateCommitError(
                    CreateCommitError::CannotRemoveSelf
                )))
            );

            let (queued_messages, _welcome_option) = alice_group
                .process_pending_proposals(&crypto)
                .expect("Could not commit to proposals");

            // Check that Bob's group is still active
            assert!(bob_group.is_active());

            let alice_events = alice_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");
            let bob_events = bob_group
                .process_message(queued_messages.clone().into(), &crypto)
                .expect("The group is no longer active");

            // Check that we receive the correct event for Bob
            match alice_events
                .first()
                .expect("Expected an event to be returned")
            {
                GroupEvent::MemberRemoved(member_removed_event) => {
                    match member_removed_event.removal() {
                        Removal::TheyLeft(leaver) => {
                            assert_eq!(leaver, &bob_credential);
                        }
                        _ => {
                            unreachable!("We should not be here")
                        }
                    }
                }
                _ => unreachable!("Expected a MemberRemoved event"),
            }

            // Check that we receive the correct event for Bob
            match bob_events
                .first()
                .expect("Expected an event to be returned")
            {
                GroupEvent::MemberRemoved(member_removed_event) => {
                    match member_removed_event.removal() {
                        Removal::WeLeft => {}
                        _ => {
                            unreachable!("We should not be here")
                        }
                    }
                }
                _ => unreachable!("Expected a MemberRemoved event"),
            }

            // Check that Bob's group is no longer active
            assert!(!bob_group.is_active());

            // Make sure the group contains one member
            assert_eq!(alice_group.members().len(), 1);

            // Check that Alice is the only member of the group
            let members = alice_group.members();
            assert_eq!(members[0].identity(), b"Alice");

            // === Auto-save ===

            // Create a new KeyPackageBundle for Bob
            let bob_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &bob_credential,
                vec![],
                &crypto,
            )
            .unwrap();

            // Add Bob to the group
            let (queued_messages, welcome) = alice_group
                .add_members(&crypto, &[bob_key_package])
                .expect("Could not add Bob");

            alice_group
                .process_message(queued_messages.into(), &crypto)
                .expect("Could not process messages");

            let bob_group = ManagedGroup::new_from_welcome(
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

            // Re-load Bob's state from file
            let path = TEMP_DIR.path().join("test_managed_group_bob.json");
            let file = File::open(path).expect("Could not open file");
            let bob_group = ManagedGroup::load(file, managed_group_config.callbacks())
                .expect("Could not load group from file");

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
    .unwrap();

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package_bundle(&[ciphersuite.name()], &alice_credential, vec![], &crypto)
            .unwrap();

    // Define the managed group configuration
    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let managed_group_config = ManagedGroupConfig::new(
        WireFormat::MlsPlaintext,
        update_policy,
        0,
        0,
        false, // use_ratchet_tree_extension
        callbacks,
    );

    // === Alice creates a group ===
    let mut alice_group = ManagedGroup::new(
        &crypto,
        &managed_group_config,
        group_id,
        &alice_key_package.hash(&crypto),
    )
    .unwrap();

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
        for handshake_message_format in
            vec![WireFormat::MlsPlaintext, WireFormat::MlsCiphertext].into_iter()
        {
            let group_id = GroupId::from_slice(b"Test Group");

            // Define the managed group configuration

            let update_policy = UpdatePolicy::default();

            // === Positive case: using the ratchet tree extension ===

            // Generate credential bundles
            let alice_credential = generate_credential_bundle(
                "Alice".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .unwrap();

            let bob_credential = generate_credential_bundle(
                "Bob".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .unwrap();

            // Generate KeyPackages
            let alice_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &alice_credential,
                vec![],
                &crypto,
            )
            .unwrap();

            let bob_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &bob_credential,
                vec![],
                &crypto,
            )
            .unwrap();

            let managed_group_config = ManagedGroupConfig::new(
                handshake_message_format,
                update_policy.clone(),
                0,
                0,
                true, // use_ratchet_tree_extension
                ManagedGroupCallbacks::default(),
            );

            // === Alice creates a group ===
            let mut alice_group = ManagedGroup::new(
                &crypto,
                &managed_group_config,
                group_id.clone(),
                &alice_key_package.hash(&crypto),
            )
            .unwrap();

            // === Alice adds Bob ===
            let (_queued_messages, welcome) =
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
            .unwrap();

            let bob_credential = generate_credential_bundle(
                "Bob".into(),
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .unwrap();

            // Generate KeyPackages
            let alice_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &alice_credential,
                vec![],
                &crypto,
            )
            .unwrap();

            let bob_key_package = generate_key_package_bundle(
                &[ciphersuite.name()],
                &bob_credential,
                vec![],
                &crypto,
            )
            .unwrap();

            let managed_group_config = ManagedGroupConfig::new(
                handshake_message_format,
                update_policy,
                0,
                0,
                false, // use_ratchet_tree_extension
                ManagedGroupCallbacks::default(),
            );

            // === Alice creates a group ===
            let mut alice_group = ManagedGroup::new(
                &crypto,
                &managed_group_config,
                group_id,
                &alice_key_package.hash(&crypto),
            )
            .unwrap();

            // === Alice adds Bob ===
            let (_queued_messages, welcome) =
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
