use openmls::prelude::*;

use std::str;

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
/// Event listener function for AddProposals
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Credential,
/// added_member: &Credential)`
fn member_added(
    managed_group: &ManagedGroup,
    _aad: &[u8],
    sender: &Credential,
    added_member: &Credential,
) {
    println!(
        "AddProposal received in group '{}' by '{}': '{}' added '{}'",
        str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
        str::from_utf8(&managed_group.credential().get_identity()).unwrap(),
        str::from_utf8(sender.get_identity()).unwrap(),
        str::from_utf8(added_member.get_identity()).unwrap(),
    );
}
/// Event listener function for RemoveProposals when a member was removed
/// `(managed_group: &ManagedGroup, aad: &[u8], removal: &Removal)`
fn member_removed(managed_group: &ManagedGroup, _aad: &[u8], removal: &Removal) {
    print!(
        "RemoveProposal received in group '{}' by '{}': ",
        str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
        str::from_utf8(&managed_group.credential().get_identity()).unwrap(),
    );
    match removal {
        Removal::WeLeft => {
            println!("We left");
        }
        Removal::WeWereRemovedBy(remover) => {
            println!(
                "'{}' removed us",
                str::from_utf8(remover.get_identity()).unwrap(),
            );
        }
        Removal::TheyLeft(leaver) => {
            println!("'{}' left", str::from_utf8(leaver.get_identity()).unwrap(),);
        }
        Removal::TheyWereRemovedBy(leaver, remover) => {
            println!(
                "'{}' removed '{}'",
                str::from_utf8(remover.get_identity()).unwrap(),
                str::from_utf8(leaver.get_identity()).unwrap(),
            );
        }
    }
}
/// Event listener function for UpdateProposals
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Credential,
/// update_proposal: &UpdateProposal)`
fn member_updated(managed_group: &ManagedGroup, _aad: &[u8], updated_member: &Credential) {
    println!(
        "UpdateProposal received in group '{}' by '{}': '{}'",
        str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
        str::from_utf8(&managed_group.credential().get_identity()).unwrap(),
        str::from_utf8(updated_member.get_identity()).unwrap(),
    );
}
/// Event listener function for application messages
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Credential, message:
/// &[u8])`
fn app_message_received(
    managed_group: &ManagedGroup,
    _aad: &[u8],
    sender: &Credential,
    message: &[u8],
) {
    println!(
        "Message received in group '{}' by '{}' from '{}': {}",
        str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
        str::from_utf8(&managed_group.credential().get_identity()).unwrap(),
        str::from_utf8(sender.get_identity()).unwrap(),
        str::from_utf8(message).unwrap()
    );
}
/// Event listener function for invalid messages
/// `(managed_group: &ManagedGroup, aad_option: Option<&[u8]>, sender_option:
/// Option<&Sender>, error: InvalidMessageError)`
fn invalid_message_received(managed_group: &ManagedGroup, error: InvalidMessageError) {
    match error {
        InvalidMessageError::InvalidCiphertext(aad) => {
            println!(
                "Invalid ciphertext message received in group '{}' by '{}' with AAD {:?}",
                str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
                str::from_utf8(&managed_group.credential().get_identity()).unwrap(),
                aad
            );
        }
        InvalidMessageError::CommitWithInvalidProposals => {
            println!("A Commit message with one ore more invalid proposals was received");
        }
        InvalidMessageError::CommitError(e) => {
            println!("An error occured when applying a Commit message: {:?}", e);
        }
    }
}
/// Event listener function for errors that occur
/// `(managed_group: &ManagedGroup, error: ManagedGroupError)`
fn error_occured(managed_group: &ManagedGroup, error: ManagedGroupError) {
    println!(
        "Error occured in group {}: {:?}",
        str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
        error
    );
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
#[test]
fn managed_group_operations() {
    for ciphersuite in Config::supported_ciphersuites() {
        let group_id = GroupId::from_slice(b"Test Group");

        // Define credential bundles
        let alice_credential_bundle =
            CredentialBundle::new("Alice".into(), CredentialType::Basic, ciphersuite.name())
                .unwrap();
        let bob_credential_bundle =
            CredentialBundle::new("Bob".into(), CredentialType::Basic, ciphersuite.name()).unwrap();

        // Generate KeyPackages
        let alice_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, vec![]).unwrap();

        let bob_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, vec![]).unwrap();
        let bob_key_package = bob_key_package_bundle.get_key_package().clone();

        // Define the managed group configuration

        let update_policy = UpdatePolicy::default();
        let callbacks = ManagedGroupCallbacks::new()
            .with_validate_add(validate_add)
            .with_validate_remove(validate_remove)
            .with_member_added(member_added)
            .with_member_removed(member_removed)
            .with_member_updated(member_updated)
            .with_app_message_received(app_message_received)
            .with_invalid_message_received(invalid_message_received)
            .with_error_occured(error_occured);
        let managed_group_config =
            ManagedGroupConfig::new(HandshakeMessageFormat::Plaintext, update_policy, callbacks);

        // === Alice creates a group ===
        let mut alice_group = ManagedGroup::new(
            &alice_credential_bundle,
            &managed_group_config,
            group_id,
            alice_key_package_bundle,
        )
        .unwrap();

        // === Alice adds Bob ===
        let (queued_messages, welcome) = match alice_group.add_members(&[bob_key_package.clone()]) {
            Ok((qm, welcome)) => (qm, welcome),
            Err(e) => panic!("Could not add member to group: {:?}", e),
        };

        alice_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");

        // Check that the group now has two members
        assert_eq!(alice_group.members().len(), 2);

        // Check that Alice & Bob are the members of the group
        let members = alice_group.members();
        assert_eq!(members[0].get_identity(), b"Alice");
        assert_eq!(members[1].get_identity(), b"Bob");

        let mut bob_group = ManagedGroup::new_from_welcome(
            &bob_credential_bundle,
            &managed_group_config,
            welcome,
            Some(alice_group.export_ratchet_tree()),
            bob_key_package_bundle,
        )
        .expect("Error creating group from Welcome");

        // Make sure that both groups have the same members
        assert_eq!(alice_group.members(), bob_group.members());

        // === Alice sends a message to Bob ===
        let message_alice = b"Hi, I'm Alice!";
        let queued_message = alice_group
            .create_message(message_alice)
            .expect("Error creating application message");
        bob_group
            .process_messages(vec![queued_message])
            .expect("The group is no longer active");

        // === Bob updates and commits ===
        let queued_messages = match bob_group.self_update(None) {
            Ok(qm) => qm,
            Err(e) => panic!("Error performing self-update: {:?}", e),
        };
        alice_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        println!("Alice processed messages");
        bob_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");

        // Check that both groups have the same state
        assert_eq!(
            alice_group.export_secret("", 32),
            bob_group.export_secret("", 32)
        );

        // Make sure that both groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            bob_group.export_ratchet_tree()
        );

        // === Alice updates and commits ===
        let queued_messages = match alice_group.propose_self_update(None) {
            Ok(qm) => qm,
            Err(e) => panic!("Error performing self-update: {:?}", e),
        };
        alice_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        bob_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");

        let (queued_messages, _welcome_option) = match alice_group.process_pending_proposals() {
            Ok(qm) => qm,
            Err(e) => panic!("Error performing self-update: {:?}", e),
        };
        alice_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        bob_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");

        // Check that both groups have the same state
        assert_eq!(
            alice_group.export_secret("", 32),
            bob_group.export_secret("", 32)
        );

        // Make sure that both groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            bob_group.export_ratchet_tree()
        );

        // === Bob adds Charlie ===
        let charlie_credential_bundle =
            CredentialBundle::new("Charlie".into(), CredentialType::Basic, ciphersuite.name())
                .unwrap();

        let charlie_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &charlie_credential_bundle, vec![])
                .unwrap();
        let charlie_key_package = charlie_key_package_bundle.get_key_package().clone();

        let (queued_messages, welcome) = match bob_group.add_members(&[charlie_key_package]) {
            Ok((qm, welcome)) => (qm, welcome),
            Err(e) => panic!("Could not add member to group: {:?}", e),
        };

        alice_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        bob_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");

        let mut charlie_group = ManagedGroup::new_from_welcome(
            &charlie_credential_bundle,
            &managed_group_config,
            welcome,
            Some(bob_group.export_ratchet_tree()),
            charlie_key_package_bundle,
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
        assert_eq!(members[0].get_identity(), b"Alice");
        assert_eq!(members[1].get_identity(), b"Bob");
        assert_eq!(members[2].get_identity(), b"Charlie");

        // === Charlie sends a message to the group ===
        let message_charlie = b"Hi, I'm Charlie!";
        let queued_message = charlie_group
            .create_message(message_charlie)
            .expect("Error creating application message");
        alice_group
            .process_messages(vec![queued_message.clone()])
            .expect("The group is no longer active");
        bob_group
            .process_messages(vec![queued_message])
            .expect("The group is no longer active");

        // === Charlie updates and commits ===
        let queued_messages = match charlie_group.self_update(None) {
            Ok(qm) => qm,
            Err(e) => panic!("Error performing self-update: {:?}", e),
        };
        alice_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        bob_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        charlie_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");

        // Check that all groups have the same state
        assert_eq!(
            alice_group.export_secret("", 32),
            bob_group.export_secret("", 32)
        );
        assert_eq!(
            alice_group.export_secret("", 32),
            charlie_group.export_secret("", 32)
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
        let queued_messages = match charlie_group.remove_members(&[1]) {
            Ok(qm) => qm,
            Err(e) => panic!("Could not remove member from group: {:?}", e),
        };

        // Check that Bob's group is still active
        assert!(bob_group.is_active());

        alice_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        bob_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        charlie_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");

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
        assert_eq!(members[0].get_identity(), b"Alice");
        assert_eq!(members[1].get_identity(), b"Charlie");

        // Check that Bob can no longer send messages
        assert!(bob_group.create_message(b"Should not go through").is_err());

        // === Alice removes Charlie and re-adds Bob ===

        // Create a new KeyPackageBundle for Bob
        let bob_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, vec![]).unwrap();
        let bob_key_package = bob_key_package_bundle.get_key_package().clone();

        // Create RemoveProposal and process it
        let queued_messages = alice_group
            .propose_remove_members(&[2])
            .expect("Could not create proposal to remove Charlie");
        alice_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        charlie_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");

        // Create AddProposal and process it
        let queued_messages = alice_group
            .propose_add_members(&[bob_key_package])
            .expect("Could not create proposal to add Bob");
        alice_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        charlie_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");

        // Commit to the proposals and process it
        let (queued_messages, welcome_option) = alice_group
            .process_pending_proposals()
            .expect("Could not flush proposals");
        alice_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        charlie_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");

        // Make sure the group contains two members
        assert_eq!(alice_group.members().len(), 2);

        // Check that Alice & Bob are the members of the group
        let members = alice_group.members();
        assert_eq!(members[0].get_identity(), b"Alice");
        assert_eq!(members[1].get_identity(), b"Bob");

        // Bob creates a new group
        let mut bob_group = ManagedGroup::new_from_welcome(
            &bob_credential_bundle,
            &managed_group_config,
            welcome_option.expect("Welcome was not returned"),
            Some(alice_group.export_ratchet_tree()),
            bob_key_package_bundle,
        )
        .expect("Error creating group from Welcome");

        // Make sure the group contains two members
        assert_eq!(alice_group.members().len(), 2);

        // Check that Alice & Bob are the members of the group
        let members = alice_group.members();
        assert_eq!(members[0].get_identity(), b"Alice");
        assert_eq!(members[1].get_identity(), b"Bob");

        // Make sure the group contains two members
        assert_eq!(bob_group.members().len(), 2);

        // Check that Alice & Bob are the members of the group
        let members = bob_group.members();
        assert_eq!(members[0].get_identity(), b"Alice");
        assert_eq!(members[1].get_identity(), b"Bob");

        // === lice sends a message to the group ===
        let message_alice = b"Hi, I'm Alice!";
        let queued_message = alice_group
            .create_message(message_alice)
            .expect("Error creating application message");
        bob_group
            .process_messages(vec![queued_message.clone()])
            .expect("The group is no longer active");

        // === Bob leaves the group ===

        let queued_messages = bob_group.leave_group().expect("Could not leave group");

        alice_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        bob_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");

        // Should fail because you cannot remove yourself from a group
        assert_eq!(
            bob_group.process_pending_proposals(),
            Err(ManagedGroupError::CreateCommit(
                CreateCommitError::CannotRemoveSelf
            ))
        );

        let (queued_messages, _welcome_option) = alice_group
            .process_pending_proposals()
            .expect("Could not commit to proposals");

        // Check that Bob's group is still active
        assert!(bob_group.is_active());

        alice_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");
        bob_group
            .process_messages(queued_messages.clone())
            .expect("The group is no longer active");

        // Check that Bob's group is no longer active
        assert!(!bob_group.is_active());

        // Make sure the group contains one member
        assert_eq!(alice_group.members().len(), 1);

        // Check that Alice is the only member of the group
        let members = alice_group.members();
        assert_eq!(members[0].get_identity(), b"Alice");
    }
}
