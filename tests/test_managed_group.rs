use openmls::prelude::*;

use std::str;

/// Validator function for AddProposals
/// `(managed_group: &ManagedGroup, sender: &Sender, aad_proposal: &AddProposal)
/// -> bool`
fn validate_add(
    _managed_group: &ManagedGroup,
    _sender: &Sender,
    _add_proposal: &AddProposal,
) -> bool {
    true
}

/// Validator function for RemoveProposals
/// `(managed_group: &ManagedGroup, sender: &Sender, remove_proposal:
/// &RemoveProposal) -> bool`
fn validate_remove(
    _managed_group: &ManagedGroup,
    _sender: &Sender,
    _remove_porposal: &RemoveProposal,
) -> bool {
    true
}
/// Event listener function for AddProposals
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Sender, add_proposal:
/// &AddProposal)`
fn member_added(
    managed_group: &ManagedGroup,
    _aad: &[u8],
    sender: &Sender,
    add_proposal: &AddProposal,
) {
    println!(
        "AddProposal received in group '{}' by '{}': '{}' added '{}'",
        str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
        str::from_utf8(&managed_group.client_id()).unwrap(),
        str::from_utf8(
            managed_group
                .member(sender.to_leaf_index())
                .unwrap()
                .get_identity()
        )
        .unwrap(),
        str::from_utf8(add_proposal.key_package.credential().get_identity()).unwrap(),
    );
}
/// Event listener function for RemoveProposals
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Sender,
/// remove_proposal: &RemoveProposal)`
fn member_removed(
    managed_group: &ManagedGroup,
    _aad: &[u8],
    sender: &Sender,
    remove_proposal: &RemoveProposal,
) {
    println!(
        "RemoveProposal received in group '{}' by '{}': '{}' removed '{}'",
        str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
        str::from_utf8(&managed_group.client_id()).unwrap(),
        str::from_utf8(
            managed_group
                .member(sender.to_leaf_index())
                .unwrap()
                .get_identity()
        )
        .unwrap(),
        remove_proposal.removed,
    );
}
/// Event listener function for UpdateProposals
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Sender,
/// update_proposal: &UpdateProposal)`
fn member_updated(
    managed_group: &ManagedGroup,
    _aad: &[u8],
    sender: &Sender,
    _update_proposal: &UpdateProposal,
) {
    println!(
        "UpdateProposal received in group '{}' by '{}': '{}'",
        str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
        str::from_utf8(&managed_group.client_id()).unwrap(),
        str::from_utf8(
            managed_group
                .member(sender.to_leaf_index())
                .unwrap()
                .get_identity()
        )
        .unwrap(),
    );
}
/// Event listener function for application messages
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Sender, message:
/// &[u8])`
fn app_message_received(
    managed_group: &ManagedGroup,
    _aad: &[u8],
    sender: &Sender,
    message: &[u8],
) {
    println!(
        "Message received in group '{}' by '{}' from '{}': {}",
        str::from_utf8(&managed_group.group_id().as_slice()).unwrap(),
        str::from_utf8(&managed_group.client_id()).unwrap(),
        str::from_utf8(
            managed_group
                .member(sender.to_leaf_index())
                .unwrap()
                .get_identity()
        )
        .unwrap(),
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
                str::from_utf8(&managed_group.client_id()).unwrap(),
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
#[test]
//#[should_panic]
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
        let callbacks = ManagedGroupCallbacks::new(
            Some(validate_add),
            Some(validate_remove),
            Some(member_added),
            Some(member_removed),
            Some(member_updated),
            Some(app_message_received),
            Some(invalid_message_received),
            Some(error_occured),
        );
        let managed_group_config =
            ManagedGroupConfig::new(HandshakeMessageFormat::Plaintext, update_policy, callbacks);

        // === Alice creates a group ===
        let mut alice_group =
            ManagedGroup::new(&managed_group_config, group_id, alice_key_package_bundle).unwrap();

        // === Alice adds Bob ===
        let (queued_messages, welcome) =
            match alice_group.add_members(&alice_credential_bundle, &[bob_key_package]) {
                Ok((qm, welcome)) => (qm, welcome),
                Err(e) => panic!("Could not add member to group: {:?}", e),
            };

        alice_group.process_messages(&queued_messages);

        // Check that the group now has two members
        assert_eq!(alice_group.get_members().len(), 2);

        // Check that Alice & Bob are the members of the group
        let members = alice_group.get_members();
        assert_eq!(members[0].get_identity(), b"Alice");
        assert_eq!(members[1].get_identity(), b"Bob");

        let mut bob_group = match ManagedGroup::new_from_welcome(
            &managed_group_config,
            welcome,
            Some(alice_group.export_ratchet_tree()),
            bob_key_package_bundle,
        ) {
            Ok(group) => group,
            Err(e) => panic!("Error creating group from Welcome: {:?}", e),
        };

        // Make sure that both groups have the same members
        assert_eq!(alice_group.get_members(), bob_group.get_members());

        // === Alice sends a message to Bob ===
        let message_alice = b"Hi, I'm Alice!";
        let queued_message =
            match alice_group.create_message(&alice_credential_bundle, message_alice) {
                Ok(m) => m,
                Err(e) => panic!("Error creating application message: {:?}", e),
            };
        bob_group.process_messages(&[queued_message]);

        // === Bob updates and commits ===
        let queued_messages = match bob_group.self_update(&bob_credential_bundle) {
            Ok(qm) => qm,
            Err(e) => panic!("Error performing self-update: {:?}", e),
        };
        alice_group.process_messages(&queued_messages);
        bob_group.process_messages(&queued_messages);

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
        let queued_messages = match alice_group.self_update(&alice_credential_bundle) {
            Ok(qm) => qm,
            Err(e) => panic!("Error performing self-update: {:?}", e),
        };
        alice_group.process_messages(&queued_messages);
        bob_group.process_messages(&queued_messages);

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

        let (queued_messages, welcome) =
            match bob_group.add_members(&bob_credential_bundle, &[charlie_key_package]) {
                Ok((qm, welcome)) => (qm, welcome),
                Err(e) => panic!("Could not add member to group: {:?}", e),
            };

        alice_group.process_messages(&queued_messages);
        bob_group.process_messages(&queued_messages);

        let mut charlie_group = match ManagedGroup::new_from_welcome(
            &managed_group_config,
            welcome,
            Some(bob_group.export_ratchet_tree()),
            charlie_key_package_bundle,
        ) {
            Ok(group) => group,
            Err(e) => panic!("Error creating group from Welcome: {:?}", e),
        };

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
        let members = alice_group.get_members();
        assert_eq!(members[0].get_identity(), b"Alice");
        assert_eq!(members[1].get_identity(), b"Bob");
        assert_eq!(members[2].get_identity(), b"Charlie");

        // === Charlie sends a message to the group ===
        let message_charlie = b"Hi, I'm Charlie!";
        let queued_message =
            match charlie_group.create_message(&charlie_credential_bundle, message_charlie) {
                Ok(m) => m,
                Err(e) => panic!("Error creating application message: {:?}", e),
            };
        alice_group.process_messages(&[queued_message.clone()]);
        bob_group.process_messages(&[queued_message]);

        // === Charlie updates and commits ===
        let queued_messages = match charlie_group.self_update(&charlie_credential_bundle) {
            Ok(qm) => qm,
            Err(e) => panic!("Error performing self-update: {:?}", e),
        };
        alice_group.process_messages(&queued_messages);
        bob_group.process_messages(&queued_messages);
        charlie_group.process_messages(&queued_messages);

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
        let queued_messages = match charlie_group.remove_members(&charlie_credential_bundle, &[1]) {
            Ok(qm) => qm,
            Err(e) => panic!("Could not remove member from group: {:?}", e),
        };
        alice_group.process_messages(&queued_messages);
        bob_group.process_messages(&queued_messages);
        charlie_group.process_messages(&queued_messages);

        // Make sure that all groups have the same public tree
        assert_eq!(
            alice_group.export_ratchet_tree(),
            charlie_group.export_ratchet_tree()
        );

        // Make sure the group only contains two members
        assert_eq!(alice_group.get_members().len(), 2);

        // Check that Alice & Charlie are the members of the group
        let members = alice_group.get_members();
        assert_eq!(members[0].get_identity(), b"Alice");
        assert_eq!(members[1].get_identity(), b"Charlie");

        // Check that Bob can no longer send messages
        assert!(bob_group
            .create_message(&bob_credential_bundle, b"Should not go through")
            .is_err());
    }
}
