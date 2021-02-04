use crate::prelude::*;

#[test]
fn test_managed_group_persistence() {
    use std::fs::File;
    use std::path::Path;
    let ciphersuite = &Config::supported_ciphersuites()[0];
    let group_id = GroupId::from_slice(b"Test Group");

    let mut key_store = KeyStore::default();

    // Generate credential bundles
    let alice_credential = key_store
        .fresh_credential(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();

    let alice_credential_bundle = key_store
        .credential_bundle(alice_credential.signature_key())
        .unwrap();

    // Generate KeyPackages
    let alice_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, vec![]).unwrap();

    // Define the managed group configuration
    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let managed_group_config = ManagedGroupConfig::new(
        HandshakeMessageFormat::Plaintext,
        update_policy,
        0,
        callbacks,
    );

    // === Alice creates a group ===

    let alice_group = ManagedGroup::new(
        &key_store,
        &managed_group_config,
        group_id,
        alice_key_package_bundle,
    )
    .unwrap();

    let path = Path::new("target/test_managed_group_serialization.json");
    let out_file = &mut File::create(&path).expect("Could not create file");
    alice_group
        .save(out_file)
        .expect("Could not write group state to file");

    let in_file = File::open(&path).expect("Could not open file");

    let alice_group_deserialized =
        ManagedGroup::load(in_file, &key_store, &ManagedGroupCallbacks::default())
            .expect("Could not deserialize managed group");

    assert_eq!(
        (
            alice_group.export_ratchet_tree(),
            alice_group.export_secret("test", 32)
        ),
        (
            alice_group_deserialized.export_ratchet_tree(),
            alice_group_deserialized.export_secret("test", 32)
        )
    );
}

// This tests if the remover is correctly passed to the callback when one member
// issues a RemoveProposal and another members issues the next Commit.
#[test]
fn remover() {
    // Callback
    fn member_removed(_managed_group: &ManagedGroup, _aad: &[u8], removal: &Removal) {
        match removal {
            Removal::TheyWereRemovedBy(leaver, remover) => {
                assert_eq!(remover.identity(), b"Alice");
                assert_eq!(leaver.identity(), b"Bob");
            }
            _ => {
                unreachable!("We should not be here")
            }
        }
    }

    let ciphersuite = &Config::supported_ciphersuites()[0];
    let group_id = GroupId::from_slice(b"Test Group");

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .expect("Could not create credential bundle");
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .expect("Could not create credential bundle");
    let charlie_credential_bundle = CredentialBundle::new(
        "Charlie".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .expect("Could not create credential bundle");

    // Generate KeyPackages
    let alice_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, vec![]).unwrap();

    let bob_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, vec![]).unwrap();

    let charlie_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &charlie_credential_bundle, vec![]).unwrap();

    // Define the managed group configuration

    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let mut managed_group_config = ManagedGroupConfig::new(
        HandshakeMessageFormat::Plaintext,
        update_policy,
        0,
        callbacks,
    );

    // === Alice creates a group ===
    let mut alice_group = ManagedGroup::new(
        &alice_credential_bundle,
        &managed_group_config,
        group_id,
        alice_key_package_bundle,
    )
    .unwrap();

    // === Alice adds Bob ===
    let (queued_messages, welcome) =
        match alice_group.add_members(&[bob_key_package_bundle.key_package().clone()]) {
            Ok((qm, welcome)) => (qm, welcome),
            Err(e) => panic!("Could not add member to group: {:?}", e),
        };

    alice_group
        .process_messages(queued_messages)
        .expect("The group is no longer active");

    let mut bob_group = ManagedGroup::new_from_welcome(
        &bob_credential_bundle,
        &managed_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree()),
        bob_key_package_bundle,
    )
    .expect("Error creating group from Welcome");

    // === Bob adds Charlie ===
    let (queued_messages, welcome) =
        match bob_group.add_members(&[charlie_key_package_bundle.key_package().clone()]) {
            Ok((qm, welcome)) => (qm, welcome),
            Err(e) => panic!("Could not add member to group: {:?}", e),
        };

    alice_group
        .process_messages(queued_messages.clone())
        .expect("The group is no longer active");
    bob_group
        .process_messages(queued_messages)
        .expect("The group is no longer active");

    let charlie_callbacks = ManagedGroupCallbacks::new().with_member_removed(member_removed);
    managed_group_config.set_callbacks(&charlie_callbacks);
    let mut charlie_group = ManagedGroup::new_from_welcome(
        &charlie_credential_bundle,
        &managed_group_config,
        welcome,
        Some(bob_group.export_ratchet_tree()),
        charlie_key_package_bundle,
    )
    .expect("Error creating group from Welcome");

    // === Alice removes Bob & Charlie commits ===

    let queued_messages = alice_group
        .propose_remove_members(&[1])
        .expect("Could not propose removal");

    charlie_group
        .process_messages(queued_messages)
        .expect("Could not process messages");

    let (queued_messages, _welcome) = charlie_group
        .process_pending_proposals()
        .expect("Could not commit proposal");

    charlie_group
        .process_messages(queued_messages)
        .expect("Could not process messages");
}
