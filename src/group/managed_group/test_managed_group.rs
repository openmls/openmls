use crate::prelude::*;

#[test]
fn test_managed_group_persistence() {
    use std::fs::File;
    use std::path::Path;
    let ciphersuite = &Config::supported_ciphersuites()[0];
    let group_id = GroupId::from_slice(b"Test Group");

    let key_store = KeyStore::default();

    // Generate credential bundles
    let alice_credential = key_store
        .generate_credential_bundle(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();

    // Generate KeyPackages
    let alice_key_package = key_store
        .generate_key_package_bundle(&[ciphersuite.name()], &alice_credential, vec![])
        .unwrap();

    // Define the managed group configuration
    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let managed_group_config = ManagedGroupConfig::new(
        HandshakeMessageFormat::Plaintext,
        update_policy,
        0, // padding_size
        0, // number_of_resumption_secrets
        callbacks,
    );

    // === Alice creates a group ===

    let alice_group = ManagedGroup::new(
        &key_store,
        &managed_group_config,
        group_id,
        &alice_key_package.hash(),
    )
    .unwrap();

    let path = Path::new("target/test_managed_group_serialization.json");
    let out_file = &mut File::create(&path).expect("Could not create file");
    alice_group
        .save(out_file)
        .expect("Could not write group state to file");

    let in_file = File::open(&path).expect("Could not open file");

    let alice_group_deserialized = ManagedGroup::load(in_file, &ManagedGroupCallbacks::default())
        .expect("Could not deserialize managed group");

    assert_eq!(
        (
            alice_group.export_ratchet_tree(),
            alice_group.export_secret("test", &[], 32)
        ),
        (
            alice_group_deserialized.export_ratchet_tree(),
            alice_group_deserialized.export_secret("test", &[], 32)
        )
    );
}

// This tests if the remover is correctly passed to the callback when one member
// issues a RemoveProposal and another members issues the next Commit.
#[test]
fn remover() {
    let ciphersuite = &Config::supported_ciphersuites()[0];
    let group_id = GroupId::from_slice(b"Test Group");

    let key_store = KeyStore::default();

    // Generate credential bundles
    let alice_credential = key_store
        .generate_credential_bundle(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();

    let bob_credential = key_store
        .generate_credential_bundle(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();

    let charlie_credential = key_store
        .generate_credential_bundle(
            "Charly".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();

    // Generate KeyPackages
    let alice_key_package = key_store
        .generate_key_package_bundle(&[ciphersuite.name()], &alice_credential, vec![])
        .unwrap();

    let bob_key_package = key_store
        .generate_key_package_bundle(&[ciphersuite.name()], &bob_credential, vec![])
        .unwrap();

    let charlie_key_package = key_store
        .generate_key_package_bundle(&[ciphersuite.name()], &charlie_credential, vec![])
        .unwrap();

    // Define the managed group configuration

    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let mut managed_group_config = ManagedGroupConfig::new(
        HandshakeMessageFormat::Plaintext,
        update_policy,
        0, // padding_size
        0, // number_of_resumption_secrets
        callbacks,
    );

    // === Alice creates a group ===
    let mut alice_group = ManagedGroup::new(
        &key_store,
        &managed_group_config,
        group_id,
        &alice_key_package.hash(),
    )
    .unwrap();

    // === Alice adds Bob ===
    let (queued_messages, welcome) = match alice_group.add_members(&key_store, &[bob_key_package]) {
        Ok((qm, welcome)) => (qm, welcome),
        Err(e) => panic!("Could not add member to group: {:?}", e),
    };

    alice_group
        .process_messages(queued_messages)
        .expect("The group is no longer active");

    let mut bob_group = ManagedGroup::new_from_welcome(
        &key_store,
        &managed_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    // === Bob adds Charlie ===
    let (queued_messages, welcome) = match bob_group.add_members(&key_store, &[charlie_key_package])
    {
        Ok((qm, welcome)) => (qm, welcome),
        Err(e) => panic!("Could not add member to group: {:?}", e),
    };

    alice_group
        .process_messages(queued_messages.clone())
        .expect("The group is no longer active");
    bob_group
        .process_messages(queued_messages)
        .expect("The group is no longer active");

    let charlie_callbacks = ManagedGroupCallbacks::default();
    managed_group_config.set_callbacks(&charlie_callbacks);
    let mut charlie_group = ManagedGroup::new_from_welcome(
        &key_store,
        &managed_group_config,
        welcome,
        Some(bob_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    // === Alice removes Bob & Charlie commits ===

    let queued_messages = alice_group
        .propose_remove_members(&key_store, &[1])
        .expect("Could not propose removal");

    charlie_group
        .process_messages(queued_messages)
        .expect("Could not process messages");

    let (queued_messages, _welcome) = charlie_group
        .process_pending_proposals(&key_store)
        .expect("Could not commit proposal");

    let events = charlie_group
        .process_messages(queued_messages)
        .expect("Could not process messages");

    match events.first().expect("Expected an event to be returned") {
        GroupEvent::MemberRemoved(member_removed_event) => match member_removed_event.removal() {
            Removal::TheyWereRemovedBy(leaver, remover) => {
                assert_eq!(remover.identity(), b"Alice");
                assert_eq!(leaver.identity(), b"Bob");
            }
            _ => {
                unreachable!("We should not be here")
            }
        },
        _ => unreachable!("Expected a MemberRemoved event"),
    }
}

ctest_ciphersuites!(export_secret, test(ciphersuite_name: CiphersuiteName) {
    println!("Testing ciphersuite {:?}", ciphersuite_name);
    let ciphersuite = Config::ciphersuite(ciphersuite_name).unwrap();
    let group_id = GroupId::from_slice(b"Test Group");

    let key_store = KeyStore::default();

    // Generate credential bundles
    let alice_credential = key_store
        .generate_credential(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();

    // Generate KeyPackages
    let alice_key_package = key_store
        .generate_key_package(&[ciphersuite.name()], &alice_credential, vec![])
        .unwrap();

    // Define the managed group configuration
    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let managed_group_config = ManagedGroupConfig::new(
        HandshakeMessageFormat::Plaintext,
        update_policy,
        0, // padding_size
        0, // number_of_resumption_secrets
        callbacks,
    );

    // === Alice creates a group ===
    let alice_group = ManagedGroup::new(
        &key_store,
        &managed_group_config,
        group_id,
        &alice_key_package.hash(),
    )
    .unwrap();

    assert!(
        alice_group
            .export_secret("test1", &[], ciphersuite.hash_length())
            .unwrap()
            != alice_group
            .export_secret("test2", &[], ciphersuite.hash_length())
            .unwrap()
    );
    assert!(
        alice_group
            .export_secret("test", &[0u8], ciphersuite.hash_length())
            .unwrap()
            != alice_group
                .export_secret("test", &[1u8], ciphersuite.hash_length())
                .unwrap()
    )
});
