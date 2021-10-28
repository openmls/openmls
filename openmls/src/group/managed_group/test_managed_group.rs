use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme, OpenMlsCryptoProvider};

use crate::{
    prelude::*,
    test_utils::test_framework::{
        errors::ClientError, ActionType::Commit, CodecUse, ManagedTestSetup,
    },
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
        .store(credential.signature_key(), &cb)
        .unwrap();
    Ok(credential)
}

fn generate_key_package_bundle(
    key_store: &impl OpenMlsCryptoProvider,
    ciphersuites: &[CiphersuiteName],
    credential: &Credential,
    extensions: Vec<Extension>,
) -> Result<KeyPackage, KeyPackageError> {
    let credential_bundle = key_store
        .key_store()
        .read(credential.signature_key())
        .unwrap();
    let kpb = KeyPackageBundle::new(ciphersuites, &credential_bundle, key_store, extensions)?;
    let kp = kpb.key_package().clone();
    key_store
        .key_store()
        .store(&kp.hash(key_store), &kpb)
        .unwrap();
    Ok(kp)
}

#[test]
fn test_managed_group_persistence() {
    let crypto = OpenMlsRustCrypto::default();
    let ciphersuite = &Config::supported_ciphersuites()[0];
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        &crypto,
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .unwrap();

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package_bundle(&crypto, &[ciphersuite.name()], &alice_credential, vec![])
            .unwrap();

    // Define the managed group configuration
    let managed_group_config = ManagedGroupConfig::test_default();

    // === Alice creates a group ===

    let alice_group = ManagedGroup::new(
        &crypto,
        &managed_group_config,
        group_id,
        &alice_key_package.hash(&crypto),
    )
    .unwrap();

    let mut file_out = tempfile::NamedTempFile::new().expect("Could not create file");
    alice_group
        .save(&mut file_out)
        .expect("Could not write group state to file");

    let file_in = file_out
        .reopen()
        .expect("Error re-opening serialized group state file");
    let alice_group_deserialized = ManagedGroup::load(file_in, &ManagedGroupCallbacks::default())
        .expect("Could not deserialize managed group");

    assert_eq!(
        (
            alice_group.export_ratchet_tree(),
            alice_group.export_secret(&crypto, "test", &[], 32)
        ),
        (
            alice_group_deserialized.export_ratchet_tree(),
            alice_group_deserialized.export_secret(&crypto, "test", &[], 32)
        )
    );
}

// This tests if the remover is correctly passed to the callback when one member
// issues a RemoveProposal and another members issues the next Commit.
#[test]
fn remover() {
    let crypto = &OpenMlsRustCrypto::default();
    let ciphersuite = &Config::supported_ciphersuites()[0];
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        crypto,
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .unwrap();

    let bob_credential = generate_credential_bundle(
        crypto,
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .unwrap();

    let charlie_credential = generate_credential_bundle(
        crypto,
        "Charly".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .unwrap();

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package_bundle(crypto, &[ciphersuite.name()], &alice_credential, vec![])
            .unwrap();

    let bob_key_package =
        generate_key_package_bundle(crypto, &[ciphersuite.name()], &bob_credential, vec![])
            .unwrap();

    let charlie_key_package =
        generate_key_package_bundle(crypto, &[ciphersuite.name()], &charlie_credential, vec![])
            .unwrap();

    // Define the managed group configuration
    let mut managed_group_config = ManagedGroupConfig::default();

    // === Alice creates a group ===
    let mut alice_group = ManagedGroup::new(
        crypto,
        &managed_group_config,
        group_id,
        &alice_key_package.hash(crypto),
    )
    .unwrap();

    // === Alice adds Bob ===
    let (queued_message, welcome) = match alice_group.add_members(crypto, &[bob_key_package]) {
        Ok((qm, welcome)) => (qm, welcome),
        Err(e) => panic!("Could not add member to group: {:?}", e),
    };

    alice_group
        .process_message(queued_message.into(), crypto)
        .expect("Process message error");

    let mut bob_group = ManagedGroup::new_from_welcome(
        crypto,
        &managed_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    // === Bob adds Charlie ===
    let (queued_messages, welcome) = match bob_group.add_members(crypto, &[charlie_key_package]) {
        Ok((qm, welcome)) => (qm, welcome),
        Err(e) => panic!("Could not add member to group: {:?}", e),
    };

    alice_group
        .process_message(queued_messages.clone().into(), crypto)
        .expect("The group is no longer active");
    bob_group
        .process_message(queued_messages.into(), crypto)
        .expect("The group is no longer active");

    let charlie_callbacks = ManagedGroupCallbacks::default();
    managed_group_config.set_callbacks(&charlie_callbacks);
    let mut charlie_group = ManagedGroup::new_from_welcome(
        crypto,
        &managed_group_config,
        welcome,
        Some(bob_group.export_ratchet_tree()),
    )
    .expect("Error creating group from Welcome");

    // === Alice removes Bob & Charlie commits ===

    let queued_messages = alice_group
        .propose_remove_member(crypto, 1)
        .expect("Could not propose removal");

    charlie_group
        .process_message(queued_messages.into(), crypto)
        .expect("Could not process messages");

    let (queued_messages, _welcome) = charlie_group
        .process_pending_proposals(crypto)
        .expect("Could not commit proposal");

    let events = charlie_group
        .process_message(queued_messages.into(), crypto)
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

    let crypto = &OpenMlsRustCrypto::default();
    println!("Testing ciphersuite {:?}", ciphersuite_name);
    let ciphersuite = Config::ciphersuite(ciphersuite_name).unwrap();
    let group_id = GroupId::from_slice(b"Test Group");



    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
            crypto,
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();

    // Generate KeyPackages
    let alice_key_package = generate_key_package_bundle(
            crypto,
            &[ciphersuite.name()],
            &alice_credential,
            vec![],
        )
        .unwrap();

    // Define the managed group configuration
    let managed_group_config = ManagedGroupConfig::builder().wire_format(WireFormat::MlsPlaintext).build();

    // === Alice creates a group ===
    let alice_group = ManagedGroup::new(


        crypto,
        &managed_group_config,
        group_id,
        &alice_key_package.hash(crypto),
    )
    .unwrap();

    assert!(
        alice_group
            .export_secret(crypto, "test1", &[], ciphersuite.hash_length())
            .unwrap()
            != alice_group
            .export_secret(crypto, "test2", &[], ciphersuite.hash_length())
            .unwrap()
    );
    assert!(
        alice_group
            .export_secret(crypto, "test", &[0u8], ciphersuite.hash_length())
            .unwrap()
            != alice_group
                .export_secret(crypto, "test", &[1u8], ciphersuite.hash_length())
                .unwrap()
    )
});

#[test]
fn test_invalid_plaintext() {
    let ciphersuite_name = Ciphersuite::default().name();
    println!("Testing ciphersuite {:?}", ciphersuite_name);
    let ciphersuite = Config::ciphersuite(ciphersuite_name).unwrap();

    // Some basic setup functions for the managed group.
    let managed_group_config = ManagedGroupConfig::builder()
        .wire_format(WireFormat::MlsPlaintext)
        .padding_size(10)
        .build();

    let number_of_clients = 20;
    let setup = ManagedTestSetup::new(
        managed_group_config,
        number_of_clients,
        CodecUse::StructMessages,
    );
    // Create a basic group with more than 4 members to create a tree with intermediate nodes.
    let group_id = setup.create_random_group(10, ciphersuite).unwrap();
    let mut groups = setup.groups.borrow_mut();
    let group = groups.get_mut(&group_id).unwrap();

    let (_, client_id) = &group
        .members
        .iter()
        .find(|(index, _)| index == &0)
        .unwrap()
        .clone();

    let clients = setup.clients.borrow();
    let client = clients.get(client_id).unwrap().borrow();

    let (mls_message, _welcome_option) = client
        .self_update(Commit, &group_id, None)
        .expect("error creating self update");

    drop(client);
    drop(clients);

    // Tamper with the message such that signature verification fails
    let mut msg_invalid_signature = mls_message.clone();
    if let MlsMessageOut::Plaintext(ref mut pt) = msg_invalid_signature {
        pt.invalidate_signature()
    };

    let error = setup
        .distribute_to_members(client_id, group, &msg_invalid_signature)
        .expect_err("No error when distributing message with invalid signature.");

    assert_eq!(
        ClientError::ManagedGroupError(ManagedGroupError::CredentialError(
            CredentialError::InvalidSignature
        )),
        error
    );

    // Tamper with the message such that sender lookup fails
    let mut msg_invalid_sender = mls_message;
    match &mut msg_invalid_sender {
        MlsMessageOut::Plaintext(pt) => pt.set_sender(Sender {
            sender_type: pt.sender().sender_type,
            sender: LeafIndex::from(group.members.len() + 1),
        }),
        MlsMessageOut::Ciphertext(_) => panic!("This should be a plaintext!"),
    };

    let error = setup
        .distribute_to_members(client_id, group, &msg_invalid_sender)
        .expect_err("No error when distributing message with invalid signature.");

    assert_eq!(
        ClientError::ManagedGroupError(ManagedGroupError::InvalidMessage(
            InvalidMessageError::UnknownSender
        )),
        error
    )
}
