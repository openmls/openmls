use crate::{
    group::mls_group::MessageSecretsStore,
    prelude::{test_utils::new_credential, *},
    storage::OpenMlsProvider,
};

use openmls_traits::signatures::Signer;

fn generate_key_package<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    extensions: Extensions,
    provider: &Provider,
    credential_with_key: CredentialWithKey,
    signer: &impl Signer,
) -> KeyPackage {
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
        .key_package()
        .clone()
}

/// This test checks that, after advancing the hash ratchet when decrypting messages,
/// we correctly write back the ratchet state to the storage provider.
///  - Alice creates a group
///  - Alice adds Bob
///  - Alice sends a message to Bob
///  - Bob processes message
#[openmls_test::openmls_test]
fn test_ratchet_writeback() {

    let wire_format_policy = MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY;

    let group_id = GroupId::from_slice(b"Test Group");

    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Generate credentials with keys
    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    // Generate KeyPackages
    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        bob_provider,
        bob_credential.clone(),
        &bob_signer,
    );

    // Define the MlsGroup configuration

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(wire_format_policy)
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        group_id.clone(),
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob ===
    let welcome = match alice_group.add_members(alice_provider, &alice_signer, &[bob_key_package]) {
        Ok((_, welcome, _)) => welcome,
        Err(e) => panic!("Could not add member to group: {e:?}"),
    };

    // Check that we received the correct proposals
    if let Some(staged_commit) = alice_group.pending_commit() {
        let _ = staged_commit
            .add_proposals()
            .next()
            .expect("Expected a proposal.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating StagedWelcome from Welcome")
    .into_group(bob_provider)
    .expect("Error creating group from StagedWelcome");

    // === Alice sends a message to Bob ===
    let message_alice = b"Hi, I'm Alice!";
    let queued_message = alice_group
        .create_message(alice_provider, &alice_signer, message_alice)
        .expect("Error creating application message");

    let bob_group_id = bob_group.group_id().clone();
    let current_epoch = bob_group.epoch();

    // Bob processes the message
    //
    // NOTE: within `MlsGroup::process_message()`,
    // updated keys should be put into storage.
    // Inside `process_message()`, `MlsGroup::decrypt_message()` is called,
    // and if the message is a `ProtocolMessage::PrivateMessage`,
    // `DecryptedMessage::from_inbound_ciphertext()` is called.

    let message_secrets_store_before: MessageSecretsStore = bob_provider
        .storage()
        .message_secrets::<GroupId, MessageSecretsStore>(&bob_group_id)
        .unwrap()
        .unwrap();

    let store_secrets_before = message_secrets_store_before.message_secrets().clone();
    let group_secrets_before = bob_group.message_secrets().clone();

    // Ensure that storage secrets match group secrets
    assert_eq!(store_secrets_before, group_secrets_before);

    // Ensure that storage secrets match group secrets
    assert_eq!(store_secrets_before, group_secrets_before);

    let _ = bob_group
        .process_message(
            bob_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that epochs are equal, because we do not move to a new epoch
    assert_eq!(current_epoch, bob_group.epoch());

    let message_secrets_store_after: MessageSecretsStore = bob_provider
        .storage()
        .message_secrets::<GroupId, MessageSecretsStore>(&bob_group_id)
        .unwrap()
        .unwrap();

    let store_secrets_after = message_secrets_store_after.message_secrets().clone();
    let group_secrets_after = bob_group.message_secrets().clone();

    // Ensure that storage secrets still match group secrets
    assert_eq!(store_secrets_after, group_secrets_after);

    // Ensure that group secrets have been updated
    assert_ne!(group_secrets_before, group_secrets_after);

    // TODO: Check that message secrets are updated to correct value
}
