use crate::{
    credentials::test_utils::new_credential,
    framing::errors::{MessageDecryptionError, SecretTreeError},
    group::{ProcessMessageError, ValidationError},
    prelude::*,
    test_utils::OpenMlsRustCrypto,
};

/// Test that ensures that the secret tree state is persisted correctly and that
/// replays are not possible.
#[test]
fn test_secret_tree_persistence() {
    let ciphersuite: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let group_id = GroupId::from_slice(b"Test Group");

    let alice_provider = &OpenMlsRustCrypto::default();
    let bob_provider = &OpenMlsRustCrypto::default();

    // Generate credentials with keys
    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    // Generate KeyPackage for Bob
    let bob_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(
            ciphersuite,
            bob_provider,
            &bob_signer,
            bob_credential.clone(),
        )
        .unwrap()
        .key_package()
        .to_owned();

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
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

    // === Bob process the message first time ===
    let _processed_message = bob_group
        .process_message(
            bob_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // === Test persistence after processing message ===
    bob_group
        .ensure_persistence(bob_provider.storage())
        .expect("Persistence check failed after first message processing");

    // === Bob processes the message second time (should fail) ===
    let _ = bob_group
        .process_message(
            bob_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect_err("This message should not be processed again to ensure forward secrecy.");

    // === Reload the group from storage ===
    let mut new_group = MlsGroup::load(bob_provider.storage(), bob_group.group_id())
        .unwrap()
        .unwrap();

    // === Bob processes the same message second time with its newly loaded group (which should be prohibited due to forward secrecy) ===
    let processed_message_second = new_group
        .process_message(
            bob_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect_err("This message should not be processed again to ensure forward secrecy.");

    // Verify that we get the correct SecretReuseError
    assert!(
        matches!(
            processed_message_second,
            ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError)
            ))
        ),
        "Expected SecretReuseError, got: {:?}",
        processed_message_second
    );
}
