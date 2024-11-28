//! This module tests the validation of message framing as defined in
//! https://book.openmls.tech/message_validation.html#semantic-validation-of-message-framing

use openmls_traits::prelude::{openmls_types::Ciphersuite, *};
use tls_codec::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafNodeIndex, framing::*, group::*, key_packages::*, treesync::LeafNodeParameters,
};

use crate::group::tests_and_kats::utils::{
    generate_credential_with_key, generate_key_package, CredentialWithKeyAndSigner,
};

// Test setup values
struct ValidationTestSetup {
    alice_group: MlsGroup,
    bob_group: MlsGroup,
    _alice_credential: CredentialWithKeyAndSigner,
    _bob_credential: CredentialWithKeyAndSigner,
    _alice_key_package: KeyPackage,
    _bob_key_package: KeyPackage,
}

// Validation test setup
fn validation_test_setup(
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) -> ValidationTestSetup {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credentials with keys
    let alice_credential =
        generate_credential_with_key("Alice".into(), ciphersuite.signature_algorithm(), provider);

    let bob_credential =
        generate_credential_with_key("Bob".into(), ciphersuite.signature_algorithm(), provider);

    // Generate KeyPackages
    let alice_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        provider,
        alice_credential.clone(),
    );

    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        provider,
        bob_credential.clone(),
    );

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(wire_format_policy)
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_credential.signer,
        &mls_group_create_config,
        group_id,
        alice_credential.credential_with_key.clone(),
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob & Bob joins ===
    let (_message, welcome, _group_info) = alice_group
        .add_members(
            provider,
            &alice_credential.signer,
            &[bob_key_package.key_package().clone()],
        )
        .expect("Could not add member.");

    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let bob_group = StagedWelcome::new_from_welcome(
        provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("error creating bob's group from welcome")
    .into_group(provider)
    .expect("error creating bob's group from welcome");

    ValidationTestSetup {
        alice_group,
        bob_group,
        _alice_credential: alice_credential,
        _bob_credential: bob_credential,
        _alice_key_package: alice_key_package.key_package().clone(),
        _bob_key_package: bob_key_package.key_package().clone(),
    }
}

// ValSem002 Group id
#[openmls_test::openmls_test]
fn test_valsem002() {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    let (message, _welcome, _group_info) = alice_group
        .self_update(
            provider,
            &_alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .expect("Could not self-update.")
        .into_contents();

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    let original_message = plaintext.clone();

    plaintext.set_group_id(GroupId::from_slice(&[9, 9, 9]));

    let message_in = ProtocolMessage::from(plaintext);

    let err = bob_group
        .process_message(provider, message_in)
        .expect_err("Could parse message despite wrong group ID.");

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::WrongGroupId)
    ));

    // Positive case
    bob_group
        .process_message(provider, ProtocolMessage::from(original_message))
        .expect("Unexpected error.");
}

// ValSem003 Epoch
#[openmls_test::openmls_test]
fn test_valsem003() {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // Alice needs to create a new message that Bob can process.
    let (message, _welcome, _group_info) = alice_group
        .self_update(
            provider,
            &_alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .expect("Could not self update.")
        .into_contents();
    alice_group.merge_pending_commit(provider).unwrap();

    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit.");

    let processed_message = bob_group
        .process_message(provider, message.into_protocol_message().unwrap())
        .expect("Could not process message.");

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    {
        bob_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging commit.");
    } else {
        unreachable!("Expected StagedCommit.");
    }

    // Do a second Commit to increase the epoch number
    let (message, _welcome, _group_info) = alice_group
        .self_update(
            provider,
            &_alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .expect("Could not add member.")
        .into_contents();

    let current_epoch = alice_group.epoch();

    let serialized_message = message.tls_serialize_detached().unwrap();
    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    let original_message = plaintext.clone();

    // Set the epoch too high
    plaintext.set_epoch(current_epoch.as_u64() + 1);
    let err = bob_group
        .process_message(provider, plaintext.clone())
        .expect_err("Could parse message despite wrong epoch.");
    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::WrongEpoch)
    ));

    // Set the epoch too low
    plaintext.set_epoch(current_epoch.as_u64() - 1);
    let err = bob_group
        .process_message(provider, plaintext)
        .expect_err("Could parse message despite wrong epoch.");
    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::WrongEpoch)
    ));

    // Positive case
    let processed_msg = bob_group
        .process_message(provider, original_message.clone())
        .unwrap();

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_msg.into_content()
    {
        bob_group
            .merge_staged_commit(provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!();
    }

    // Processing a commit twice should fail i.e. an epoch can only be used once in a commit message
    let process_twice = bob_group.process_message(provider, original_message);
    assert!(matches!(
        process_twice.unwrap_err(),
        ProcessMessageError::ValidationError(ValidationError::WrongEpoch)
    ));
}

// ValSem004 Sender: Member: check the member exists
#[openmls_test::openmls_test]
fn test_valsem004() {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    let (message, _welcome, _group_info) = alice_group
        .self_update(
            provider,
            &_alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .expect("Could not self-update.")
        .into_contents();

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    let original_message = plaintext.clone();

    let random_sender = Sender::build_member(LeafNodeIndex::new(987));
    plaintext.set_sender(random_sender);

    // The membership tag is checked before the sender, so we need to re-calculate it and set it
    plaintext
        .set_membership_tag(
            provider.crypto(),
            ciphersuite,
            alice_group.message_secrets().membership_key(),
            alice_group.message_secrets().serialized_context(),
        )
        .expect("Error setting membership tag.");

    let message_in = ProtocolMessage::from(plaintext);

    let err = bob_group
        .process_message(provider, message_in)
        .expect_err("Could parse message despite wrong sender.");

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::UnknownMember)
    ));

    // Positive case
    bob_group
        .process_message(provider, ProtocolMessage::from(original_message))
        .expect("Unexpected error.");
}

// ValSem005 Application messages must use ciphertext
#[openmls_test::openmls_test]
fn test_valsem005() {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    let (message, _welcome, _group_info) = alice_group
        .self_update(
            provider,
            &_alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .expect("Could not self-update.")
        .into_contents();

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    let original_message = plaintext.clone();

    plaintext.set_content(FramedContentBody::Application(vec![1, 2, 3].into()));

    // The membership tag is checked before verifying content encryption, so we need to re-calculate it and set it
    plaintext
        .set_membership_tag(
            provider.crypto(),
            ciphersuite,
            alice_group.message_secrets().membership_key(),
            alice_group.message_secrets().serialized_context(),
        )
        .expect("Error setting membership tag.");

    let message_in = ProtocolMessage::from(plaintext);

    let err = bob_group
        .process_message(provider, message_in)
        .expect_err("Could parse message despite unencrypted application message.");

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::UnencryptedApplicationMessage)
    ));

    // Positive case
    bob_group
        .process_message(provider, ProtocolMessage::from(original_message))
        .expect("Unexpected error.");
}

// ValSem006 Ciphertext: decryption needs to work
#[openmls_test::openmls_test]
fn test_valsem006() {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    let message = alice_group
        .create_message(provider, &_alice_credential.signer, &[1, 2, 3])
        .expect("An unexpected error occurred.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut ciphertext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_ciphertext()
        .expect("Message was not a plaintext.");

    let original_message = ciphertext.clone();

    ciphertext.set_ciphertext(vec![1, 2, 3]);

    let message_in = ProtocolMessage::from(ciphertext);

    let err = bob_group
        .process_message(provider, message_in)
        .expect_err("Could parse message despite garbled ciphertext.");

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::AeadError
        ))
    ));

    // Positive case
    bob_group
        .process_message(provider, ProtocolMessage::from(original_message))
        .expect("Unexpected error.");
}

// ValSem007 Membership tag presence
#[openmls_test::openmls_test]
fn test_valsem007() {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    let (message, _welcome, _group_info) = alice_group
        .self_update(
            provider,
            &_alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .expect("Could not self-update.")
        .into_contents();

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    let original_message = plaintext.clone();

    plaintext.unset_membership_tag();

    let message_in = ProtocolMessage::from(plaintext);

    let err = bob_group
        .process_message(provider, message_in)
        .expect_err("Could parse message despite missing membership tag.");

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::MissingMembershipTag)
    ));

    // Positive case
    bob_group
        .process_message(provider, ProtocolMessage::from(original_message))
        .expect("Unexpected error.");
}

// ValSem008 Membership tag verification
#[openmls_test::openmls_test]
fn test_valsem008() {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // Alice needs to create a new message that Bob can process.
    let (message, _welcome, _group_info) = alice_group
        .self_update(
            provider,
            &_alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .expect("Could not self-update.")
        .into_contents();

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    let original_message = plaintext.clone();

    plaintext.set_membership_tag_test(MembershipTag(
        Mac::new(
            provider.crypto(),
            ciphersuite,
            &Secret::default(),
            &[1, 2, 3],
        )
        .expect("Could not compute membership tag."),
    ));

    let message_in = ProtocolMessage::from(plaintext);

    let err = bob_group
        .process_message(provider, message_in)
        .expect_err("Could process message despite wrong membership tag.");

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::InvalidMembershipTag)
    ));

    // Positive case
    bob_group
        .process_message(provider, ProtocolMessage::from(original_message))
        .expect("Unexpected error.");
}

// ValSem009 Confirmation tag presence
#[openmls_test::openmls_test]
fn test_valsem009() {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    let (message, _welcome, _group_info) = alice_group
        .self_update(
            provider,
            &_alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .expect("Could not self-update.")
        .into_contents();

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    let original_message = plaintext.clone();

    plaintext.set_confirmation_tag(None);

    // The membership tag covers the confirmation tag, so we need to re-calculate it and set it
    plaintext
        .set_membership_tag(
            provider.crypto(),
            ciphersuite,
            alice_group.message_secrets().membership_key(),
            alice_group.message_secrets().serialized_context(),
        )
        .expect("Error setting membership tag.");

    let message_in = ProtocolMessage::from(plaintext);

    let err = bob_group
        .process_message(provider, message_in)
        .expect_err("Could parse message despite missing confirmation tag.");

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::MissingConfirmationTag)
    ));

    // Positive case
    bob_group
        .process_message(provider, ProtocolMessage::from(original_message))
        .expect("Unexpected error.");
}

// ValSem010 Signature verification
#[openmls_test::openmls_test]
fn test_valsem010() {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // Alice needs to create a new message that Bob can process.
    let (message, _welcome, _group_info) = alice_group
        .self_update(
            provider,
            &_alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .expect("Could not self update.")
        .into_contents();

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    let original_message = plaintext.clone();

    // Invalidate signature
    plaintext.invalidate_signature();

    // The membership tag covers the signature, so we need to re-calculate it and set it
    plaintext
        .set_membership_tag(
            provider.crypto(),
            ciphersuite,
            alice_group.message_secrets().membership_key(),
            alice_group.message_secrets().serialized_context(),
        )
        .expect("Error setting membership tag.");

    let message_in = ProtocolMessage::from(plaintext);

    let err = bob_group
        .process_message(provider, message_in)
        .expect_err("Could process message despite wrong signature.");

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::InvalidSignature)
    ));

    // Positive case
    bob_group
        .process_message(provider, ProtocolMessage::from(original_message))
        .expect("Unexpected error.");
}
