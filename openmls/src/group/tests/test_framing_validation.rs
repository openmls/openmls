//! This module tests the validation of message framing as defined in
//! https://openmls.tech/book/message_validation.html#semantic-validation-of-message-framing

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
use tls_codec::{Deserialize, Serialize};

use rstest::*;
use rstest_reuse::{self, *};

use crate::{
    credentials::*,
    framing::*,
    group::{errors::*, *},
    key_packages::*,
};

use super::utils::{generate_credential_bundle, generate_key_package_bundle};

// Test setup values
struct ValidationTestSetup {
    alice_group: MlsGroup,
    bob_group: MlsGroup,
    _alice_credential: Credential,
    _bob_credential: Credential,
    _alice_key_package: KeyPackage,
    _bob_key_package: KeyPackage,
}

// Validation test setup
fn validation_test_setup(
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> ValidationTestSetup {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let bob_credential = generate_credential_bundle(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package_bundle(&[ciphersuite], &alice_credential, vec![], backend)
            .expect("An unexpected error occurred.");

    let bob_key_package =
        generate_key_package_bundle(&[ciphersuite], &bob_credential, vec![], backend)
            .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice(),
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob & Bob joins ===
    let (_message, welcome) = alice_group
        .add_members(backend, &[bob_key_package.clone()])
        .expect("Could not add member.");

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    let bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("error creating bob's group from welcome");

    ValidationTestSetup {
        alice_group,
        bob_group,
        _alice_credential: alice_credential,
        _bob_credential: bob_credential,
        _alice_key_package: alice_key_package,
        _bob_key_package: bob_key_package,
    }
}

// ValSem001 Wire format
#[apply(ciphersuites_and_backends)]
fn test_valsem001(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let ValidationTestSetup {
        mut alice_group,
        bob_group: _,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self-update.");

    let mut serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let original_message = serialized_message.clone();

    serialized_message[0] = WireFormat::MlsCiphertext as u8;

    let err = VerifiableMlsAuthContent::tls_deserialize(&mut serialized_message.as_slice())
        .expect_err("Could deserialize message despite wrong wire format.");

    assert_eq!(
        err,
        tls_codec::Error::DecodingError("Wrong wire format.".to_string())
    );

    // Positive case
    VerifiableMlsAuthContent::tls_deserialize(&mut original_message.as_slice())
        .expect("Unexpected error.");

    // Test with MlsCiphertext
    let ValidationTestSetup {
        mut alice_group,
        bob_group: _,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self-update.");

    let mut serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let original_message = serialized_message.clone();

    serialized_message[0] = WireFormat::MlsPlaintext as u8;

    let err = MlsCiphertext::tls_deserialize(&mut serialized_message.as_slice())
        .expect_err("Could deserialize message despite wrong wire format.");

    assert_eq!(
        err,
        tls_codec::Error::DecodingError("Wrong wire format.".to_string())
    );

    // Positive case
    MlsCiphertext::tls_deserialize(&mut original_message.as_slice()).expect("Unexpected error.");
}

// ValSem002 Group id
#[apply(ciphersuites_and_backends)]
fn test_valsem002(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self-update.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext =
        VerifiableMlsAuthContent::tls_deserialize(&mut serialized_message.as_slice())
            .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    plaintext.set_group_id(GroupId::from_slice(&[9, 9, 9]));

    let message_in = MlsMessageIn::from(plaintext);

    let err = bob_group
        .process_message(backend, message_in)
        .expect_err("Could parse message despite wrong group ID.");

    assert_eq!(
        err,
        ProcessMessageError::ValidationError(ValidationError::WrongGroupId)
    );

    // Positive case
    bob_group
        .process_message(backend, MlsMessageIn::from(original_message))
        .expect("Unexpected error.");
}

// ValSem003 Epoch
#[apply(ciphersuites_and_backends)]
fn test_valsem003(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Alice needs to create a new message that Bob can process.
    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self update.");
    alice_group.merge_pending_commit().unwrap();

    alice_group
        .merge_pending_commit()
        .expect("Could not merge commit.");

    let processed_message = bob_group
        .process_message(backend, message.into())
        .expect("Could not process message.");

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    {
        bob_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge Commit message.");
    } else {
        unreachable!("Expected StagedCommit.");
    }

    // Do a second Commit to increase the epoch number
    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not add member.");

    let current_epoch = message.epoch();

    let serialized_message = message.tls_serialize_detached().unwrap();
    let mut plaintext =
        VerifiableMlsAuthContent::tls_deserialize(&mut serialized_message.as_slice())
            .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    // Set the epoch too high
    plaintext.set_epoch(current_epoch.as_u64() + 1);
    let err = bob_group
        .process_message(backend, plaintext.clone().into())
        .expect_err("Could parse message despite wrong epoch.");
    assert_eq!(
        err,
        ProcessMessageError::ValidationError(ValidationError::WrongEpoch)
    );

    // Set the epoch too low
    plaintext.set_epoch(current_epoch.as_u64() - 1);
    let err = bob_group
        .process_message(backend, plaintext.into())
        .expect_err("Could parse message despite wrong epoch.");
    assert_eq!(
        err,
        ProcessMessageError::ValidationError(ValidationError::WrongEpoch)
    );

    // Positive case
    let processed_msg = bob_group
        .process_message(backend, original_message.clone().into())
        .unwrap();

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_msg.into_content()
    {
        bob_group.merge_staged_commit(*staged_commit).unwrap();
    } else {
        unreachable!();
    }

    // Processing a commit twice should fail i.e. an epoch can only be used once in a commit message
    let process_twice = bob_group.process_message(backend, original_message.into());
    assert_eq!(
        process_twice.unwrap_err(),
        ProcessMessageError::ValidationError(ValidationError::WrongEpoch)
    );
}

// ValSem004 Sender: Member: check the member exists
#[apply(ciphersuites_and_backends)]
fn test_valsem004(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self-update.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext =
        VerifiableMlsAuthContent::tls_deserialize(&mut serialized_message.as_slice())
            .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    let random_sender = Sender::build_member(987);
    plaintext.set_sender(random_sender);

    let message_in = MlsMessageIn::from(plaintext);

    let err = bob_group
        .process_message(backend, message_in)
        .expect_err("Could parse message despite wrong sender.");

    assert_eq!(
        err,
        ProcessMessageError::ValidationError(ValidationError::UnknownMember)
    );

    // Positive case
    bob_group
        .process_message(backend, MlsMessageIn::from(original_message))
        .expect("Unexpected error.");
}

// ValSem005 Application messages must use ciphertext
#[apply(ciphersuites_and_backends)]
fn test_valsem005(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self-update.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext =
        VerifiableMlsAuthContent::tls_deserialize(&mut serialized_message.as_slice())
            .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    plaintext.set_content_body(MlsContentBody::Application(vec![1, 2, 3].into()));

    let message_in = MlsMessageIn::from(plaintext);

    let err = bob_group
        .process_message(backend, message_in)
        .expect_err("Could parse message despite unencrypted application message.");

    assert_eq!(
        err,
        ProcessMessageError::ValidationError(ValidationError::UnencryptedApplicationMessage)
    );

    // Positive case
    bob_group
        .process_message(backend, MlsMessageIn::from(original_message))
        .expect("Unexpected error.");
}

// ValSem006 Ciphertext: decryption needs to work
#[apply(ciphersuites_and_backends)]
fn test_valsem006(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let message = alice_group
        .create_message(backend, &[1, 2, 3])
        .expect("An unexpected error occurred.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut ciphertext = MlsCiphertext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_message = ciphertext.clone();

    ciphertext.set_ciphertext(vec![1, 2, 3]);

    let message_in = MlsMessageIn::from(ciphertext);

    let err = bob_group
        .process_message(backend, message_in)
        .expect_err("Could parse message despite garbled ciphertext.");

    assert_eq!(
        err,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::AeadError
        ))
    );

    // Positive case
    bob_group
        .process_message(backend, MlsMessageIn::from(original_message))
        .expect("Unexpected error.");
}

// ValSem007 Membership tag presence
#[apply(ciphersuites_and_backends)]
fn test_valsem007(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self-update.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext =
        VerifiableMlsAuthContent::tls_deserialize(&mut serialized_message.as_slice())
            .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    plaintext.unset_membership_tag();

    let message_in = MlsMessageIn::from(plaintext);

    let err = bob_group
        .process_message(backend, message_in)
        .expect_err("Could parse message despite missing membership tag.");

    assert_eq!(
        err,
        ProcessMessageError::ValidationError(ValidationError::MissingMembershipTag)
    );

    // Positive case
    bob_group
        .process_message(backend, MlsMessageIn::from(original_message))
        .expect("Unexpected error.");
}

// ValSem008 Membership tag verification
#[apply(ciphersuites_and_backends)]
fn test_valsem008(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Alice needs to create a new message that Bob can process.
    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self-update.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext =
        VerifiableMlsAuthContent::tls_deserialize(&mut serialized_message.as_slice())
            .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    plaintext.set_membership_tag(MembershipTag(
        Mac::new(backend, &Secret::default(), &[1, 2, 3])
            .expect("Could not compute membership tag."),
    ));

    let message_in = MlsMessageIn::from(plaintext);

    let err = bob_group
        .process_message(backend, message_in)
        .expect_err("Could process message despite wrong membership tag.");

    assert_eq!(err, ProcessMessageError::InvalidMembershipTag);

    // Positive case
    bob_group
        .process_message(backend, MlsMessageIn::from(original_message))
        .expect("Unexpected error.");
}

// ValSem009 Confirmation tag presence
#[apply(ciphersuites_and_backends)]
fn test_valsem009(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self-update.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext =
        VerifiableMlsAuthContent::tls_deserialize(&mut serialized_message.as_slice())
            .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    plaintext.set_confirmation_tag(None);

    let message_in = MlsMessageIn::from(plaintext);

    let err = bob_group
        .process_message(backend, message_in)
        .expect_err("Could parse message despite missing confirmation tag.");

    assert_eq!(
        err,
        ProcessMessageError::ValidationError(ValidationError::MissingConfirmationTag)
    );

    // Positive case
    bob_group
        .process_message(backend, MlsMessageIn::from(original_message))
        .expect("Unexpected error.");
}

// ValSem010 Signature verification
#[apply(ciphersuites_and_backends)]
fn test_valsem010(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        mut bob_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        _bob_key_package: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Alice needs to create a new message that Bob can process.
    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self update.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext =
        VerifiableMlsAuthContent::tls_deserialize(&mut serialized_message.as_slice())
            .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    let confirmation_tag = Some(
        plaintext
            .confirmation_tag()
            .expect("Expected confirmation tag.")
            .clone(),
    );

    // Create fake signature
    let mut signature = plaintext.signature().clone();
    signature.modify(&[1, 2, 3]);

    // The membership tag covers the signature, so we need to re-calculate it and set it

    // Set the serialized group context
    plaintext.set_context(
        alice_group
            .group()
            .context()
            .tls_serialize_detached()
            .expect("Could not serialize the group context."),
    );
    let tbs_payload = plaintext
        .payload()
        .tls_serialize_detached()
        .expect("Could not serialize Tbs.");
    let auth_data = MlsContentAuthData::new(signature.clone(), confirmation_tag);
    let tbm_payload =
        MlsContentTbm::new(&tbs_payload, &auth_data).expect("Could not create MlsContentTbm.");
    let new_membership_tag = alice_group
        .group()
        .message_secrets()
        .membership_key()
        .tag(backend, tbm_payload)
        .expect("Could not create membership tag.");

    // Set the fake signature
    plaintext.set_signature(signature);

    // Set the new membership tag
    plaintext.set_membership_tag(new_membership_tag);

    let message_in = MlsMessageIn::from(plaintext);

    let err = bob_group
        .process_message(backend, message_in)
        .expect_err("Could process message despite wrong signature.");

    assert_eq!(err, ProcessMessageError::InvalidSignature);

    // Positive case
    bob_group
        .process_message(backend, MlsMessageIn::from(original_message))
        .expect("Unexpected error.");
}
