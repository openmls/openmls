//! This module tests the validation of message framing as defined in
//! https://openmls.tech/book/message_validation.html#semantic-validation-of-message-framing

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{random::OpenMlsRand, types::Ciphersuite, OpenMlsCryptoProvider};
use tls_codec::{Deserialize, Serialize};

use rstest::*;
use rstest_reuse::{self, *};

use crate::{
    ciphersuite::hash_ref::KeyPackageRef,
    credentials::*,
    framing::*,
    group::{errors::*, *},
    key_packages::*,
};

use super::utils::{generate_credential_bundle, generate_key_package_bundle};

// Test setup values
struct ValidationTestSetup {
    alice_group: MlsGroup,
    _alice_credential: Credential,
    _bob_credential: Credential,
    _alice_key_package: KeyPackage,
    bob_key_package: KeyPackage,
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
    let alice_group = MlsGroup::new(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice(),
    )
    .expect("An unexpected error occurred.");

    ValidationTestSetup {
        alice_group,
        _alice_credential: alice_credential,
        _bob_credential: bob_credential,
        _alice_key_package: alice_key_package,
        bob_key_package,
    }
}

// ValSem001 Wire format
#[apply(ciphersuites_and_backends)]
fn test_valsem001(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    let mut serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let original_message = serialized_message.clone();

    serialized_message[0] = WireFormat::MlsCiphertext as u8;

    let err = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect_err("Could deserialize message despite wrong wire format.");

    assert_eq!(
        err,
        tls_codec::Error::DecodingError("Wrong wire format.".to_string())
    );

    // Positive case
    VerifiableMlsPlaintext::tls_deserialize(&mut original_message.as_slice())
        .expect("Unexpected error.");

    // Test with MlsCiphertext
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

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
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    plaintext.set_group_id(GroupId::from_slice(&[9, 9, 9]));

    let message_in = MlsMessageIn::from(plaintext);

    let err = alice_group
        .parse_message(message_in, backend)
        .expect_err("Could parse message despite wrong group ID.");

    assert_eq!(
        err,
        ParseMessageError::ValidationError(ValidationError::WrongGroupId)
    );

    // Positive case
    alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem003 Epoch
#[apply(ciphersuites_and_backends)]
fn test_valsem003(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Alice can't process her own commits, so we'll have to add Bob.
    let (_message, welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("error creating bob's group from welcome");

    // Now that we added bob, Alice needs to create a new message that Bob can process.
    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self update.");

    let unverified_message = bob_group
        .parse_message(message.into(), backend)
        .expect("Could not parse message.");
    let processed_message = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Could not process unverified message.");

    if let ProcessedMessage::StagedCommitMessage(staged_commit) = processed_message {
        bob_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge Commit message.");
    } else {
        unreachable!("Expected StagedCommit.");
    }

    // Do a second Commit to increase the epoch number
    let (message, _welcome) = bob_group
        .self_update(backend, None)
        .expect("Could not add member.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    // Set the epoch too high
    plaintext.set_epoch(100);

    let message_in = MlsMessageIn::from(plaintext.clone());

    let err = bob_group
        .parse_message(message_in, backend)
        .expect_err("Could parse message despite wrong epoch.");

    assert_eq!(
        err,
        ParseMessageError::ValidationError(ValidationError::WrongEpoch)
    );

    // Set the epoch too low
    plaintext.set_epoch(0);

    let message_in = MlsMessageIn::from(plaintext);

    let err = bob_group
        .parse_message(message_in, backend)
        .expect_err("Could parse message despite wrong epoch.");

    assert_eq!(
        err,
        ParseMessageError::ValidationError(ValidationError::WrongEpoch)
    );

    // Positive case
    bob_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem004 Sender: Member: check the member exists
#[apply(ciphersuites_and_backends)]
fn test_valsem004(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    let random_sender = Sender::build_member(&KeyPackageRef::from_slice(
        &backend
            .rand()
            .random_vec(16)
            .expect("An unexpected error occurred."),
    ));
    plaintext.set_sender(random_sender);

    let message_in = MlsMessageIn::from(plaintext);

    let err = alice_group
        .parse_message(message_in, backend)
        .expect_err("Could parse message despite wrong sender.");

    assert_eq!(
        err,
        ParseMessageError::ValidationError(ValidationError::UnknownMember)
    );

    // Positive case
    alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem005 Application messages must use ciphertext
#[apply(ciphersuites_and_backends)]
fn test_valsem005(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    plaintext.set_content_type(ContentType::Application);
    plaintext.set_content(MlsPlaintextContentType::Application(vec![1, 2, 3].into()));

    let message_in = MlsMessageIn::from(plaintext);

    let err = alice_group
        .parse_message(message_in, backend)
        .expect_err("Could parse message despite unencrypted application message.");

    assert_eq!(
        err,
        ParseMessageError::ValidationError(ValidationError::UnencryptedApplicationMessage)
    );

    // Positive case
    alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem006 Ciphertext: decryption needs to work
#[apply(ciphersuites_and_backends)]
fn test_valsem006(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (_message, welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    alice_group
        .merge_pending_commit()
        .expect("An unexpected error occurred.");

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

    let ratchet_tree = alice_group.export_ratchet_tree();

    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build();

    let mut bob_group =
        MlsGroup::new_from_welcome(backend, &mls_group_config, welcome, Some(ratchet_tree))
            .expect("An unexpected error occurred.");

    let err = bob_group
        .parse_message(message_in, backend)
        .expect_err("Could parse message despite garbled ciphertext.");

    assert_eq!(
        err,
        ParseMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::AeadError
        ))
    );

    // Positive case
    bob_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem007 Membership tag presence
#[apply(ciphersuites_and_backends)]
fn test_valsem007(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    plaintext.unset_membership_tag();

    let message_in = MlsMessageIn::from(plaintext);

    let err = alice_group
        .parse_message(message_in, backend)
        .expect_err("Could parse message despite missing membership tag.");

    assert_eq!(
        err,
        ParseMessageError::ValidationError(ValidationError::MissingMembershipTag)
    );

    // Positive case
    alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem008 Membership tag verification
#[apply(ciphersuites_and_backends)]
fn test_valsem008(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Alice can't process her own commits, so we'll have to add Bob.
    let (_message, welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("error creating bob's group from welcome");

    // Now that we added bob, Alice needs to create a new message that Bob can process.
    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self update.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    plaintext.set_membership_tag(MembershipTag(
        Mac::new(backend, &Secret::default(), &[1, 2, 3])
            .expect("Could not compute membership tag."),
    ));

    let message_in = MlsMessageIn::from(plaintext);

    let unverified_message = bob_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite wrong membership tag.");

    assert_eq!(err, UnverifiedMessageError::InvalidMembershipTag);

    // Positive case
    let unverified_message = bob_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Could not parse message.");
    bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem009 Confirmation tag presence
#[apply(ciphersuites_and_backends)]
fn test_valsem009(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    plaintext.set_confirmation_tag(None);

    let message_in = MlsMessageIn::from(plaintext);

    let err = alice_group
        .parse_message(message_in, backend)
        .expect_err("Could parse message despite missing confirmation tag.");

    assert_eq!(
        err,
        ParseMessageError::ValidationError(ValidationError::MissingConfirmationTag)
    );

    // Positive case
    alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem010 Signature verification
#[apply(ciphersuites_and_backends)]
fn test_valsem010(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Alice can't process her own commits, so we'll have to add Bob.
    let (_message, welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("error creating bob's group from welcome");

    // Now that we added bob, Alice needs to create a new message that Bob can process.
    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not self update.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
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
    let tbm_payload = MlsPlaintextTbmPayload::new(&tbs_payload, &signature, &confirmation_tag)
        .expect("Could not create MlsPlaintextTbm.");
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

    let unverified_message = bob_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite wrong signature.");

    assert_eq!(err, UnverifiedMessageError::InvalidSignature);

    // Positive case
    let unverified_message = bob_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Could not parse message.");
    bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}
