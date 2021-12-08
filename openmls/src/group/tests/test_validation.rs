//! This module contains all tests regarding the validation of incoming messages
//! as defined in https://github.com/openmls/openmls/wiki/Message-validation

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme, OpenMlsCryptoProvider};
use tls_codec::{Deserialize, Serialize};

use crate::{
    ciphersuite::{Ciphersuite, CiphersuiteName, Mac, Secret},
    credentials::{Credential, CredentialBundle, CredentialError, CredentialType},
    extensions::Extension,
    framing::{
        ContentType, MembershipTag, MlsCiphertext, MlsCiphertextError, MlsMessageIn,
        MlsPlaintextContentType, MlsPlaintextError, MlsPlaintextTbmPayload, Sender,
        ValidationError, VerifiableMlsPlaintext, VerificationError, WireFormat,
    },
    group::{
        CoreGroupError, FramingValidationError, GroupEpoch, GroupId, MlsGroup, MlsGroupConfig,
        MlsGroupError,
    },
    key_packages::{KeyPackage, KeyPackageBundle, KeyPackageError},
    prelude::ProcessedMessage,
    test_utils::*,
    tree::index::LeafIndex,
};

// Helper function to generate a CredentialBundle
fn generate_credential_bundle(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_scheme: SignatureScheme,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<Credential, CredentialError> {
    let cb = CredentialBundle::new(identity, credential_type, signature_scheme, backend)?;
    let credential = cb.credential().clone();
    backend
        .key_store()
        .store(credential.signature_key(), &cb)
        .expect("An unexpected error occurred.");
    Ok(credential)
}

// Helper function to generate a KeyPackageBundle
fn generate_key_package_bundle(
    ciphersuites: &[CiphersuiteName],
    credential: &Credential,
    extensions: Vec<Extension>,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<KeyPackage, KeyPackageError> {
    let credential_bundle = backend
        .key_store()
        .read(credential.signature_key())
        .expect("An unexpected error occurred.");
    let kpb = KeyPackageBundle::new(ciphersuites, &credential_bundle, backend, extensions)?;
    let kp = kpb.key_package().clone();
    backend
        .key_store()
        .store(&kp.hash(backend).expect("Could not hash KeyPackage."), &kpb)
        .expect("An unexpected error occurred.");
    Ok(kp)
}

// Test setup values
#[cfg(test)]
struct ValidationTestSetup {
    alice_group: MlsGroup,
    _alice_credential: Credential,
    _bob_credential: Credential,
    _alice_key_package: KeyPackage,
    bob_key_package: KeyPackage,
}

// Validation test setup
fn validation_test_setup(
    wire_format: WireFormat,
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> ValidationTestSetup {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let bob_credential = generate_credential_bundle(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package_bundle(&[ciphersuite.name()], &alice_credential, vec![], backend)
            .expect("An unexpected error occurred.");

    let bob_key_package =
        generate_key_package_bundle(&[ciphersuite.name()], &bob_credential, vec![], backend)
            .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration

    let mls_group_config = MlsGroupConfig::builder().wire_format(wire_format).build();

    // === Alice creates a group ===
    let alice_group = MlsGroup::new(
        backend,
        &mls_group_config,
        group_id,
        &alice_key_package
            .hash(backend)
            .expect("Could not hash KeyPackage."),
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

// ValSem1 Wire format
#[apply(ciphersuites_and_backends)]
fn test_valsem1(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsPlaintext, ciphersuite, backend);

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
    } = validation_test_setup(WireFormat::MlsCiphertext, ciphersuite, backend);

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

// ValSem2 Group id
#[apply(ciphersuites_and_backends)]
fn test_valsem2(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsPlaintext, ciphersuite, backend);

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
        MlsGroupError::Group(CoreGroupError::FramingValidationError(
            FramingValidationError::WrongGroupId
        ))
    );

    // Positive case
    alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem3 Epoch
#[apply(ciphersuites_and_backends)]
fn test_valsem3(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsPlaintext, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    let unverified_message = alice_group
        .parse_message(message.into(), backend)
        .expect("Could not parse message.");
    let processed_message = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Could not process unverified message.");

    if let ProcessedMessage::StagedCommitMessage(staged_commit) = processed_message {
        alice_group
            .merge_staged_commit(*staged_commit)
            .expect("Could not merge Commit message.");
    } else {
        unreachable!("Expected StagedCommit.");
    }

    // Do a second Commit to increase the epoch number
    let (message, _welcome) = alice_group
        .self_update(backend, None)
        .expect("Could not add member.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    // Set the epoch too high
    plaintext.set_epoch(GroupEpoch(100));

    let message_in = MlsMessageIn::from(plaintext.clone());

    let err = alice_group
        .parse_message(message_in, backend)
        .expect_err("Could parse message despite wrong epoch.");

    assert_eq!(
        err,
        MlsGroupError::Group(CoreGroupError::FramingValidationError(
            FramingValidationError::WrongEpoch
        ))
    );

    // Set the epoch too low
    plaintext.set_epoch(GroupEpoch(0));

    let message_in = MlsMessageIn::from(plaintext);

    let err = alice_group
        .parse_message(message_in, backend)
        .expect_err("Could parse message despite wrong epoch.");

    assert_eq!(
        err,
        MlsGroupError::Group(CoreGroupError::FramingValidationError(
            FramingValidationError::WrongEpoch
        ))
    );

    // Positive case
    alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem4 Sender: Member: check the member exists
#[apply(ciphersuites_and_backends)]
fn test_valsem4(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsPlaintext, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_message = plaintext.clone();

    plaintext.set_sender(Sender {
        sender_type: crate::prelude::SenderType::Member,
        sender: LeafIndex::from(100u32),
    });

    let message_in = MlsMessageIn::from(plaintext);

    let err = alice_group
        .parse_message(message_in, backend)
        .expect_err("Could parse message despite wrong sender index.");

    assert_eq!(
        err,
        MlsGroupError::Group(CoreGroupError::FramingValidationError(
            FramingValidationError::UnknownMember
        ))
    );

    // Positive case
    alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem5 Application messages must use ciphertext
#[apply(ciphersuites_and_backends)]
fn test_valsem5(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsPlaintext, ciphersuite, backend);

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
        MlsGroupError::Group(CoreGroupError::ValidationError(
            ValidationError::UnencryptedApplicationMessage
        ))
    );

    // Positive case
    alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem6 Ciphertext: decryption needs to work
#[apply(ciphersuites_and_backends)]
fn test_valsem6(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsCiphertext, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut ciphertext = MlsCiphertext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_message = ciphertext.clone();

    ciphertext.set_ciphertext(vec![1, 2, 3]);

    let message_in = MlsMessageIn::from(ciphertext);

    let err = alice_group
        .parse_message(message_in, backend)
        .expect_err("Could parse message despite garbled ciphertext.");

    assert_eq!(
        err,
        MlsGroupError::Group(CoreGroupError::ValidationError(
            ValidationError::MlsCiphertextError(MlsCiphertextError::DecryptionError)
        ))
    );

    // Positive case
    alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem7 Membership tag presence
#[apply(ciphersuites_and_backends)]
fn test_valsem7(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsPlaintext, ciphersuite, backend);

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
        MlsGroupError::Group(CoreGroupError::ValidationError(
            ValidationError::MissingMembershipTag
        ))
    );

    // Positive case
    alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem8 Membership tag verification
#[apply(ciphersuites_and_backends)]
fn test_valsem8(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsPlaintext, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

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

    let unverified_message = alice_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite wrong membership tag.");

    assert_eq!(
        err,
        MlsGroupError::Group(CoreGroupError::ValidationError(
            ValidationError::MlsPlaintextError(MlsPlaintextError::VerificationError(
                VerificationError::InvalidMembershipTag
            ))
        ))
    );

    // Positive case
    let unverified_message = alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Could not parse message.");
    alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem9 Confirmation tag presence
#[apply(ciphersuites_and_backends)]
fn test_valsem9(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsPlaintext, ciphersuite, backend);

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
        MlsGroupError::Group(CoreGroupError::ValidationError(
            ValidationError::MissingConfirmationTag
        ))
    );

    // Positive case
    alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Unexpected error.");
}

// ValSem10 Signature verification
#[apply(ciphersuites_and_backends)]
fn test_valsem10(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let ValidationTestSetup {
        mut alice_group,
        _alice_credential: _,
        _bob_credential: _,
        _alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsPlaintext, ciphersuite, backend);

    let (message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

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
        .epoch_secrets()
        .membership_key()
        .tag(backend, tbm_payload)
        .expect("Could not create membership tag.");

    // Set the fake signature
    plaintext.set_signature(signature);

    // Set the new membership tag
    plaintext.set_membership_tag(new_membership_tag);

    let message_in = MlsMessageIn::from(plaintext);

    let unverified_message = alice_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite wrong signature.");

    assert_eq!(
        err,
        MlsGroupError::Group(CoreGroupError::ValidationError(
            ValidationError::CredentialError(CredentialError::InvalidSignature)
        ))
    );

    // Positive case
    let unverified_message = alice_group
        .parse_message(MlsMessageIn::from(original_message), backend)
        .expect("Could not parse message.");
    alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}
