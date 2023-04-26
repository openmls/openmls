use crate::{
    framing::*,
    group::{config::CryptoConfig, errors::*, *},
    messages::external_proposals::*,
};

use openmls_traits::types::Ciphersuite;

use super::utils::*;

// Creates a standalone group
fn new_test_group(
    identity: &str,
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    external_senders: ExternalSendersExtension,
) -> (MlsGroup, CredentialWithKeyAndSigner) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let credential_with_keys =
        generate_credential_bundle(identity.into(), ciphersuite.signature_algorithm(), backend);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .external_senders(external_senders)
        .build();

    (
        MlsGroup::new_with_group_id(
            backend,
            &credential_with_keys.signer,
            &mls_group_config,
            group_id,
            credential_with_keys.credential_with_key.clone(),
        )
        .unwrap(),
        credential_with_keys,
    )
}

// Validation test setup
fn validation_test_setup(
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    external_senders: ExternalSendersExtension,
) -> (MlsGroup, CredentialWithKeyAndSigner) {
    // === Alice creates a group ===
    let (mut alice_group, alice_signer_when_keys) = new_test_group(
        "Alice",
        wire_format_policy,
        ciphersuite,
        backend,
        external_senders,
    );

    let bob_credential_bundle =
        generate_credential_bundle("Bob".into(), ciphersuite.signature_algorithm(), backend);

    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        backend,
        bob_credential_bundle,
    );

    alice_group
        .add_members(backend, &alice_signer_when_keys.signer, &[bob_key_package])
        .expect("error adding Bob to group");

    alice_group
        .merge_pending_commit(backend)
        .expect("error merging pending commit");
    assert_eq!(alice_group.members().count(), 2);

    (alice_group, alice_signer_when_keys)
}

#[openmls_test::openmls_test]
fn external_remove_proposal_should_remove_member(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // delivery service credentials. DS will craft an external remove proposal
    let ds_credential_bundle = generate_credential_bundle(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        backend,
    );

    let (mut alice_group, alice_credential) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        backend,
        vec![ExternalSender::new(
            ds_credential_bundle
                .credential_with_key
                .signature_key
                .clone(),
            ds_credential_bundle.credential_with_key.credential.clone(),
        )],
    );

    // DS is an allowed external sender of the group
    assert!(alice_group
         .group()
         .group_context_extensions()
         .iter()
         .any(|e| matches!(e, Extension::ExternalSenders(senders) if senders.iter().any(|s| s.credential() == &ds_credential_bundle.credential_with_key.credential) )));

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find(|member| member.credential.identity() == b"Bob")
        .map(|member| member.index)
        .unwrap();
    // Now Delivery Service wants to (already) remove Bob
    let bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_bundle.signer,
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .into();

    // Alice validates the message
    let processed_message = alice_group
        .process_message(backend, bob_external_remove_proposal)
        .unwrap();
    // commit the proposal
    let ProcessedMessageContent::ProposalMessage(remove_proposal) = processed_message.into_content() else { panic!("Not a remove proposal");};
    alice_group.store_pending_proposal(*remove_proposal);
    alice_group
        .commit_to_pending_proposals(backend, &alice_credential.signer)
        .unwrap();
    alice_group.merge_pending_commit(backend).unwrap();

    // Trying to do an external remove proposal of Bob now should fail as he no longer is in the group
    let invalid_bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove(
        // Bob is no longer in the group
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_bundle.signer,
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .into();
    let processed_message = alice_group
        .process_message(backend, invalid_bob_external_remove_proposal)
        .unwrap();
    // commit the proposal
    let ProcessedMessageContent::ProposalMessage(remove_proposal) = processed_message.into_content() else { panic!("Not a remove proposal");};
    alice_group.store_pending_proposal(*remove_proposal);
    assert_eq!(
        alice_group
            .commit_to_pending_proposals(backend, &alice_credential.signer)
            .unwrap_err(),
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::ProposalValidationError(
                ProposalValidationError::UnknownMemberRemoval
            )
        )
    );
}

#[openmls_test::openmls_test]
fn external_remove_proposal_should_fail_when_invalid_external_senders_index(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // delivery service credentials. DS will craft an external remove proposal
    let ds_credential_bundle = generate_credential_bundle(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        backend,
    );

    let (mut alice_group, _alice_credential) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        backend,
        vec![ExternalSender::new(
            ds_credential_bundle
                .credential_with_key
                .signature_key
                .clone(),
            ds_credential_bundle.credential_with_key.credential.clone(),
        )],
    );

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find(|member| member.credential.identity() == b"Bob")
        .map(|member| member.index)
        .unwrap();
    // Now Delivery Service wants to (already) remove Bob with invalid sender index
    let bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_bundle.signer,
        SenderExtensionIndex::new(10), // invalid sender index
    )
    .unwrap()
    .into();

    // Alice tries to validate the message and should fail as sender is invalid
    let error = alice_group
        .process_message(backend, bob_external_remove_proposal)
        .unwrap_err();
    assert_eq!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnauthorizedExternalSender)
    );
}

#[openmls_test::openmls_test]
fn external_remove_proposal_should_fail_when_invalid_signature(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // delivery service credentials. DS will craft an external remove proposal
    let ds_credential_bundle = generate_credential_bundle(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        backend,
    );

    let (mut alice_group, _alice_credential) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        backend,
        vec![ExternalSender::new(
            ds_credential_bundle
                .credential_with_key
                .signature_key
                .clone(),
            ds_credential_bundle.credential_with_key.credential,
        )],
    );

    let ds_invalid_credential_bundle = generate_credential_bundle(
        "delivery-service-invalid".into(),
        ciphersuite.signature_algorithm(),
        backend,
    );

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find(|member| member.credential.identity() == b"Bob")
        .map(|member| member.index)
        .unwrap();
    // Now Delivery Service wants to (already) remove Bob with invalid sender index
    let bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_invalid_credential_bundle.signer,
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .into();

    // Alice tries to validate the message and should fail as sender is invalid
    let error = alice_group
        .process_message(backend, bob_external_remove_proposal)
        .unwrap_err();
    assert_eq!(error, ProcessMessageError::InvalidSignature);
}

#[openmls_test::openmls_test]
fn external_remove_proposal_should_fail_when_no_external_senders(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let (mut alice_group, _) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        backend,
        vec![],
    );
    // delivery service credentials. DS will craft an external remove proposal
    let ds_credential_bundle = generate_credential_bundle(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        backend,
    );

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find(|member| member.credential.identity() == b"Bob")
        .map(|member| member.index)
        .unwrap();
    // Now Delivery Service wants to remove Bob with invalid sender index but there's no extension
    let bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_bundle.signer,
        SenderExtensionIndex::new(1), // invalid sender index
    )
    .unwrap()
    .into();

    // Alice tries to validate the message and should fail as sender is invalid
    let error = alice_group
        .process_message(backend, bob_external_remove_proposal)
        .unwrap_err();
    assert_eq!(
        error,
        ProcessMessageError::ValidationError(ValidationError::NoExternalSendersExtension)
    );
}
