use openmls_test::openmls_test;

use crate::{credentials::BasicCredential, framing::*, group::*, messages::external_proposals::*};

use openmls_traits::{types::Ciphersuite, OpenMlsProvider as _};

use crate::group::tests_and_kats::utils::*;

// Creates a standalone group
fn new_test_group(
    identity: &str,
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
    external_senders: ExternalSendersExtension,
) -> (MlsGroup, CredentialWithKeyAndSigner) {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credentials with keys
    let credential_with_keys =
        generate_credential_with_key(identity.into(), ciphersuite.signature_algorithm(), provider);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(wire_format_policy)
        .ciphersuite(ciphersuite)
        .with_group_context_extensions(Extensions::single(Extension::ExternalSenders(
            external_senders,
        )))
        .unwrap()
        .build();

    (
        MlsGroup::new_with_group_id(
            provider,
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
    provider: &impl crate::storage::OpenMlsProvider,
    external_senders: ExternalSendersExtension,
) -> (MlsGroup, CredentialWithKeyAndSigner) {
    // === Alice creates a group ===
    let (mut alice_group, alice_signer_when_keys) = new_test_group(
        "Alice",
        wire_format_policy,
        ciphersuite,
        provider,
        external_senders,
    );

    let bob_credential_with_key =
        generate_credential_with_key("Bob".into(), ciphersuite.signature_algorithm(), provider);

    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        provider,
        bob_credential_with_key,
    );

    alice_group
        .add_members(
            provider,
            &alice_signer_when_keys.signer,
            &[bob_key_package.key_package().clone()],
        )
        .expect("error adding Bob to group");

    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");
    assert_eq!(alice_group.members().count(), 2);

    (alice_group, alice_signer_when_keys)
}

#[openmls_test]
fn external_remove_proposal_should_remove_member() {
    // delivery service credentials. DS will craft an external remove proposal
    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        provider,
    );

    let (mut alice_group, alice_credential) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        provider,
        vec![ExternalSender::new(
            ds_credential_with_key
                .credential_with_key
                .signature_key
                .clone(),
            ds_credential_with_key
                .credential_with_key
                .credential
                .clone(),
        )],
    );

    // DS is an allowed external sender of the group
    assert!(alice_group
         .context()
         .extensions()
         .iter()
         .any(|e| matches!(e, Extension::ExternalSenders(senders) if senders.iter().any(|s| s.credential() == &ds_credential_with_key.credential_with_key.credential) )));

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find(|member| {
            let credential = BasicCredential::try_from(member.credential.clone()).unwrap();
            let identity = credential.identity();
            identity == b"Bob"
        })
        .map(|member| member.index)
        .unwrap();
    // Now Delivery Service wants to (already) remove Bob
    let bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove::<Provider>(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_with_key.signer,
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .into();

    // Alice validates the message
    let processed_message = alice_group
        .process_message(
            provider,
            bob_external_remove_proposal
                .try_into_protocol_message()
                .unwrap(),
        )
        .unwrap();
    // commit the proposal
    let ProcessedMessageContent::ProposalMessage(remove_proposal) =
        processed_message.into_content()
    else {
        panic!("Not a remove proposal");
    };
    alice_group
        .store_pending_proposal(provider.storage(), *remove_proposal)
        .unwrap();
    alice_group
        .commit_to_pending_proposals(provider, &alice_credential.signer)
        .unwrap();
    alice_group.merge_pending_commit(provider).unwrap();

    // Trying to do an external remove proposal of Bob now should fail as he no longer is in the group
    let invalid_bob_external_remove_proposal: MlsMessageIn =
        ExternalProposal::new_remove::<Provider>(
            // Bob is no longer in the group
            bob_index,
            alice_group.group_id().clone(),
            alice_group.epoch(),
            &ds_credential_with_key.signer,
            SenderExtensionIndex::new(0),
        )
        .unwrap()
        .into();
    let processed_message = alice_group
        .process_message(
            provider,
            invalid_bob_external_remove_proposal
                .try_into_protocol_message()
                .unwrap(),
        )
        .unwrap();
    // commit the proposal
    let ProcessedMessageContent::ProposalMessage(remove_proposal) =
        processed_message.into_content()
    else {
        panic!("Not a remove proposal");
    };
    alice_group
        .store_pending_proposal(provider.storage(), *remove_proposal)
        .unwrap();
    assert!(matches!(
        alice_group
            .commit_to_pending_proposals(provider, &alice_credential.signer)
            .unwrap_err(),
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::ProposalValidationError(
                ProposalValidationError::UnknownMemberRemoval
            )
        )
    ));
}

#[openmls_test]
fn external_remove_proposal_should_fail_when_invalid_external_senders_index<
    Provider: OpenMlsProvider,
>() {
    // delivery service credentials. DS will craft an external remove proposal
    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        provider,
    );

    let (mut alice_group, _alice_credential) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        provider,
        vec![ExternalSender::new(
            ds_credential_with_key
                .credential_with_key
                .signature_key
                .clone(),
            ds_credential_with_key
                .credential_with_key
                .credential
                .clone(),
        )],
    );

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find(|member| member.credential.serialized_content() == b"Bob")
        .map(|member| member.index)
        .unwrap();
    // Now Delivery Service wants to (already) remove Bob with invalid sender index
    let bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove::<Provider>(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_with_key.signer,
        SenderExtensionIndex::new(10), // invalid sender index
    )
    .unwrap()
    .into();

    // Alice tries to validate the message and should fail as sender is invalid
    let error = alice_group
        .process_message(
            provider,
            bob_external_remove_proposal
                .try_into_protocol_message()
                .unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnauthorizedExternalSender)
    ));
}

#[openmls_test]
fn external_remove_proposal_should_fail_when_invalid_signature() {
    // delivery service credentials. DS will craft an external remove proposal
    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        provider,
    );

    let (mut alice_group, _alice_credential) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        provider,
        vec![ExternalSender::new(
            ds_credential_with_key
                .credential_with_key
                .signature_key
                .clone(),
            ds_credential_with_key.credential_with_key.credential,
        )],
    );

    let ds_invalid_credential_with_key = generate_credential_with_key(
        "delivery-service-invalid".into(),
        ciphersuite.signature_algorithm(),
        provider,
    );

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find(|member| member.credential.serialized_content() == b"Bob")
        .map(|member| member.index)
        .unwrap();
    // Now Delivery Service wants to (already) remove Bob with invalid sender index
    let bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove::<Provider>(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_invalid_credential_with_key.signer,
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .into();

    // Alice tries to validate the message and should fail as sender is invalid
    let error = alice_group
        .process_message(
            provider,
            bob_external_remove_proposal
                .try_into_protocol_message()
                .unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::InvalidSignature)
    ));
}

#[openmls_test]
fn external_remove_proposal_should_fail_when_no_external_senders() {
    let (mut alice_group, _) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        provider,
        vec![],
    );
    // delivery service credentials. DS will craft an external remove proposal
    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        provider,
    );

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find(|member| member.credential.serialized_content() == b"Bob")
        .map(|member| member.index)
        .unwrap();
    // Now Delivery Service wants to remove Bob with invalid sender index but there's no extension
    let bob_external_remove_proposal: MlsMessageIn = ExternalProposal::new_remove::<Provider>(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_with_key.signer,
        SenderExtensionIndex::new(1), // invalid sender index
    )
    .unwrap()
    .into();

    // Alice tries to validate the message and should fail as sender is invalid
    let error = alice_group
        .process_message(
            provider,
            bob_external_remove_proposal
                .try_into_protocol_message()
                .unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnauthorizedExternalSender)
    ));
}
