use openmls_test::openmls_test;

use crate::{framing::*, group::*, messages::external_proposals::*};

use openmls_traits::types::Ciphersuite;

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
        .with_group_context_extensions(
            Extensions::single(Extension::ExternalSenders(external_senders))
                .expect("failed to create single-element extensions list"),
        )
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
    alice_provider: &impl crate::storage::OpenMlsProvider,
    bob_provider: &impl crate::storage::OpenMlsProvider,
    external_senders: ExternalSendersExtension,
) -> (MlsGroup, CredentialWithKeyAndSigner) {
    // === Alice creates a group ===
    let (mut alice_group, alice_signer_when_keys) = new_test_group(
        "Alice",
        wire_format_policy,
        ciphersuite,
        alice_provider,
        external_senders,
    );

    let bob_credential_with_key = generate_credential_with_key(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        bob_provider,
        bob_credential_with_key,
    );

    alice_group
        .add_members(
            alice_provider,
            &alice_signer_when_keys.signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .expect("error adding Bob to group");

    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");
    assert_eq!(alice_group.members().count(), 2);

    (alice_group, alice_signer_when_keys)
}

#[openmls_test]
fn external_add_proposal_should_suceeed() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // delivery service credentials. DS will craft an external add proposal
    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let (mut alice_group, alice_credential) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
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

    // A new client, Charlie, wants to be in the group
    let charlie_provider = &Provider::default();
    let charlie_credential = generate_credential_with_key(
        "Charlie".into(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );

    let charlie_kp = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        charlie_provider,
        charlie_credential.clone(),
    );

    // Now Delivery Service wants to add Charlie
    let charlie_external_add_proposal: MlsMessageIn = ExternalProposal::new_add::<Provider>(
        charlie_kp.key_package,
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
            alice_provider,
            charlie_external_add_proposal
                .try_into_protocol_message()
                .unwrap(),
        )
        .unwrap();

    // commit the proposal
    let ProcessedMessageContent::ProposalMessage(add_proposal) = processed_message.into_content()
    else {
        panic!("Not an add proposal");
    };
    alice_group
        .store_pending_proposal(alice_provider.storage(), *add_proposal)
        .unwrap();
    let (_, welcome, _) = alice_group
        .commit_to_pending_proposals(alice_provider, &alice_credential.signer)
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();
    assert_eq!(alice_group.members().count(), 3);

    let welcome: MlsMessageIn = welcome.expect("expected a welcome").into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    // Finally, Charlie can join with the Welcome
    let mls_group_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let charlie_group = StagedWelcome::new_from_welcome(
        charlie_provider,
        &mls_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(charlie_provider)
    .unwrap();
    assert_eq!(charlie_group.members().count(), 3);
}

#[openmls_test]
fn external_add_proposal_should_fail_when_invalid_external_senders_index<
    Provider: OpenMlsProvider,
>() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ds_provider = &Provider::default();

    // delivery service credentials. DS will craft an external add proposal
    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        ds_provider,
    );

    let (mut alice_group, _alice_credential) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
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

    // A new client, Charlie, wants to be in the group
    let charlie_provider = &Provider::default();
    let charlie_credential = generate_credential_with_key(
        "Charlie".into(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );

    let charlie_kp = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        charlie_provider,
        charlie_credential.clone(),
    );

    // Now Delivery Service wants to add Charlie with invalid sender index
    let charlie_external_add_proposal: MlsMessageIn = ExternalProposal::new_add::<Provider>(
        charlie_kp.key_package,
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
            charlie_provider,
            charlie_external_add_proposal
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
fn external_add_proposal_should_fail_when_invalid_signature() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ds_provider = &Provider::default();

    // delivery service credentials. DS will craft an external add proposal
    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        ds_provider,
    );

    let (mut alice_group, _alice_credential) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
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
        ds_provider,
    );

    // A new client, Charlie, wants to be in the group
    let charlie_provider = &Provider::default();
    let charlie_credential = generate_credential_with_key(
        "Charlie".into(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );

    let charlie_kp = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        charlie_provider,
        charlie_credential.clone(),
    );

    // Now Delivery Service wants to add Charlie with invalid sender signature
    let charlie_external_add_proposal: MlsMessageIn = ExternalProposal::new_add::<Provider>(
        charlie_kp.key_package,
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
            alice_provider,
            charlie_external_add_proposal
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
fn external_add_proposal_should_fail_when_no_external_senders() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ds_provider = &Provider::default();

    let (mut alice_group, _) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
        vec![],
    );

    // delivery service credentials. DS will craft an external add proposal
    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        ds_provider,
    );

    // A new client, Charlie, wants to be in the group
    let charlie_provider = &Provider::default();
    let charlie_credential = generate_credential_with_key(
        "Charlie".into(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );

    let charlie_kp = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        charlie_provider,
        charlie_credential.clone(),
    );

    // Now Delivery Service wants to add Charlie with invalid sender index but there's no extension
    let charlie_external_add_proposal: MlsMessageIn = ExternalProposal::new_add::<Provider>(
        charlie_kp.key_package,
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
            alice_provider,
            charlie_external_add_proposal
                .try_into_protocol_message()
                .unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnauthorizedExternalSender)
    ));
}
