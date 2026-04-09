use openmls_test::openmls_test;

use crate::{
    framing::*,
    group::*,
    messages::external_proposals::*,
    messages::proposals::Proposal,
    prelude::{Capabilities, KeyPackage},
};

use openmls_traits::types::Ciphersuite;

use crate::group::tests_and_kats::utils::*;

// Creates a standalone group with extension capabilities for the Unknown extension 0xf001,
// and with the external senders group context extension.
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
        .capabilities(
            Capabilities::builder()
                .extensions(vec![ExtensionType::Unknown(0xf001)])
                .build(),
        )
        .with_group_context_extensions(
            Extensions::single(Extension::ExternalSenders(external_senders))
                .expect("failed to create single-element extensions list"),
        )
        .build();

    let group = MlsGroup::new_with_group_id(
        provider,
        &credential_with_keys.signer,
        &mls_group_config,
        group_id,
        credential_with_keys.credential_with_key.clone(),
    )
    .unwrap();

    assert!(group
        .own_leaf_node()
        .unwrap()
        .capabilities()
        .extensions()
        .contains(&ExtensionType::Unknown(0xf001)));

    (group, credential_with_keys)
}

// Validation test setup
// Sets up a group with members Alice and Bob,
// where their capabilities support the Unknown extension 0xf001,
// and on which the external senders group context extension is enabled.
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

    let bob_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(
            Capabilities::builder()
                .extensions(vec![ExtensionType::Unknown(0xf001)])
                .build(),
        )
        .build(
            ciphersuite,
            bob_provider,
            &bob_credential_with_key.signer,
            bob_credential_with_key.credential_with_key,
        )
        .unwrap();

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
fn external_group_context_ext_proposal_should_succeed() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ds_provider = &Provider::default();

    // delivery service credentials. DS will craft a proposal
    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        ds_provider,
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

    let old_extensions = alice_group.extensions().to_owned();
    assert!(!old_extensions.contains(ExtensionType::ApplicationId));

    // define the new group context extensions
    let extensions = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[], &[], &[]),
    ))
    .expect("failed to create single-element extensions list");

    // Now Delivery Service wants to update the group context extensions
    let external_group_context_ext_proposal: MlsMessageIn =
        ExternalProposal::new_group_context_extensions::<Provider>(
            extensions,
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
            external_group_context_ext_proposal
                .try_into_protocol_message()
                .unwrap(),
        )
        .unwrap();

    // commit the proposal
    let ProcessedMessageContent::ProposalMessage(proposal) = processed_message.into_content()
    else {
        panic!("Not a proposal");
    };
    if !matches!(proposal.proposal(), Proposal::GroupContextExtensions(_)) {
        panic!("Not a group context extensions proposal");
    }
    alice_group
        .store_pending_proposal(alice_provider.storage(), *proposal)
        .unwrap();
    let (_, _, _) = alice_group
        .commit_to_pending_proposals(alice_provider, &alice_credential.signer)
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    assert_ne!(*alice_group.extensions(), old_extensions);
    assert!(alice_group
        .extensions()
        .contains(ExtensionType::RequiredCapabilities));
}

#[openmls_test]
fn external_group_context_ext_proposal_should_succeed_unknown_extension() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ds_provider = &Provider::default();

    // delivery service credentials. DS will craft a proposal
    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        ds_provider,
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

    let old_extensions = alice_group.extensions().to_owned();
    assert!(!old_extensions.contains(ExtensionType::Unknown(0xf001)));

    // define the new group context extensions
    let extensions = Extensions::from_vec(vec![
        Extension::Unknown(0xf001, UnknownExtension(vec![1])),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(0xf001)],
            &[],
            &[],
        )),
    ])
    .unwrap();

    // Now Delivery Service wants to update the group context extensions
    let external_group_context_ext_proposal: MlsMessageIn =
        ExternalProposal::new_group_context_extensions::<Provider>(
            extensions,
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
            external_group_context_ext_proposal
                .try_into_protocol_message()
                .unwrap(),
        )
        .unwrap();

    // commit the proposal
    let ProcessedMessageContent::ProposalMessage(proposal) = processed_message.into_content()
    else {
        panic!("Not a proposal");
    };
    if !matches!(proposal.proposal(), Proposal::GroupContextExtensions(_)) {
        panic!("Not a group context extensions proposal");
    }
    alice_group
        .store_pending_proposal(alice_provider.storage(), *proposal)
        .unwrap();
    let (_, _, _) = alice_group
        .commit_to_pending_proposals(alice_provider, &alice_credential.signer)
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    assert_ne!(*alice_group.extensions(), old_extensions);
    assert!(alice_group
        .extensions()
        .contains(ExtensionType::Unknown(0xf001)));
}

#[openmls_test]
fn external_group_context_ext_proposal_should_fail_when_invalid_external_senders_index() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ds_provider = &Provider::default();

    // define the new group context extensions
    let extensions = Extensions::from_vec(vec![
        Extension::Unknown(0xf001, UnknownExtension(vec![1])),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(0xf001)],
            &[],
            &[],
        )),
    ])
    .unwrap();
    // delivery service credentials. DS will craft a proposal
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

    // Now Delivery Service wants to make group context extensions proposal,
    // with invalid sender index
    let external_group_context_ext_proposal: MlsMessageIn =
        ExternalProposal::new_group_context_extensions::<Provider>(
            extensions,
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
            alice_provider,
            external_group_context_ext_proposal
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
fn external_group_context_ext_proposal_should_fail_when_invalid_signature() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ds_provider = &Provider::default();

    // define the new group context extensions
    let extensions = Extensions::from_vec(vec![
        Extension::Unknown(0xf001, UnknownExtension(vec![1])),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(0xf001)],
            &[],
            &[],
        )),
    ])
    .unwrap();
    // delivery service credentials. DS will craft a proposal
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

    // Now Delivery Service wants to make group context extensions proposal
    let external_group_context_ext_proposal: MlsMessageIn =
        ExternalProposal::new_group_context_extensions::<Provider>(
            extensions,
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
            external_group_context_ext_proposal
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
fn external_group_context_ext_proposal_should_fail_when_no_external_senders() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ds_provider = &Provider::default();

    // define the new group context extensions
    let extensions = Extensions::from_vec(vec![
        Extension::Unknown(0xf001, UnknownExtension(vec![1])),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(0xf001)],
            &[],
            &[],
        )),
    ])
    .unwrap();

    let (mut alice_group, _) = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
        vec![],
    );

    // delivery service credentials. DS will craft a proposal
    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        ds_provider,
    );

    // Now Delivery Service wants to make group context extensions proposal
    let external_group_context_ext_proposal: MlsMessageIn =
        ExternalProposal::new_group_context_extensions::<Provider>(
            extensions,
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
            external_group_context_ext_proposal
                .try_into_protocol_message()
                .unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnauthorizedExternalSender)
    ));
}
