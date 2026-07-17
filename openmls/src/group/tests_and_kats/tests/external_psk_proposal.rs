//! External-sender PreSharedKey proposal.
//!
//! RFC 9420 §12.1.8.2 permits an external sender (configured via the
//! `ExternalSendersExtension`) to send `PreSharedKey` proposals. This test
//! checks that OpenMLS both *creates* such a proposal
//! ([`ExternalProposal::new_pre_shared_key`]) and *accepts* it on the receiving
//! side (rather than rejecting it with `UnsupportedProposalType`).

use openmls_test::openmls_test;
use openmls_traits::types::Ciphersuite;

use crate::{
    framing::*,
    group::*,
    messages::external_proposals::*,
    messages::proposals::Proposal,
    prelude::{Capabilities, KeyPackage},
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
};

use crate::group::tests_and_kats::utils::*;

// Alice creates a group with Bob as a member and a delivery service (DS) as an
// allowed external sender.
fn setup(
    ciphersuite: Ciphersuite,
    alice_provider: &impl crate::storage::OpenMlsProvider,
    bob_provider: &impl crate::storage::OpenMlsProvider,
    external_senders: ExternalSendersExtension,
) -> (MlsGroup, CredentialWithKeyAndSigner) {
    let group_id = GroupId::from_slice(b"Test Group");

    let alice_credential_with_keys = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let mls_group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .capabilities(Capabilities::builder().build())
        .with_group_context_extensions(
            Extensions::single(Extension::ExternalSenders(external_senders))
                .expect("failed to create single-element extensions list"),
        )
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_credential_with_keys.signer,
        &mls_group_config,
        group_id,
        alice_credential_with_keys.credential_with_key.clone(),
    )
    .unwrap();

    let bob_credential_with_key = generate_credential_with_key(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let bob_key_package = KeyPackage::builder()
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
            &alice_credential_with_keys.signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .expect("error adding Bob to group");
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");
    assert_eq!(alice_group.members().count(), 2);

    (alice_group, alice_credential_with_keys)
}

// An external sender's PreSharedKey proposal is accepted on processing (it used
// to be rejected as `UnsupportedProposalType`).
#[openmls_test]
fn external_psk_proposal_should_be_accepted() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ds_provider = &Provider::default();

    // Delivery service credential -- the external sender.
    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        ds_provider,
    );

    let (mut alice_group, _alice_credential) = setup(
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

    // The DS crafts an external PreSharedKey proposal.
    let psk_id = PreSharedKeyId::new(
        ciphersuite,
        ds_provider.rand(),
        Psk::External(ExternalPsk::new(vec![1, 2, 3, 4, 5, 6, 7, 8])),
    )
    .unwrap();
    let external_psk_proposal: MlsMessageIn = ExternalProposal::new_pre_shared_key(
        psk_id,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_with_key.signer,
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .into();

    // Alice validates the message -- it must be accepted, not rejected as an
    // unsupported proposal type for the external sender.
    let processed_message = alice_group
        .process_message(
            alice_provider,
            external_psk_proposal.try_into_protocol_message().unwrap(),
        )
        .expect("external PSK proposal must be accepted");

    let ProcessedMessageContent::ProposalMessage(proposal) = processed_message.into_content()
    else {
        panic!("Not a proposal");
    };
    assert!(
        matches!(proposal.proposal(), Proposal::PreSharedKey(_)),
        "expected a PreSharedKey proposal"
    );
    assert!(matches!(proposal.sender(), Sender::External(_)));
}

// A PreSharedKey proposal from an *unauthorized* external sender is still
// rejected.
#[openmls_test]
fn external_psk_proposal_should_fail_when_invalid_external_senders_index() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ds_provider = &Provider::default();

    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        ds_provider,
    );

    let (mut alice_group, _alice_credential) = setup(
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

    let psk_id = PreSharedKeyId::new(
        ciphersuite,
        ds_provider.rand(),
        Psk::External(ExternalPsk::new(vec![1, 2, 3, 4, 5, 6, 7, 8])),
    )
    .unwrap();
    let external_psk_proposal: MlsMessageIn = ExternalProposal::new_pre_shared_key(
        psk_id,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_credential_with_key.signer,
        SenderExtensionIndex::new(10), // invalid sender index
    )
    .unwrap()
    .into();

    let error = alice_group
        .process_message(
            alice_provider,
            external_psk_proposal.try_into_protocol_message().unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnauthorizedExternalSender)
    ));
}
