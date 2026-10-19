use openmls_test::openmls_test;

use crate::{
    component::ComponentData,
    framing::*,
    group::{proposal_store::ProposalStore, public_group::PublicGroup, *},
    messages::external_proposals::*,
    messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal, ProposalType},
    prelude::{
        processing::{AppDataDictionaryUpdater, AppDataUpdates},
        Capabilities, CredentialType, KeyPackage,
    },
};

use openmls_traits::types::Ciphersuite;

use crate::group::tests_and_kats::utils::*;

const COMPONENT_ID: u16 = 0xf042;

// Sets up a group with members Alice and Bob, both supporting AppDataUpdate
// proposals, with `ds` as the only external sender, and a PublicGroup that
// tracks the group.
fn validation_test_setup(
    ciphersuite: Ciphersuite,
    alice_provider: &impl crate::storage::OpenMlsProvider,
    bob_provider: &impl crate::storage::OpenMlsProvider,
    public_provider: &impl crate::storage::OpenMlsProvider,
    ds: &CredentialWithKeyAndSigner,
) -> (MlsGroup, CredentialWithKeyAndSigner, MlsGroup, PublicGroup) {
    let capabilities = Capabilities::builder()
        .ciphersuites(vec![ciphersuite])
        .credentials(vec![CredentialType::Basic])
        .extensions(vec![ExtensionType::AppDataDictionary])
        .proposals(vec![ProposalType::AppDataUpdate])
        .build();
    let group_context_extensions = Extensions::from_vec(vec![
        Extension::ExternalSenders(vec![ExternalSender::new(
            ds.credential_with_key.signature_key.clone(),
            ds.credential_with_key.credential.clone(),
        )]),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::AppDataDictionary],
            &[ProposalType::AppDataUpdate],
            &[],
        )),
    ])
    .unwrap();
    let mls_group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .capabilities(capabilities.clone())
        .with_group_context_extensions(group_context_extensions)
        .build();

    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_credential.signer,
        &mls_group_config,
        GroupId::from_slice(b"Test Group"),
        alice_credential.credential_with_key.clone(),
    )
    .unwrap();

    let bob_credential = generate_credential_with_key(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );
    let bob_key_package = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(
            ciphersuite,
            bob_provider,
            &bob_credential.signer,
            bob_credential.credential_with_key,
        )
        .unwrap();
    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_credential.signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_config.join_config(),
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(bob_provider)
    .unwrap();

    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_credential.signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let (public_group, _extensions) = PublicGroup::from_external(
        public_provider.crypto(),
        public_provider.storage(),
        alice_group.export_ratchet_tree().into(),
        verifiable_group_info,
        ProposalStore::new(),
    )
    .unwrap();

    (alice_group, alice_credential, bob_group, public_group)
}

// Application logic for the test component: an update replaces the data.
fn set_updates<'a>(
    mut updater: AppDataDictionaryUpdater<'_>,
    proposals: impl Iterator<Item = &'a AppDataUpdateProposal>,
) -> Option<AppDataUpdates> {
    for proposal in proposals {
        let AppDataUpdateOperation::Update(data) = proposal.operation() else {
            panic!("expected an update operation");
        };
        updater.set(ComponentData::from_parts(
            proposal.component_id(),
            data.clone(),
        ));
    }
    updater.changes()
}

fn into_public_message(message: MlsMessageOut) -> PublicMessageIn {
    let message: MlsMessageIn = message.into();
    match message.try_into_protocol_message().unwrap() {
        ProtocolMessage::PublicMessage(public_message) => *public_message,
        ProtocolMessage::PrivateMessage(_) => panic!("Unexpected message type."),
    }
}

// An AppDataUpdate proposal from a configured external sender is accepted by
// a member and by a PublicGroup, and the Commit covering it updates the
// app_data_dictionary for all of them (draft-ietf-mls-extensions-10 §4.7).
#[openmls_test]
fn external_app_data_update_proposal_should_succeed() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let public_provider = &Provider::default();
    let ds_provider = &Provider::default();

    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        ds_provider,
    );
    let (mut alice_group, alice_credential, mut bob_group, mut public_group) =
        validation_test_setup(
            ciphersuite,
            alice_provider,
            bob_provider,
            public_provider,
            &ds_credential_with_key,
        );
    assert!(alice_group.extensions().app_data_dictionary().is_none());

    let proposal = into_public_message(
        ExternalProposal::new_app_data_update(
            COMPONENT_ID,
            AppDataUpdateOperation::Update(b"ds data".to_vec().into()),
            alice_group.group_id().clone(),
            alice_group.epoch(),
            &ds_credential_with_key.signer,
            SenderExtensionIndex::new(0),
        )
        .unwrap(),
    );

    // Alice, Bob and the PublicGroup accept and store the proposal
    for (group, provider) in [
        (&mut alice_group, alice_provider),
        (&mut bob_group, bob_provider),
    ] {
        let processed_message = group.process_message(provider, proposal.clone()).unwrap();
        let ProcessedMessageContent::ProposalMessage(queued_proposal) =
            processed_message.into_content()
        else {
            panic!("Not a proposal");
        };
        assert_eq!(
            queued_proposal.sender(),
            &Sender::External(SenderExtensionIndex::new(0))
        );
        assert!(matches!(
            queued_proposal.proposal(),
            Proposal::AppDataUpdate(_)
        ));
        group
            .store_pending_proposal(provider.storage(), *queued_proposal)
            .unwrap();
    }
    let processed_message = public_group
        .process_message(public_provider.crypto(), proposal)
        .unwrap();
    let ProcessedMessageContent::ProposalMessage(queued_proposal) =
        processed_message.into_content()
    else {
        panic!("Not a proposal");
    };
    assert!(matches!(
        queued_proposal.proposal(),
        Proposal::AppDataUpdate(_)
    ));
    public_group
        .add_proposal(public_provider.storage(), *queued_proposal)
        .unwrap();

    // Alice commits the proposal by reference
    let mut stage = alice_group
        .commit_builder()
        .load_psks(alice_provider.storage())
        .unwrap();
    let updates = set_updates(
        stage.app_data_dictionary_updater(),
        stage.app_data_update_proposals(),
    );
    stage.with_app_data_dictionary_updates(updates);
    let (commit, _, _) = stage
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_credential.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap()
        .into_contents();
    alice_group.merge_pending_commit(alice_provider).unwrap();
    let commit = into_public_message(commit);

    // Bob processes the commit
    let ProcessedMessageContent::UnresolvedAppDataCommit(unresolved_commit) = bob_group
        .process_message(bob_provider, commit.clone())
        .unwrap()
        .into_content()
    else {
        panic!("Not an unresolved AppDataUpdate commit");
    };
    let updates = set_updates(
        bob_group.app_data_dictionary_updater(),
        unresolved_commit.app_data_update_proposals(),
    );
    let staged_commit = bob_group
        .stage_app_data_commit(bob_provider, *unresolved_commit, updates)
        .unwrap();
    bob_group
        .merge_staged_commit(bob_provider, staged_commit)
        .unwrap();

    // The PublicGroup processes the commit
    let ProcessedMessageContent::UnresolvedAppDataCommit(unresolved_commit) = public_group
        .process_message(public_provider.crypto(), commit)
        .unwrap()
        .into_content()
    else {
        panic!("Not an unresolved AppDataUpdate commit");
    };
    let updates = set_updates(
        public_group.app_data_dictionary_updater(),
        unresolved_commit.app_data_update_proposals(),
    );
    let staged_commit = public_group
        .stage_app_data_commit(public_provider.crypto(), *unresolved_commit, updates)
        .unwrap();
    public_group
        .merge_commit(public_provider.storage(), staged_commit)
        .unwrap();

    for extensions in [
        alice_group.extensions(),
        bob_group.extensions(),
        public_group.group_context().extensions(),
    ] {
        assert_eq!(
            extensions
                .app_data_dictionary()
                .and_then(|dict| dict.dictionary().get(&COMPONENT_ID)),
            Some(b"ds data".as_slice())
        );
    }
}

// An AppDataUpdate proposal from a party that is not a configured external
// sender is refused by a member and by a PublicGroup.
#[openmls_test]
fn external_app_data_update_proposal_should_fail_when_not_an_external_sender() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let public_provider = &Provider::default();
    let ds_provider = &Provider::default();

    let ds_credential_with_key = generate_credential_with_key(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        ds_provider,
    );
    let (_alice_group, _alice_credential, mut bob_group, public_group) = validation_test_setup(
        ciphersuite,
        alice_provider,
        bob_provider,
        public_provider,
        &ds_credential_with_key,
    );
    let intruder_credential_with_key = generate_credential_with_key(
        "intruder".into(),
        ciphersuite.signature_algorithm(),
        ds_provider,
    );

    // Signed by a key that is not in the external senders extension, at the
    // index of the delivery service, or at an index past its end
    for (sender_index, expected_error) in [
        (0, ValidationError::InvalidSignature),
        (1, ValidationError::UnauthorizedExternalSender),
    ] {
        let proposal = into_public_message(
            ExternalProposal::new_app_data_update(
                COMPONENT_ID,
                AppDataUpdateOperation::Update(b"intruder data".to_vec().into()),
                bob_group.group_id().clone(),
                bob_group.epoch(),
                &intruder_credential_with_key.signer,
                SenderExtensionIndex::new(sender_index),
            )
            .unwrap(),
        );

        let error = bob_group
            .process_message(bob_provider, proposal.clone())
            .unwrap_err();
        assert_eq!(
            error,
            ProcessMessageError::ValidationError(expected_error.clone())
        );

        let error = public_group
            .process_message(public_provider.crypto(), proposal)
            .unwrap_err();
        assert_eq!(
            error,
            PublicProcessMessageError::ValidationError(expected_error)
        );
    }
}
