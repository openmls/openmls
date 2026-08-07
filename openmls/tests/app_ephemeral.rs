#![cfg(feature = "extensions-draft")]

use openmls::{
    component::ComponentId, messages::group_info::VerifiableGroupInfo, prelude::*,
    test_utils::single_group_test_framework::*,
};
use openmls_basic_credential::SignatureKeyPair;

// TODO: reduce boilerplate in tests using the single_group_test_framework, once it allows
// including Capabilities for joining members.
/// Test basic AppEphemeral proposal handling.
/// NOTE: The main single_group_test_framework functionality can't be used in this test,
/// since the capabilities need to be set to include ProposalType::AppEphemeral
#[openmls_test::openmls_test]
fn app_ephemeral_proposals() {
    const COMPONENT_ID: ComponentId = 1;
    const DATA: &[u8] = b"data";

    let group_id = GroupId::from_slice(b"Test Group");

    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Include the AppEphemeral proposal type in the LeafNode capabilities
    let capabilities =
        Capabilities::new(None, None, None, Some(&[ProposalType::AppEphemeral]), None);

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        // add to leaf node capabilities
        .capabilities(capabilities.clone())
        .build();

    // Generate credentials with keys
    let (alice_credential, alice_signer) = generate_credential(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let (bob_credential, bob_signer) = generate_credential(
        b"Bob".to_vec(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    // Generate KeyPackage for Bob with the correct LeafNode capabilities
    let bob_key_package = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(ciphersuite, bob_provider, &bob_signer, bob_credential)
        .unwrap();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob ===
    let welcome = match alice_group.add_members(
        alice_provider,
        &alice_signer,
        &[bob_key_package.key_package().clone()],
    ) {
        Ok((_, welcome, _)) => welcome,
        Err(e) => panic!("Could not add member to group: {e:?}"),
    };
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating StagedWelcome from Welcome")
    .into_group(bob_provider)
    .expect("Error creating group from StagedWelcome");

    // === Alice creates a commit with an AppEphemeral proposal ===
    let message_bundle = alice_group
        .commit_builder()
        .add_proposals(vec![Proposal::AppEphemeral(Box::new(
            AppEphemeralProposal::new(COMPONENT_ID, DATA.into()),
        ))])
        .load_psks(alice_provider.storage())
        .expect("error loading psks")
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signer,
            |_| true,
        )
        .expect("error validating data and building commit")
        .stage_commit(alice_provider)
        .expect("error staging commit");

    let alice_pending_commit = alice_group.pending_commit().expect("no pending commit");

    // ensure that the number of AppEphemeral proposals for the component id COMPONENT_ID is correct
    assert_eq!(
        alice_pending_commit
            .staged_proposal_queue
            .app_ephemeral_proposals_for_component_id(COMPONENT_ID)
            .count(),
        1
    );

    // handle proposals on Bob's side
    let (mls_message_out, _, _) = message_bundle.into_contents();

    let protocol_message = MlsMessageIn::from(mls_message_out)
        .try_into_protocol_message()
        .unwrap();

    let processed_message = bob_group
        .process_message(bob_provider, protocol_message)
        .expect("could not process message");

    let bob_staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => commit,
        _ => panic!("incorrect message type"),
    };

    // ensure that the number of AppEphemeral proposals for the component id COMPONENT_ID is correct
    assert_eq!(
        bob_staged_commit
            .staged_proposal_queue
            .app_ephemeral_proposals_for_component_id(COMPONENT_ID)
            .count(),
        1
    );

    // Inspect the component ids for all AppEphemeral proposals in the commit
    let component_ids = bob_staged_commit
        .staged_proposal_queue
        .unique_component_ids_for_app_ephemeral();
    assert_eq!(component_ids, vec![COMPONENT_ID]);

    // handle proposals on Bob's side
    for queued_proposal in bob_staged_commit
        .staged_proposal_queue
        .app_ephemeral_proposals_for_component_id(COMPONENT_ID)
    {
        let proposal = queued_proposal.app_ephemeral_proposal();

        assert_eq!(proposal.data(), DATA);

        // handle data here...
    }
}

/// Capabilities declaring support for the AppEphemeral proposal type. Every
/// member's leaf needs this before anyone may commit such a proposal.
fn app_ephemeral_capabilities() -> Capabilities {
    Capabilities::new(None, None, None, Some(&[ProposalType::AppEphemeral]), None)
}

/// Set up a group of Alice and Bob where both leaves support the AppEphemeral
/// proposal type. Returns Alice's group, her signer and the join config a third
/// party uses to join by external commit.
fn setup_group_for_external_commit<P: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    alice_provider: &P,
    bob_provider: &P,
) -> (MlsGroup, SignatureKeyPair, MlsGroupJoinConfig) {
    let capabilities = app_ephemeral_capabilities();

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities.clone())
        .build();

    let (alice_credential, alice_signer) = generate_credential(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let (bob_credential, bob_signer) = generate_credential(
        b"Bob".to_vec(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let bob_key_package = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(ciphersuite, bob_provider, &bob_signer, bob_credential)
        .expect("error building Bob's key package");

    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        GroupId::from_slice(b"Test Group"),
        alice_credential,
    )
    .expect("An unexpected error occurred.");

    alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        )
        .expect("could not add member to group");
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging commit");

    (
        alice_group,
        alice_signer,
        mls_group_create_config.join_config().clone(),
    )
}

/// Export Alice's group info in the form an external joiner needs.
fn export_verifiable_group_info<P: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &P,
    signer: &SignatureKeyPair,
) -> VerifiableGroupInfo {
    group
        .export_group_info(provider.crypto(), signer, true)
        .expect("error exporting group info")
        .into_verifiable_group_info()
        .expect("expected the message to be a group info")
}

/// A joiner may attach an AppEphemeral proposal by value to its external
/// commit. Another client can read the payload from the commit before it is a
/// member of the group, and members find the proposal in the staged commit.
#[openmls_test::openmls_test]
fn app_ephemeral_proposal_in_external_commit() {
    const COMPONENT_ID: ComponentId = 1;
    const OTHER_COMPONENT_ID: ComponentId = 2;
    const DATA: &[u8] = b"external commit data";

    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    let (mut alice_group, alice_signer, join_config) =
        setup_group_for_external_commit(ciphersuite, alice_provider, bob_provider);

    let (charlie_credential, charlie_signer) = generate_credential(
        b"Charlie".to_vec(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );

    let verifiable_group_info =
        export_verifiable_group_info(&alice_group, alice_provider, &alice_signer);

    let (charlie_group, bundle) = MlsGroup::external_commit_builder()
        .with_config(join_config)
        .build_group(charlie_provider, verifiable_group_info, charlie_credential)
        .expect("error building group from group info")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(app_ephemeral_capabilities())
                .build(),
        )
        .add_proposal(Proposal::AppEphemeral(Box::new(AppEphemeralProposal::new(
            COMPONENT_ID,
            DATA.into(),
        ))))
        .load_psks(charlie_provider.storage())
        .expect("error loading psks")
        .build(
            charlie_provider.rand(),
            charlie_provider.crypto(),
            &charlie_signer,
            |_| true,
        )
        .expect("error validating data and building commit")
        .finalize(charlie_provider)
        .expect("error finalizing external commit");

    let commit = bundle.into_commit();

    // Read the payload off the wire without any group state.
    let protocol_message = MlsMessageIn::from(commit.clone())
        .try_into_protocol_message()
        .expect("expected the commit to be a protocol message");
    let ProtocolMessage::PublicMessage(public_message) = protocol_message else {
        panic!("an external commit is always a public message");
    };

    let peeked = public_message.unverified_app_ephemeral_proposals(COMPONENT_ID);
    assert_eq!(peeked.len(), 1);
    assert_eq!(peeked[0].data(), DATA);
    assert!(public_message
        .unverified_app_ephemeral_proposals(OTHER_COMPONENT_ID)
        .is_empty());

    let processed_message = alice_group
        .process_message(
            alice_provider,
            MlsMessageIn::from(commit)
                .try_into_protocol_message()
                .expect("expected the commit to be a protocol message"),
        )
        .expect("could not process message");

    let staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => *commit,
        _ => panic!("incorrect message type"),
    };

    {
        let mut proposals = staged_commit
            .staged_proposal_queue
            .app_ephemeral_proposals_for_component_id(COMPONENT_ID);
        let queued_proposal = proposals.next().expect("no AppEphemeral proposal");
        assert_eq!(queued_proposal.app_ephemeral_proposal().data(), DATA);
        assert!(proposals.next().is_none());
    }

    alice_group
        .merge_staged_commit(alice_provider, staged_commit)
        .expect("error merging staged commit");

    assert_eq!(
        alice_group.epoch_authenticator(),
        charlie_group.epoch_authenticator()
    );
}

/// Proposal types that RFC 9420 does not allow by value in an external commit
/// are still rejected when the commit is built.
#[openmls_test::openmls_test]
fn forbidden_proposal_in_external_commit_is_rejected() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let dave_provider = &Provider::default();

    let (alice_group, alice_signer, join_config) =
        setup_group_for_external_commit(ciphersuite, alice_provider, bob_provider);

    let (charlie_credential, charlie_signer) = generate_credential(
        b"Charlie".to_vec(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );
    let (dave_credential, dave_signer) = generate_credential(
        b"Dave".to_vec(),
        ciphersuite.signature_algorithm(),
        dave_provider,
    );

    let dave_key_package = KeyPackage::builder()
        .leaf_node_capabilities(app_ephemeral_capabilities())
        .build(ciphersuite, dave_provider, &dave_signer, dave_credential)
        .expect("error building Dave's key package");

    let verifiable_group_info =
        export_verifiable_group_info(&alice_group, alice_provider, &alice_signer);

    let error = MlsGroup::external_commit_builder()
        .with_config(join_config)
        .build_group(charlie_provider, verifiable_group_info, charlie_credential)
        .expect("error building group from group info")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(app_ephemeral_capabilities())
                .build(),
        )
        .add_proposal(Proposal::Add(Box::new(AddProposal::from(
            dave_key_package.key_package().clone(),
        ))))
        .load_psks(charlie_provider.storage())
        .expect("error loading psks")
        .build(
            charlie_provider.rand(),
            charlie_provider.crypto(),
            &charlie_signer,
            |_| true,
        )
        .expect_err("an Add proposal by value must not be allowed in an external commit");

    assert!(matches!(
        error,
        CreateCommitError::InvalidExternalCommit(
            ExternalCommitValidationError::InvalidInlineProposals
        )
    ));
}
