use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::hash_ref::ProposalRef,
    credentials::CredentialType,
    extensions::{Extension, ExtensionType, Extensions, RequiredCapabilitiesExtension},
    framing::{
        mls_auth_content::AuthenticatedContent, sender::Sender, FramingParameters, WireFormat,
    },
    group::{
        errors::*,
        mls_group::{
            proposal_store::{ProposalQueue, ProposalStore, QueuedProposal},
            tests_and_kats::utils::{setup_alice_bob_group, setup_client},
            ProcessedMessageContent,
        },
        GroupContext, GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome,
    },
    key_packages::{KeyPackageBundle, KeyPackageIn},
    messages::proposals::{AddProposal, Proposal, ProposalOrRef, ProposalType},
    prelude::LeafNodeParameters,
    test_utils::*,
    versions::ProtocolVersion,
};

/// This test makes sure ProposalQueue works as intended. This functionality is
/// used in `create_commit` to filter the epoch proposals. Expected result:
/// `filtered_queued_proposals` returns only proposals of a certain type
#[openmls_test::openmls_test]
fn proposal_queue_functions(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);
    // Define identities
    let (alice_credential, alice_key_package_bundle, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);

    let bob_key_package = bob_key_package_bundle.key_package();
    let alice_update_key_package_bundle =
        KeyPackageBundle::generate(provider, &alice_signer, ciphersuite, alice_credential);
    let alice_update_key_package = alice_update_key_package_bundle.key_package();
    let kpi = KeyPackageIn::from(alice_update_key_package.clone());
    assert!(kpi
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .is_ok());

    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::random(provider.rand()),
        0,
        vec![],
        vec![],
        Extensions::empty(),
    );

    // Let's create some proposals
    let add_proposal_alice1 = AddProposal {
        key_package: alice_key_package_bundle.key_package().clone(),
    };
    let add_proposal_alice2 = AddProposal {
        key_package: alice_key_package_bundle.key_package().clone(),
    };
    let add_proposal_bob = AddProposal {
        key_package: bob_key_package.clone(),
    };

    let proposal_add_alice1 = Proposal::Add(add_proposal_alice1);
    let proposal_add_alice2 = Proposal::Add(add_proposal_alice2);
    let proposal_add_bob = Proposal::Add(add_proposal_bob);

    // Test proposal types
    assert!(proposal_add_alice1.is_type(ProposalType::Add));
    assert!(!proposal_add_alice1.is_type(ProposalType::Update));
    assert!(!proposal_add_alice1.is_type(ProposalType::Remove));

    // Frame proposals in PublicMessage
    let mls_plaintext_add_alice1 = AuthenticatedContent::member_proposal(
        framing_parameters,
        LeafNodeIndex::new(0),
        proposal_add_alice1,
        &group_context,
        &alice_signer,
    )
    .unwrap();
    let mls_plaintext_add_alice2 = AuthenticatedContent::member_proposal(
        framing_parameters,
        LeafNodeIndex::new(1),
        proposal_add_alice2,
        &group_context,
        &alice_signer,
    )
    .unwrap();
    let mls_plaintext_add_bob = AuthenticatedContent::member_proposal(
        framing_parameters,
        LeafNodeIndex::new(1),
        proposal_add_bob,
        &group_context,
        &alice_signer,
    )
    .unwrap();

    let proposal_reference_add_alice1 = ProposalRef::from_authenticated_content_by_ref(
        provider.crypto(),
        ciphersuite,
        &mls_plaintext_add_alice1,
    )
    .unwrap();
    let proposal_reference_add_alice2 = ProposalRef::from_authenticated_content_by_ref(
        provider.crypto(),
        ciphersuite,
        &mls_plaintext_add_alice2,
    )
    .unwrap();
    let proposal_reference_add_bob = ProposalRef::from_authenticated_content_by_ref(
        provider.crypto(),
        ciphersuite,
        &mls_plaintext_add_bob,
    )
    .unwrap();

    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            mls_plaintext_add_alice1,
        )
        .expect("Could not create QueuedProposal."),
    );
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            mls_plaintext_add_alice2,
        )
        .expect("Could not create QueuedProposal."),
    );

    let (proposal_queue, own_update) = ProposalQueue::filter_proposals(
        ciphersuite,
        provider.crypto(),
        Sender::build_member(LeafNodeIndex::new(1)),
        &proposal_store,
        &[],
        LeafNodeIndex::new(0),
    )
    .expect("Could not create ProposalQueue.");

    // Own update should not be required in this case (only add proposals)
    assert!(!own_update);

    // Test if proposals are all covered
    let valid_proposal_reference_list = &[
        proposal_reference_add_alice1.clone(),
        proposal_reference_add_alice2.clone(),
    ];
    assert!(proposal_queue.contains(valid_proposal_reference_list));

    let invalid_proposal_reference_list = &[
        proposal_reference_add_alice1,
        proposal_reference_add_alice2,
        proposal_reference_add_bob,
    ];
    assert!(!proposal_queue.contains(invalid_proposal_reference_list));

    // Get filtered proposals
    for filtered_proposal in proposal_queue.filtered_by_type(ProposalType::Add) {
        assert!(filtered_proposal.proposal().is_type(ProposalType::Add));
    }
}

/// Test, that we QueuedProposalQueue is iterated in the right order.
#[openmls_test::openmls_test]
fn proposal_queue_order() {
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);
    // Define identities
    let (alice_credential, alice_key_package_bundle, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);

    let bob_key_package = bob_key_package_bundle.key_package();
    let alice_update_key_package_bundle =
        KeyPackageBundle::generate(provider, &alice_signer, ciphersuite, alice_credential);
    let alice_update_key_package = alice_update_key_package_bundle.key_package();
    let kpi = KeyPackageIn::from(alice_update_key_package.clone());
    assert!(kpi
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .is_ok());

    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::random(provider.rand()),
        0,
        vec![],
        vec![],
        Extensions::empty(),
    );

    // Let's create some proposals
    let add_proposal_alice1 = AddProposal {
        key_package: alice_key_package_bundle.key_package().clone(),
    };
    let add_proposal_bob1 = AddProposal {
        key_package: bob_key_package.clone(),
    };

    let proposal_add_alice1 = Proposal::Add(add_proposal_alice1);
    let proposal_add_bob1 = Proposal::Add(add_proposal_bob1);

    // Frame proposals in PublicMessage
    let mls_plaintext_add_alice1 = AuthenticatedContent::member_proposal(
        framing_parameters,
        LeafNodeIndex::new(0),
        proposal_add_alice1.clone(),
        &group_context,
        &alice_signer,
    )
    .unwrap();
    let proposal_reference_add_alice1 = ProposalRef::from_authenticated_content_by_ref(
        provider.crypto(),
        ciphersuite,
        &mls_plaintext_add_alice1,
    )
    .unwrap();

    let mls_plaintext_add_bob1 = AuthenticatedContent::member_proposal(
        framing_parameters,
        LeafNodeIndex::new(1),
        proposal_add_bob1.clone(),
        &group_context,
        &alice_signer,
    )
    .unwrap();

    // This should set the order of the proposals.
    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            mls_plaintext_add_alice1,
        )
        .unwrap(),
    );
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            mls_plaintext_add_bob1,
        )
        .unwrap(),
    );

    let proposal_or_refs = vec![
        ProposalOrRef::Proposal(proposal_add_bob1.clone()),
        ProposalOrRef::Reference(proposal_reference_add_alice1),
    ];

    let sender = Sender::build_member(LeafNodeIndex::new(0));

    // And the same should go for proposal queues built from committed
    // proposals. The order here should be dictated by the proposals passed
    // as ProposalOrRefs.
    let proposal_queue = ProposalQueue::from_committed_proposals(
        ciphersuite,
        provider.crypto(),
        proposal_or_refs,
        &proposal_store,
        &sender,
    )
    .unwrap();

    let proposal_collection: Vec<&QueuedProposal> =
        proposal_queue.filtered_by_type(ProposalType::Add).collect();

    assert_eq!(proposal_collection[0].proposal(), &proposal_add_bob1);
    assert_eq!(proposal_collection[1].proposal(), &proposal_add_alice1);
}

#[openmls_test::openmls_test]
fn required_extension_key_package_mismatch(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Basic group setup.
    let (alice_credential, _, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _, _) =
        setup_client("Bob", ciphersuite, provider);
    let bob_key_package = bob_key_package_bundle.key_package();

    // Set required capabilities
    let extensions = &[ExtensionType::Unknown(0xff00)];
    // We don't support unknown proposals (yet)
    let proposals = &[];
    let credentials = &[CredentialType::Basic];
    let required_capabilities =
        RequiredCapabilitiesExtension::new(extensions, proposals, credentials);

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_group_context_extensions(Extensions::single(Extension::RequiredCapabilities(
            required_capabilities,
        )))
        .unwrap()
        .build(provider, &alice_signer, alice_credential)
        .expect("Error creating MlsGroup.");

    let e = alice_group.propose_add_member(provider, &alice_signer, bob_key_package)
        .expect_err("Proposal was created even though the key package didn't support the required extensions.");

    assert_eq!(
        e,
        ProposeAddMemberError::LeafNodeValidation(
            crate::treesync::errors::LeafNodeValidationError::UnsupportedExtensions
        )
    );
}

#[openmls_test::openmls_test]
fn group_context_extensions(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Basic group setup.
    let (alice_credential, _, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _, _) =
        setup_client("Bob", ciphersuite, provider);

    let bob_key_package = bob_key_package_bundle.key_package();

    // Set required capabilities
    let extensions = &[ExtensionType::ApplicationId];
    let proposals = &[
        ProposalType::GroupContextExtensions,
        ProposalType::Add,
        ProposalType::Remove,
        ProposalType::Update,
    ];
    let credentials = &[CredentialType::Basic];
    let required_capabilities =
        RequiredCapabilitiesExtension::new(extensions, proposals, credentials);

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_group_context_extensions(Extensions::single(Extension::RequiredCapabilities(
            required_capabilities,
        )))
        .unwrap()
        .build(provider, &alice_signer, alice_credential)
        .expect("Error creating MlsGroup.");

    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(provider, &alice_signer, &[bob_key_package.clone()])
        .expect("Error adding members.");

    alice_group.merge_pending_commit(provider).unwrap();

    let ratchet_tree = alice_group.export_ratchet_tree();

    // Make sure that Bob can join the group with the required extension in place
    // and Bob's key package supporting them.
    let _bob_group = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Error joining group.");
}

#[openmls_test::openmls_test]
fn group_context_extension_proposal_fails(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Basic group setup.
    let (alice_credential, _, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _bob_signer, _) =
        setup_client("Bob", ciphersuite, provider);

    let bob_key_package = bob_key_package_bundle.key_package();

    // Set required capabilities
    let proposals = &[
        ProposalType::GroupContextExtensions,
        ProposalType::Add,
        ProposalType::Remove,
        ProposalType::Update,
    ];
    let credentials = &[CredentialType::Basic];
    let required_capabilities = RequiredCapabilitiesExtension::new(&[], proposals, credentials);

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_group_context_extensions(Extensions::single(Extension::RequiredCapabilities(
            required_capabilities,
        )))
        .unwrap()
        .build(provider, &alice_signer, alice_credential)
        .expect("Error creating MlsGroup.");

    // Adding Bob
    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(provider, &alice_signer, &[bob_key_package.clone()])
        .expect("Error adding members.");

    alice_group.merge_pending_commit(provider).unwrap();

    let ratchet_tree = alice_group.export_ratchet_tree();

    let _bob_group = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .and_then(|staged_join| staged_join.into_group(provider))
    .expect("Error joining group.");

    // TODO: openmls/openmls#1130 re-enable
    // // Now Bob wants the ApplicationId extension to be required.
    // // This should fail because Alice doesn't support it.
    //let unsupported_extensions = Extensions::single(Extension::Unknown(
    //    0xff00,
    //    UnknownExtension(vec![0, 1, 2, 3]),
    //));
    //let e = bob_group
    //    .propose_group_context_extensions(provider, unsupported_extensions, &bob_signer)
    //    .expect_err("Bob was able to propose an extension not supported by all other parties.");
    //
    //assert_eq!(
    //    e,
    //    ProposalError::CreateGroupContextExtProposalError(
    //        CreateGroupContextExtProposalError::KeyPackageExtensionSupport(
    //            KeyPackageExtensionSupportError::UnsupportedExtension
    //        )
    //    )
    //);
}

#[openmls_test::openmls_test]
fn group_context_extension_proposal(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Basic group setup.
    let (mut alice_group, alice_signer, mut bob_group, bob_signer, _bob_credential) =
        setup_alice_bob_group(ciphersuite, provider);

    // Alice adds a required capability.
    let required_application_id =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::ApplicationId],
            &[],
            &[CredentialType::Basic],
        ));
    let (gce_proposal, _) = alice_group
        .propose_group_context_extensions(
            provider,
            Extensions::single(required_application_id),
            &alice_signer,
        )
        .expect("Error proposing gce.");

    let processed_message = bob_group
        .process_message(provider, gce_proposal.into_protocol_message().unwrap())
        .expect("Error processing gce proposal.");

    match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(queued_proposal) => {
            bob_group
                .store_pending_proposal(provider.storage(), *queued_proposal)
                .unwrap();
        }
        _ => panic!("Expected a StagedCommitMessage."),
    };

    // Bob commits the proposal.
    let (commit, _, _) = bob_group
        .commit_to_pending_proposals(provider, &bob_signer)
        .unwrap();

    bob_group.merge_pending_commit(provider).unwrap();

    let processed_message = alice_group
        .process_message(provider, commit.into_protocol_message().unwrap())
        .expect("Error processing commit.");

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            alice_group.merge_staged_commit(provider, *commit).unwrap();
        }
        _ => panic!("Expected a StagedCommitMessage."),
    };

    assert_eq!(
        alice_group.epoch_authenticator(),
        bob_group.epoch_authenticator()
    )
}

// Test if update proposals are properly discarded if a remove proposal is
// present for a given leaf.
#[openmls_test::openmls_test]
fn remove_and_update_processing(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Create a group with alice and bob.
    let (alice_credential, _, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_key_package_bundle, bob_signer, _) =
        setup_client("Bob", ciphersuite, provider);

    let bob_key_package = bob_key_package_bundle.key_package();

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(provider, &alice_signer, alice_credential)
        .expect("Error creating MlsGroup.");

    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(provider, &alice_signer, &[bob_key_package.clone()])
        .expect("Error adding members.");

    alice_group.merge_pending_commit(provider).unwrap();

    let ratchet_tree = alice_group.export_ratchet_tree();

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Error joining group.")
    .into_group(provider)
    .unwrap();

    // Alice proposes that Bob be removed.
    let (remove_proposal, _proposal_ref) = alice_group
        .propose_remove_member(provider, &alice_signer, LeafNodeIndex::new(1))
        .expect("Error proposing remove.");

    let processed_message = bob_group
        .process_message(provider, remove_proposal.into_protocol_message().unwrap())
        .unwrap();

    match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(queued_proposal) => {
            bob_group
                .store_pending_proposal(provider.storage(), *queued_proposal)
                .unwrap();
        }
        _ => panic!("Expected a ProposalMessage."),
    };

    // At the same time, bob proposes an update.
    let (update_proposal, _proposal_ref) = bob_group
        .propose_self_update(provider, &bob_signer, LeafNodeParameters::default())
        .expect("Error proposing update.");

    let processed_message = alice_group
        .process_message(provider, update_proposal.into_protocol_message().unwrap())
        .unwrap();

    match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(queued_proposal) => {
            alice_group
                .store_pending_proposal(provider.storage(), *queued_proposal)
                .unwrap();
        }
        _ => panic!("Expected a ProposalMessage."),
    };

    let pending_proposals: Vec<_> = alice_group.pending_proposals().collect();
    println!("Pending proposals: {:?}", pending_proposals);

    // Alice commits both proposals.
    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(provider, &alice_signer)
        .unwrap();

    let staged_proposals: Vec<_> = alice_group
        .pending_commit()
        .unwrap()
        .queued_proposals()
        .collect();

    println!("Staged proposals {:?}", staged_proposals);

    alice_group.merge_pending_commit(provider).unwrap();

    // Bob processes the commit.
    let processed_message = bob_group
        .process_message(provider, commit.into_protocol_message().unwrap())
        .unwrap();

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            bob_group.merge_staged_commit(provider, *commit).unwrap();
        }
        _ => panic!("Expected a StagedCommitMessage."),
    };

    // Bob should be removed now.
    assert_eq!(alice_group.members().count(), 1);
    assert!(!bob_group.is_active());
}
