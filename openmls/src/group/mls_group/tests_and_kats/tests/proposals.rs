use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::hash_ref::ProposalRef,
    credentials::{test_utils, CredentialType},
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
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    key_packages::{KeyPackage, KeyPackageBundle, KeyPackageIn},
    messages::proposals::{AddProposal, Proposal, ProposalOrRef, ProposalType},
    prelude::LeafNodeParameters,
    treesync::node::leaf_node::Capabilities,
    versions::ProtocolVersion,
};

#[cfg(feature = "extensions-draft-08")]
use crate::{
    component::ComponentId,
    group::MlsGroupCreateConfig,
    messages::proposals::AppEphemeralProposal,
    prelude::{MlsMessageIn, StagedCommit},
    test_utils::single_group_test_framework::*,
};

/// This test makes sure ProposalQueue works as intended. This functionality is
/// used in `create_commit` to filter the epoch proposals. Expected result:
/// `filtered_queued_proposals` returns only proposals of a certain type
#[openmls_test::openmls_test]
fn proposal_queue_functions() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let crypto = alice_provider.crypto();
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);
    // Define identities
    let (alice_credential, alice_key_package_bundle, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, alice_provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, bob_provider);

    let bob_key_package = bob_key_package_bundle.key_package();
    let alice_update_key_package_bundle =
        KeyPackageBundle::generate(alice_provider, &alice_signer, ciphersuite, alice_credential);
    let alice_update_key_package = alice_update_key_package_bundle.key_package();
    let kpi = KeyPackageIn::from(alice_update_key_package.clone());
    assert!(kpi.validate(crypto, ProtocolVersion::Mls10).is_ok());

    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::random(alice_provider.rand()),
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

    let proposal_add_alice1 = Proposal::add(add_proposal_alice1);
    let proposal_add_alice2 = Proposal::add(add_proposal_alice2);
    let proposal_add_bob = Proposal::add(add_proposal_bob);

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
        crypto,
        ciphersuite,
        &mls_plaintext_add_alice1,
    )
    .unwrap();
    let proposal_reference_add_alice2 = ProposalRef::from_authenticated_content_by_ref(
        crypto,
        ciphersuite,
        &mls_plaintext_add_alice2,
    )
    .unwrap();
    let proposal_reference_add_bob =
        ProposalRef::from_authenticated_content_by_ref(crypto, ciphersuite, &mls_plaintext_add_bob)
            .unwrap();

    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            crypto,
            mls_plaintext_add_alice1,
        )
        .expect("Could not create QueuedProposal."),
    );
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            crypto,
            mls_plaintext_add_alice2,
        )
        .expect("Could not create QueuedProposal."),
    );

    let (proposal_queue, own_update) = ProposalQueue::filter_proposals(
        proposal_store.proposals().map(Clone::clone),
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
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);
    // Define identities
    let (alice_credential, alice_key_package_bundle, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, alice_provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, bob_provider);

    let bob_key_package = bob_key_package_bundle.key_package();
    let alice_update_key_package_bundle =
        KeyPackageBundle::generate(alice_provider, &alice_signer, ciphersuite, alice_credential);
    let alice_update_key_package = alice_update_key_package_bundle.key_package();
    let kpi = KeyPackageIn::from(alice_update_key_package.clone());
    assert!(kpi
        .validate(alice_provider.crypto(), ProtocolVersion::Mls10)
        .is_ok());

    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::random(alice_provider.rand()),
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

    let proposal_add_alice1 = Proposal::add(add_proposal_alice1);
    let proposal_add_bob1 = Proposal::add(add_proposal_bob1);

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
        alice_provider.crypto(),
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
            alice_provider.crypto(),
            mls_plaintext_add_alice1,
        )
        .unwrap(),
    );
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            bob_provider.crypto(),
            mls_plaintext_add_bob1,
        )
        .unwrap(),
    );

    let proposal_or_refs = vec![
        ProposalOrRef::proposal(proposal_add_bob1.clone()),
        ProposalOrRef::reference(proposal_reference_add_alice1),
    ];

    let sender = Sender::build_member(LeafNodeIndex::new(0));

    // And the same should go for proposal queues built from committed
    // proposals. The order here should be dictated by the proposals passed
    // as ProposalOrRefs.
    let proposal_queue = ProposalQueue::from_committed_proposals(
        ciphersuite,
        alice_provider.crypto(),
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
fn required_extension_key_package_mismatch() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Basic group setup.
    let (alice_credential, _, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, alice_provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _, _) =
        setup_client("Bob", ciphersuite, bob_provider);
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
        .build(alice_provider, &alice_signer, alice_credential)
        .expect("Error creating MlsGroup.");

    let e = alice_group.propose_add_member(alice_provider, &alice_signer, bob_key_package)
        .expect_err("Proposal was created even though the key package didn't support the required extensions.");

    assert_eq!(
        e,
        ProposeAddMemberError::LeafNodeValidation(
            crate::treesync::errors::LeafNodeValidationError::UnsupportedExtensions
        )
    );
}

#[openmls_test::openmls_test]
fn group_context_extensions() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Basic group setup.
    let (alice_credential, _, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, alice_provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _, _) =
        setup_client("Bob", ciphersuite, bob_provider);

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
        .build(alice_provider, &alice_signer, alice_credential)
        .expect("Error creating MlsGroup.");

    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_key_package),
        )
        .expect("Error adding members.");

    alice_group.merge_pending_commit(alice_provider).unwrap();

    let ratchet_tree = alice_group.export_ratchet_tree();

    // Make sure that Bob can join the group with the required extension in place
    // and Bob's key package supporting them.
    let _bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Error joining group.");
}

#[openmls_test::openmls_test]
fn group_context_extension_proposal_fails() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    // Basic group setup.
    let (alice_credential, _, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, alice_provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _bob_signer, _) =
        setup_client("Bob", ciphersuite, bob_provider);

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
        .build(alice_provider, &alice_signer, alice_credential)
        .expect("Error creating MlsGroup.");

    // Adding Bob
    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_key_package),
        )
        .expect("Error adding members.");

    alice_group.merge_pending_commit(alice_provider).unwrap();

    let ratchet_tree = alice_group.export_ratchet_tree();

    let _bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .and_then(|staged_join| staged_join.into_group(bob_provider))
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
fn group_context_extension_proposal() {
    // Basic group setup.
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (mut alice_group, alice_signer, mut bob_group, bob_signer, _alice_credential, _bob_credential) =
        // TODO: don't let alice and bob share the provider
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    // Alice adds a required capability.
    let required_application_id =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::ApplicationId],
            &[],
            &[CredentialType::Basic],
        ));
    let (gce_proposal, _) = alice_group
        .propose_group_context_extensions(
            alice_provider,
            Extensions::single(required_application_id),
            &alice_signer,
        )
        .expect("Error proposing gce.");

    let processed_message = bob_group
        .process_message(bob_provider, gce_proposal.into_protocol_message().unwrap())
        .expect("Error processing gce proposal.");

    match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(queued_proposal) => {
            bob_group
                .store_pending_proposal(bob_provider.storage(), *queued_proposal)
                .unwrap();
        }
        _ => panic!("Expected a StagedCommitMessage."),
    };

    // Bob commits the proposal.
    let (commit, _, _) = bob_group
        .commit_to_pending_proposals(bob_provider, &bob_signer)
        .unwrap();

    bob_group.merge_pending_commit(bob_provider).unwrap();

    let processed_message = alice_group
        .process_message(alice_provider, commit.into_protocol_message().unwrap())
        .expect("Error processing commit.");

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            alice_group
                .merge_staged_commit(alice_provider, *commit)
                .unwrap();
        }
        _ => panic!("Expected a StagedCommitMessage."),
    };

    assert_eq!(
        alice_group.epoch_authenticator(),
        bob_group.epoch_authenticator()
    )
}

// A simple test to check that a SelfRemove proposal can be created and
// processed.
#[openmls_test::openmls_test]
fn self_remove_proposals() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Create credentials and keys
    let (alice_credential, alice_signer) =
        test_utils::new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signer) =
        test_utils::new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    // Add SelfRemove to capabilities
    let capabilities = Capabilities::new(
        None,
        Some(&[ciphersuite]),
        None,
        Some(&[ProposalType::SelfRemove]),
        None,
    );

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackage::builder()
        .leaf_node_capabilities(capabilities.clone())
        .build(
            ciphersuite,
            bob_provider,
            &bob_signer,
            bob_credential.clone(),
        )
        .unwrap();
    let bob_key_package = bob_key_package_bundle.key_package();

    // Alice creates a group
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        // support the non-default SelfRemove proposal type
        .with_capabilities(capabilities)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(alice_provider, &alice_signer, alice_credential.clone())
        .expect("Error creating group.");

    // Alice adds Bob
    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_key_package),
        )
        .expect("Could not create proposal.");

    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");

    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        &MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build(),
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .and_then(|staged_join| staged_join.into_group(bob_provider))
    .expect("error creating group from welcome");

    // Now Bob wants to remove himself via a SelfRemove proposal
    let self_remove = bob_group
        .leave_group_via_self_remove(bob_provider, &bob_signer)
        .unwrap();

    // Alice process Bob's proposal
    let processed_message = alice_group
        .process_message(alice_provider, self_remove.into_protocol_message().unwrap())
        .expect("Error processing self remove proposal.");

    match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(queued_proposal) => {
            alice_group
                .store_pending_proposal(alice_provider.storage(), *queued_proposal)
                .unwrap();
        }
        _ => panic!("Expected a ProposalMessage."),
    };

    // Alice commits Bob's proposal
    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(alice_provider, &alice_signer)
        .unwrap();

    alice_group.merge_pending_commit(alice_provider).unwrap();

    // Bob processes Alice's commit
    let processed_message = bob_group
        .process_message(bob_provider, commit.into_protocol_message().unwrap())
        .expect("Error processing commit.");

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            bob_group
                .merge_staged_commit(bob_provider, *commit)
                .unwrap();
        }
        _ => panic!("Expected a StagedCommitMessage."),
    };

    // Bob should have been removed from the group
    assert!(!bob_group.is_active());
    assert_eq!(alice_group.members().count(), 1);
}

// Test if update proposals are properly discarded if a remove proposal is
// present for a given leaf.
#[openmls_test::openmls_test]
fn remove_and_update_processing() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Create a group with alice and bob.
    let (alice_credential, _, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, alice_provider);
    let (_bob_credential_with_key, bob_key_package_bundle, bob_signer, _) =
        setup_client("Bob", ciphersuite, bob_provider);

    let bob_key_package = bob_key_package_bundle.key_package();

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(alice_provider, &alice_signer, alice_credential)
        .expect("Error creating MlsGroup.");

    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_key_package),
        )
        .expect("Error adding members.");

    alice_group.merge_pending_commit(alice_provider).unwrap();

    let ratchet_tree = alice_group.export_ratchet_tree();

    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Error joining group.")
    .into_group(bob_provider)
    .unwrap();

    // Alice proposes that Bob be removed.
    let (remove_proposal, _proposal_ref) = alice_group
        .propose_remove_member(alice_provider, &alice_signer, LeafNodeIndex::new(1))
        .expect("Error proposing remove.");

    let processed_message = bob_group
        .process_message(
            bob_provider,
            remove_proposal.into_protocol_message().unwrap(),
        )
        .unwrap();

    match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(queued_proposal) => {
            bob_group
                .store_pending_proposal(bob_provider.storage(), *queued_proposal)
                .unwrap();
        }
        _ => panic!("Expected a ProposalMessage."),
    };

    // At the same time, bob proposes an update.
    let (update_proposal, _proposal_ref) = bob_group
        .propose_self_update(bob_provider, &bob_signer, LeafNodeParameters::default())
        .expect("Error proposing update.");

    let processed_message = alice_group
        .process_message(
            alice_provider,
            update_proposal.into_protocol_message().unwrap(),
        )
        .unwrap();

    match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(queued_proposal) => {
            alice_group
                .store_pending_proposal(alice_provider.storage(), *queued_proposal)
                .unwrap();
        }
        _ => panic!("Expected a ProposalMessage."),
    };

    let pending_proposals: Vec<_> = alice_group.pending_proposals().collect();
    println!("Pending proposals: {:?}", pending_proposals);

    // Alice commits both proposals.
    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(alice_provider, &alice_signer)
        .unwrap();

    let staged_proposals: Vec<_> = alice_group
        .pending_commit()
        .unwrap()
        .queued_proposals()
        .collect();

    println!("Staged proposals {:?}", staged_proposals);

    alice_group.merge_pending_commit(alice_provider).unwrap();

    // Bob processes the commit.
    let processed_message = bob_group
        .process_message(bob_provider, commit.into_protocol_message().unwrap())
        .unwrap();

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            bob_group
                .merge_staged_commit(bob_provider, *commit)
                .unwrap();
        }
        _ => panic!("Expected a StagedCommitMessage."),
    };
    // Bob should be removed now.
    assert_eq!(alice_group.members().count(), 1);
    assert!(!bob_group.is_active());
}

// A simple test to check that SelfRemove proposals are only ever sent as
// PublicMessages.
#[openmls_test::openmls_test]
fn self_remove_proposals_always_public() {
    let alice_provider = &Provider::default();
    let (alice_credential, alice_signer) =
        test_utils::new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    // Alice creates a group
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build(alice_provider, &alice_signer, alice_credential.clone())
        .expect("Error creating group.");

    // Now Bob wants to remove himself via a SelfRemove proposal
    let self_remove = alice_group
        .leave_group_via_self_remove(alice_provider, &alice_signer)
        .expect_err("SelfRemove proposal was created with wrong wire format policy.");

    assert_eq!(
        self_remove,
        LeaveGroupError::CannotSelfRemoveWithPureCiphertext
    );
}

#[cfg(feature = "extensions-draft-08")]
// helper function to retrieve data from AppEphemeral proposals
fn get_app_ephemeral_proposals_data(
    component_id: ComponentId,
    staged_commit: &StagedCommit,
) -> Vec<Vec<u8>> {
    staged_commit
        .staged_proposal_queue
        .app_ephemeral_proposals_for_component_id(component_id)
        .map(|queued_proposal| queued_proposal.app_ephemeral_proposal().data().to_vec())
        .collect::<Vec<_>>()
}

// TODO: reduce boilerplate in tests using the single_group_test_framework, once it allows
// including Capabilities for joining members.
#[cfg(feature = "extensions-draft-08")]
/// Test AppEphemeral proposal handling, with more than one proposal.
/// NOTE: The main single_group_test_framework functionality can't be used in this test,
/// since the capabilities need to be set to include ProposalType::AppEphemeral.
#[openmls_test::openmls_test]
fn app_ephemeral_proposals_multiple() {
    const COMPONENT_ID_1: ComponentId = 4; // higher to check sorting
    const COMPONENT_ID_2: ComponentId = 2;
    const DATA_A: &[u8] = b"A";
    const DATA_B: &[u8] = b"B";
    const DATA_C: &[u8] = b"C";

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
        .add_proposals(vec![
            Proposal::AppEphemeral(Box::new(AppEphemeralProposal::new(
                COMPONENT_ID_1,
                DATA_A.into(),
            ))),
            Proposal::AppEphemeral(Box::new(AppEphemeralProposal::new(
                COMPONENT_ID_2,
                DATA_B.into(),
            ))),
            Proposal::AppEphemeral(Box::new(AppEphemeralProposal::new(
                COMPONENT_ID_1,
                DATA_C.into(),
            ))),
        ])
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

    // ensure that AppEphemeral proposals for the component id COMPONENT_ID are correct, and in the
    // correct order
    assert_eq!(
        get_app_ephemeral_proposals_data(COMPONENT_ID_1, alice_pending_commit),
        vec![DATA_A, DATA_C]
    );
    assert_eq!(
        get_app_ephemeral_proposals_data(COMPONENT_ID_2, alice_pending_commit),
        vec![DATA_B]
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

    // Retrieve the component ids for all AppEphemeral proposals in the commit
    // Ensure that the order is correct
    let component_ids = bob_staged_commit
        .staged_proposal_queue
        .unique_component_ids_for_app_ephemeral();
    assert_eq!(component_ids, vec![COMPONENT_ID_2, COMPONENT_ID_1]);

    assert_eq!(
        get_app_ephemeral_proposals_data(COMPONENT_ID_1, &bob_staged_commit),
        vec![DATA_A, DATA_C]
    );
    assert_eq!(
        get_app_ephemeral_proposals_data(COMPONENT_ID_2, &bob_staged_commit),
        vec![DATA_B]
    );
}
