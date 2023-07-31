use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};

use super::CoreGroup;
use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::hash_ref::ProposalRef,
    credentials::CredentialType,
    extensions::{Extension, ExtensionType, Extensions, RequiredCapabilitiesExtension},
    framing::{
        mls_auth_content::AuthenticatedContent, sender::Sender, FramingParameters, WireFormat,
    },
    group::{
        config::CryptoConfig,
        errors::*,
        proposals::{ProposalQueue, ProposalStore, QueuedProposal},
        public_group::errors::PublicGroupBuildError,
        test_core_group::setup_client,
        CreateCommitParams, GroupContext, GroupId,
    },
    key_packages::{KeyPackageBundle, KeyPackageIn},
    messages::proposals::{AddProposal, Proposal, ProposalOrRef, ProposalType},
    schedule::psk::store::ResumptionPskStore,
    test_utils::*,
    treesync::errors::LeafNodeValidationError,
    versions::ProtocolVersion,
};

/// This test makes sure ProposalQueue works as intended. This functionality is
/// used in `create_commit` to filter the epoch proposals. Expected result:
/// `filtered_queued_proposals` returns only proposals of a certain type
#[apply(ciphersuites_and_providers)]
fn proposal_queue_functions(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);
    // Define identities
    let (alice_credential, alice_key_package_bundle, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);

    let bob_key_package = bob_key_package_bundle.key_package();
    let alice_update_key_package_bundle =
        KeyPackageBundle::new(provider, &alice_signer, ciphersuite, alice_credential);
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
#[apply(ciphersuites_and_providers)]
fn proposal_queue_order(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::PublicMessage);
    // Define identities
    let (alice_credential, alice_key_package_bundle, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, provider);

    let bob_key_package = bob_key_package_bundle.key_package();
    let alice_update_key_package_bundle =
        KeyPackageBundle::new(provider, &alice_signer, ciphersuite, alice_credential);
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

#[apply(ciphersuites_and_providers)]
fn test_required_unsupported_proposals(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let (alice_credential, _, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);

    // Set required capabilities
    let extensions = &[];
    let proposals = &[ProposalType::GroupContextExtensions, ProposalType::AppAck];
    let credentials = &[CredentialType::Basic];
    let required_capabilities =
        RequiredCapabilitiesExtension::new(extensions, proposals, credentials);

    // This must fail because we don't actually support AppAck proposals
    let e = CoreGroup::builder(
        GroupId::random(provider.rand()),
        CryptoConfig::with_default_version(ciphersuite),
        alice_credential,
    )
    .with_required_capabilities(required_capabilities)
    .build(provider, &alice_signer)
    .expect_err(
        "CoreGroup creation must fail because AppAck proposals aren't supported in OpenMLS yet.",
    );
    assert_eq!(
        e,
        CoreGroupBuildError::PublicGroupBuildError(PublicGroupBuildError::UnsupportedProposalType)
    )
}

#[apply(ciphersuites_and_providers)]
fn test_required_extension_key_package_mismatch(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    let (alice_credential, _, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _, _) =
        setup_client("Bob", ciphersuite, provider);
    let bob_key_package = bob_key_package_bundle.key_package();

    // Set required capabilities
    let extensions = &[
        ExtensionType::RequiredCapabilities,
        ExtensionType::ApplicationId,
    ];
    let proposals = &[
        ProposalType::GroupContextExtensions,
        ProposalType::Add,
        ProposalType::Remove,
        ProposalType::Update,
    ];
    let credentials = &[CredentialType::Basic];
    let required_capabilities =
        RequiredCapabilitiesExtension::new(extensions, proposals, credentials);

    let alice_group = CoreGroup::builder(
        GroupId::random(provider.rand()),
        CryptoConfig::with_default_version(ciphersuite),
        alice_credential,
    )
    .with_required_capabilities(required_capabilities)
    .build(provider, &alice_signer)
    .expect("Error creating CoreGroup.");

    let e = alice_group
        .create_add_proposal(
            framing_parameters,
            bob_key_package.clone(),
            &alice_signer,
        )
        .expect_err("Proposal was created even though the key package didn't support the required extensions.");
    assert_eq!(
        e,
        CreateAddProposalError::LeafNodeValidation(LeafNodeValidationError::UnsupportedExtensions)
    );
}

#[apply(ciphersuites_and_providers)]
fn test_group_context_extensions(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

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

    let mut alice_group = CoreGroup::builder(
        GroupId::random(provider.rand()),
        CryptoConfig::with_default_version(ciphersuite),
        alice_credential,
    )
    .with_required_capabilities(required_capabilities)
    .build(provider, &alice_signer)
    .expect("Error creating CoreGroup.");

    let bob_add_proposal = alice_group
        .create_add_proposal(framing_parameters, bob_key_package.clone(), &alice_signer)
        .expect("Could not create proposal");

    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );
    log::info!(" >>> Creating commit ...");
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, provider, &alice_signer)
        .expect("Error creating commit");

    log::info!(" >>> Staging & merging commit ...");

    alice_group
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging own staged commit");
    let ratchet_tree = alice_group.public_group().export_ratchet_tree();

    // Make sure that Bob can join the group with the required extension in place
    // and Bob's key package supporting them.
    let _bob_group = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        bob_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
    )
    .expect("Error joining group.");
}

#[apply(ciphersuites_and_providers)]
fn test_group_context_extension_proposal_fails(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    let (alice_credential, _, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _, _) =
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

    let mut alice_group = CoreGroup::builder(
        GroupId::random(provider.rand()),
        CryptoConfig::with_default_version(ciphersuite),
        alice_credential,
    )
    .with_required_capabilities(required_capabilities)
    .build(provider, &alice_signer)
    .expect("Error creating CoreGroup.");

    // TODO: openmls/openmls#1130 add a test for unsupported required capabilities.
    //       We can't test this right now because we don't have a capability
    //       that is not a "default" proposal or extension.
    // // Alice tries to add a required capability she doesn't support herself.
    // let required_application_id = Extension::RequiredCapabilities(
    //     RequiredCapabilitiesExtension::new(&[ExtensionType::ApplicationId], &[]),
    // );
    // let e = alice_group.create_group_context_ext_proposal(
    //     framing_parameters,
    //     &alice_credential_bundle,
    //     &[required_application_id.clone()],
    //     provider,
    // ).expect_err("Alice was able to create a gce proposal with a required extensions she doesn't support.");
    // assert_eq!(
    //     e,
    //     CreateGroupContextExtProposalError::TreeSyncError(
    //         crate::treesync::errors::TreeSyncError::UnsupportedExtension
    //     )
    // );
    //
    // // Well, this failed luckily.

    // Adding Bob
    let bob_add_proposal = alice_group
        .create_add_proposal(framing_parameters, bob_key_package.clone(), &alice_signer)
        .expect("Could not create proposal");

    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );
    log::info!(" >>> Creating commit ...");
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, provider, &alice_signer)
        .expect("Error creating commit");

    log::info!(" >>> Staging & merging commit ...");

    alice_group
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging pending commit");
    let ratchet_tree = alice_group.public_group().export_ratchet_tree();

    let _bob_group = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        bob_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
    )
    .expect("Error joining group.");

    // TODO: openmls/openmls#1130 re-enable
    // // Now Bob wants the ApplicationId extension to be required.
    // // This should fail because Alice doesn't support it.
    // let e = bob_group
    //     .create_group_context_ext_proposal(
    //         framing_parameters,
    //         &alice_credential_bundle,
    //         &[required_application_id],
    //         provider,
    //     )
    //     .expect_err("Bob was able to create a gce proposal for an extension not supported by all other parties.");
    // assert_eq!(
    //     e,
    //     CreateGroupContextExtProposalError::TreeSyncError(
    //         crate::treesync::errors::TreeSyncError::UnsupportedExtension
    //     )
    // );
}

#[apply(ciphersuites_and_providers)]
fn test_group_context_extension_proposal(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    let (alice_credential, _, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_bob_credential_with_key, bob_key_package_bundle, _, _) =
        setup_client("Bob", ciphersuite, provider);

    let bob_key_package = bob_key_package_bundle.key_package();

    let mut alice_group = CoreGroup::builder(
        GroupId::random(provider.rand()),
        CryptoConfig::with_default_version(ciphersuite),
        alice_credential,
    )
    .build(provider, &alice_signer)
    .expect("Error creating CoreGroup.");

    // Adding Bob
    let bob_add_proposal = alice_group
        .create_add_proposal(framing_parameters, bob_key_package.clone(), &alice_signer)
        .expect("Could not create proposal");

    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );
    log::info!(" >>> Creating commit ...");
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_results = alice_group
        .create_commit(params, provider, &alice_signer)
        .expect("Error creating commit");

    log::info!(" >>> Staging & merging commit ...");

    alice_group
        .merge_commit(provider, create_commit_results.staged_commit)
        .expect("error merging pending commit");

    let ratchet_tree = alice_group.public_group().export_ratchet_tree();

    let mut bob_group = CoreGroup::new_from_welcome(
        create_commit_results
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        bob_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
    )
    .expect("Error joining group.");

    // Alice adds a required capability.
    let required_application_id =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::ApplicationId],
            &[],
            &[CredentialType::Basic],
        ));
    let gce_proposal = alice_group
        .create_group_context_ext_proposal(
            framing_parameters,
            Extensions::single(required_application_id),
            &alice_signer,
        )
        .expect("Error creating gce proposal.");

    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            gce_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );
    log::info!(" >>> Creating commit ...");
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, provider, &alice_signer)
        .expect("Error creating commit");

    log::info!(" >>> Staging & merging commit ...");

    let staged_commit = bob_group
        .read_keys_and_stage_commit(&create_commit_result.commit, &proposal_store, &[], provider)
        .expect("error staging commit");
    bob_group
        .merge_commit(provider, staged_commit)
        .expect("error merging commit");

    alice_group
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging pending commit");

    assert_eq!(
        alice_group
            .export_secret(provider.crypto(), "label", b"gce test", 32)
            .expect("Error exporting secret."),
        bob_group
            .export_secret(provider.crypto(), "label", b"gce test", 32)
            .expect("Error exporting secret.")
    )
}
