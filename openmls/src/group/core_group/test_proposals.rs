use crate::{group::past_secrets::MessageSecretsStore, test_utils::*};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    ciphersuite::{Ciphersuite, Secret},
    config::{errors::ConfigError, Config},
    credentials::{CredentialBundle, CredentialType},
    extensions::{Extension, ExtensionType, KeyIdExtension, RequiredCapabilitiesExtension},
    framing::sender::{Sender, SenderType},
    framing::{FramingParameters, MlsPlaintext, WireFormat},
    group::{
        create_commit_params::CreateCommitParams,
        errors::CoreGroupError,
        proposals::{CreationProposalQueue, ProposalStore, StagedProposal, StagedProposalQueue},
        GroupContext, GroupEpoch, GroupId,
    },
    key_packages::{KeyPackageBundle, KeyPackageError},
    messages::proposals::{AddProposal, Proposal, ProposalOrRef, ProposalReference, ProposalType},
    schedule::MembershipKey,
};

use super::CoreGroup;

fn setup_client(
    id: &str,
    ciphersuite: &Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (CredentialBundle, KeyPackageBundle) {
    let credential_bundle = CredentialBundle::new(
        id.into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    (credential_bundle, key_package_bundle)
}

/// This test makes sure CreationProposalQueue works as intented. This functionality is
/// used in `create_commit` to filter the epoch proposals. Expected result:
/// `filtered_queued_proposals` returns only proposals of a certain type
#[apply(ciphersuites_and_backends)]
fn proposal_queue_functions(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::MlsPlaintext);
    // Define identities
    let (alice_credential_bundle, alice_key_package_bundle) =
        setup_client("Alice", ciphersuite, backend);
    let (_bob_credential_bundle, bob_key_package_bundle) =
        setup_client("Bob", ciphersuite, backend);

    let bob_key_package = bob_key_package_bundle.key_package();
    let alice_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let alice_update_key_package = alice_update_key_package_bundle.key_package();
    assert!(alice_update_key_package.verify(backend).is_ok());

    let group_context =
        GroupContext::new(GroupId::random(backend), GroupEpoch(0), vec![], vec![], &[])
            .expect("Could not create new GroupContext");

    // Let's create some proposals
    let add_proposal_alice1 = AddProposal {
        key_package: alice_key_package_bundle.key_package().clone(),
    };
    let add_proposal_alice2 = AddProposal {
        key_package: alice_key_package_bundle.key_package().clone(),
    };
    let add_proposal_bob1 = AddProposal {
        key_package: bob_key_package.clone(),
    };

    let proposal_add_alice1 = Proposal::Add(add_proposal_alice1);
    let proposal_reference_add_alice1 =
        ProposalReference::from_proposal(ciphersuite, backend, &proposal_add_alice1)
            .expect("An unexpected error occurred.");
    let proposal_add_alice2 = Proposal::Add(add_proposal_alice2);
    let proposal_reference_add_alice2 =
        ProposalReference::from_proposal(ciphersuite, backend, &proposal_add_alice2)
            .expect("An unexpected error occurred.");
    let proposal_add_bob1 = Proposal::Add(add_proposal_bob1);
    let proposal_reference_add_bob1 =
        ProposalReference::from_proposal(ciphersuite, backend, &proposal_add_bob1)
            .expect("An unexpected error occurred.");

    // Test proposal types
    assert!(proposal_add_alice1.is_type(ProposalType::Add));
    assert!(!proposal_add_alice1.is_type(ProposalType::Update));
    assert!(!proposal_add_alice1.is_type(ProposalType::Remove));

    // Frame proposals in MlsPlaintext
    let mls_plaintext_add_alice1 = MlsPlaintext::member_proposal(
        framing_parameters,
        0u32,
        proposal_add_alice1,
        &alice_credential_bundle,
        &group_context,
        &MembershipKey::from_secret(
            Secret::random(ciphersuite, backend, None).expect("Not enough randomness."),
        ),
        backend,
    )
    .expect("Could not create proposal.");
    let mls_plaintext_add_alice2 = MlsPlaintext::member_proposal(
        framing_parameters,
        1u32,
        proposal_add_alice2,
        &alice_credential_bundle,
        &group_context,
        &MembershipKey::from_secret(
            Secret::random(ciphersuite, backend, None).expect("Not enough randomness."),
        ),
        backend,
    )
    .expect("Could not create proposal.");
    let _mls_plaintext_add_bob1 = MlsPlaintext::member_proposal(
        framing_parameters,
        1u32,
        proposal_add_bob1,
        &alice_credential_bundle,
        &group_context,
        &MembershipKey::from_secret(
            Secret::random(ciphersuite, backend, None).expect("Not enough randomness."),
        ),
        backend,
    )
    .expect("Could not create proposal.");

    let mut proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, mls_plaintext_add_alice1)
            .expect("Could not create StagedProposal."),
    );
    proposal_store.add(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, mls_plaintext_add_alice2)
            .expect("Could not create StagedProposal."),
    );

    let (proposal_queue, own_update) = CreationProposalQueue::filter_proposals(
        ciphersuite,
        backend,
        SenderType::Member,
        &proposal_store,
        &[],
        0u32,
        1u32,
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
        proposal_reference_add_bob1,
    ];
    assert!(!proposal_queue.contains(invalid_proposal_reference_list));

    // Get filtered proposals
    for filtered_proposal in proposal_queue.filtered_by_type(ProposalType::Add) {
        assert!(filtered_proposal.proposal().is_type(ProposalType::Add));
    }
}

/// Test, that we StagedProposalQueue is iterated in the right order.
#[apply(ciphersuites_and_backends)]
fn proposal_queue_order(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Framing parameters
    let framing_parameters = FramingParameters::new(&[], WireFormat::MlsPlaintext);
    // Define identities
    let (alice_credential_bundle, alice_key_package_bundle) =
        setup_client("Alice", ciphersuite, backend);
    let (_bob_credential_bundle, bob_key_package_bundle) =
        setup_client("Bob", ciphersuite, backend);

    let bob_key_package = bob_key_package_bundle.key_package();
    let alice_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let alice_update_key_package = alice_update_key_package_bundle.key_package();
    assert!(alice_update_key_package.verify(backend).is_ok());

    let group_context =
        GroupContext::new(GroupId::random(backend), GroupEpoch(0), vec![], vec![], &[])
            .expect("An unexpected error occurred.");

    // Let's create some proposals
    let add_proposal_alice1 = AddProposal {
        key_package: alice_key_package_bundle.key_package().clone(),
    };
    let add_proposal_bob1 = AddProposal {
        key_package: bob_key_package.clone(),
    };

    let proposal_add_alice1 = Proposal::Add(add_proposal_alice1);
    let proposal_reference_add_alice1 =
        ProposalReference::from_proposal(ciphersuite, backend, &proposal_add_alice1)
            .expect("An unexpected error occurred.");
    let proposal_add_bob1 = Proposal::Add(add_proposal_bob1);

    // Frame proposals in MlsPlaintext
    let mls_plaintext_add_alice1 = MlsPlaintext::member_proposal(
        framing_parameters,
        0u32,
        proposal_add_alice1.clone(),
        &alice_credential_bundle,
        &group_context,
        &MembershipKey::from_secret(
            Secret::random(ciphersuite, backend, None /* MLS version */)
                .expect("Not enough randomness."),
        ),
        backend,
    )
    .expect("Could not create proposal.");
    let mls_plaintext_add_bob1 = MlsPlaintext::member_proposal(
        framing_parameters,
        1u32,
        proposal_add_bob1.clone(),
        &alice_credential_bundle,
        &group_context,
        &MembershipKey::from_secret(
            Secret::random(ciphersuite, backend, None /* MLS version */)
                .expect("Not enough randomness."),
        ),
        backend,
    )
    .expect("Could not create proposal.");

    // This should set the order of the proposals.
    let mut proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, mls_plaintext_add_alice1)
            .expect("Could not create StagedProposal."),
    );
    proposal_store.add(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, mls_plaintext_add_bob1)
            .expect("Could not create StagedProposal."),
    );

    let proposal_or_refs = vec![
        ProposalOrRef::Proposal(proposal_add_bob1.clone()),
        ProposalOrRef::Reference(proposal_reference_add_alice1),
    ];

    let sender = Sender {
        sender_type: SenderType::Member,
        sender: (0u32),
    };

    // And the same should go for proposal queues built from committed
    // proposals. The order here should be dictated by the proposals passed
    // as ProposalOrRefs.
    let proposal_queue = StagedProposalQueue::from_committed_proposals(
        ciphersuite,
        backend,
        proposal_or_refs,
        &proposal_store,
        sender,
    )
    .expect("An unexpected error occurred.");

    let proposal_collection: Vec<&StagedProposal> =
        proposal_queue.filtered_by_type(ProposalType::Add).collect();

    assert_eq!(proposal_collection[0].proposal(), &proposal_add_bob1);
    assert_eq!(proposal_collection[1].proposal(), &proposal_add_alice1);
}

#[apply(ciphersuites_and_backends)]
fn test_required_unsupported_proposals(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let (_alice_credential_bundle, alice_key_package_bundle) =
        setup_client("Alice", ciphersuite, backend);

    // Set required capabilities
    let extensions = &[];
    let proposals = &[ProposalType::GroupContextExtensions, ProposalType::AppAck];
    let required_capabilities = RequiredCapabilitiesExtension::new(extensions, proposals);

    // This must fail because we don't actually support AppAck proposals
    let e = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .with_required_capabilities(required_capabilities)
        .build(backend)
        .expect_err(
            "CoreGroup creation must fail because AppAck proposals aren't supported in OpenMLS yet.",
        );
    assert_eq!(
        e,
        CoreGroupError::ConfigError(ConfigError::UnsupportedProposalType)
    )
}

#[apply(ciphersuites_and_backends)]
fn test_required_extension_key_package_mismatch(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    let (alice_credential_bundle, alice_key_package_bundle) =
        setup_client("Alice", ciphersuite, backend);
    let (_bob_credential_bundle, bob_key_package_bundle) =
        setup_client("Bob", ciphersuite, backend);
    let bob_key_package = bob_key_package_bundle.key_package();

    // Set required capabilities
    let extensions = &[
        ExtensionType::Capabilities,
        ExtensionType::RequiredCapabilities,
        ExtensionType::KeyId,
    ];
    let proposals = &[
        ProposalType::GroupContextExtensions,
        ProposalType::Add,
        ProposalType::Remove,
        ProposalType::Update,
    ];
    let required_capabilities = RequiredCapabilitiesExtension::new(extensions, proposals);

    let alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .with_required_capabilities(required_capabilities)
        .build(backend)
        .expect("Error creating CoreGroup.");

    let e = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect_err("Proposal was created even though the key package didn't support the required extensions.");
    assert_eq!(
        e,
        CoreGroupError::KeyPackageError(KeyPackageError::UnsupportedExtension)
    );
}

#[apply(ciphersuites_and_backends)]
fn test_group_context_extensions(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    let (alice_credential_bundle, alice_key_package_bundle) =
        setup_client("Alice", ciphersuite, backend);
    let (bob_credential_bundle, _) = setup_client("Bob", ciphersuite, backend);

    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        vec![Extension::KeyPackageId(KeyIdExtension::default())],
    )
    .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    // Set required capabilities
    let extensions = &[ExtensionType::Capabilities, ExtensionType::KeyId];
    let proposals = &[
        ProposalType::GroupContextExtensions,
        ProposalType::Add,
        ProposalType::Remove,
        ProposalType::Update,
    ];
    let required_capabilities = RequiredCapabilitiesExtension::new(extensions, proposals);

    let mut alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .with_required_capabilities(required_capabilities)
        .build(backend)
        .expect("Error creating CoreGroup.");

    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal");

    let mut proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create StagedProposal."),
    );
    log::info!(" >>> Creating commit ...");
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend)
        .expect("Error creating commit");

    log::info!(" >>> Staging & merging commit ...");

    let mut alice_mss = MessageSecretsStore::new(0);
    alice_group
        .merge_staged_commit(
            create_commit_result.staged_commit,
            &mut proposal_store,
            &mut alice_mss,
        )
        .expect("error merging own staged commit");
    let ratchet_tree = alice_group.treesync().export_nodes();

    // Make sure that Bob can join the group with the required extension in place
    // and Bob's key package supporting them.
    let _bob_group = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree),
        bob_key_package_bundle,
        backend,
    )
    .expect("Error joining group.");
}

#[apply(ciphersuites_and_backends)]
fn test_group_context_extension_proposal_fails(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    let (alice_credential_bundle, alice_key_package_bundle) =
        setup_client("Alice", ciphersuite, backend);
    let (bob_credential_bundle, _) = setup_client("Bob", ciphersuite, backend);

    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        vec![Extension::KeyPackageId(KeyIdExtension::default())],
    )
    .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    // Set required capabilities
    let extensions = &[ExtensionType::Capabilities];
    let proposals = &[
        ProposalType::GroupContextExtensions,
        ProposalType::Add,
        ProposalType::Remove,
        ProposalType::Update,
    ];
    let required_capabilities = RequiredCapabilitiesExtension::new(extensions, proposals);

    let mut alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .with_required_capabilities(required_capabilities)
        .build(backend)
        .expect("Error creating CoreGroup.");

    // Alice tries to add a required capability she doesn't support herself.
    let required_key_id = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
        &[ExtensionType::KeyId],
        &[],
    ));
    let e = alice_group.create_group_context_ext_proposal(
        framing_parameters,
        &alice_credential_bundle,
        &[required_key_id.clone()],
        backend,
    ).expect_err("Alice was able to create a gce proposal with a required extensions she doesn't support.");
    assert_eq!(
        e,
        CoreGroupError::KeyPackageError(KeyPackageError::UnsupportedExtension)
    );

    // Well, this failed luckily.

    // Adding Bob
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal");

    let mut proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create StagedProposal."),
    );
    log::info!(" >>> Creating commit ...");
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend)
        .expect("Error creating commit");

    log::info!(" >>> Staging & merging commit ...");

    alice_group
        .merge_staged_commit(
            create_commit_result.staged_commit,
            &mut proposal_store,
            &mut MessageSecretsStore::new(0),
        )
        .expect("error merging pending commit");
    let ratchet_tree = alice_group.treesync().export_nodes();

    let bob_group = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree),
        bob_key_package_bundle,
        backend,
    )
    .expect("Error joining group.");

    // Now Bob wants the KeyId extension to be required.
    // This should fail because Alice doesn't support it.
    let e = bob_group
        .create_group_context_ext_proposal(
            framing_parameters,
            &alice_credential_bundle,
            &[required_key_id],
            backend,
        )
        .expect_err("Bob was able to create a gce proposal for an extension not supported by all other parties.");
    assert_eq!(
        e,
        CoreGroupError::KeyPackageError(KeyPackageError::UnsupportedExtension)
    );
}

#[apply(ciphersuites_and_backends)]
fn test_group_context_extension_proposal(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    let (alice_credential_bundle, _) = setup_client("Alice", ciphersuite, backend);
    let (bob_credential_bundle, _) = setup_client("Bob", ciphersuite, backend);

    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        vec![Extension::KeyPackageId(KeyIdExtension::default())],
    )
    .expect("An unexpected error occurred.");
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        vec![Extension::KeyPackageId(KeyIdExtension::default())],
    )
    .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    // Set required capabilities
    let extensions = &[ExtensionType::Capabilities];
    let proposals = &[
        ProposalType::GroupContextExtensions,
        ProposalType::Add,
        ProposalType::Remove,
        ProposalType::Update,
    ];
    let required_capabilities = RequiredCapabilitiesExtension::new(extensions, proposals);

    let mut alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .with_required_capabilities(required_capabilities)
        .build(backend)
        .expect("Error creating CoreGroup.");

    // Adding Bob
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal");

    let mut proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create StagedProposal."),
    );
    log::info!(" >>> Creating commit ...");
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_results = alice_group
        .create_commit(params, backend)
        .expect("Error creating commit");

    log::info!(" >>> Staging & merging commit ...");

    alice_group
        .merge_staged_commit(
            create_commit_results.staged_commit,
            &mut proposal_store,
            &mut MessageSecretsStore::new(0),
        )
        .expect("error merging pending commit");

    let ratchet_tree = alice_group.treesync().export_nodes();

    let mut bob_group = CoreGroup::new_from_welcome(
        create_commit_results
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree),
        bob_key_package_bundle,
        backend,
    )
    .expect("Error joining group.");

    // Alice adds a required capability.
    let required_key_id = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
        &[ExtensionType::KeyId],
        &[],
    ));
    let gce_proposal = alice_group
        .create_group_context_ext_proposal(
            framing_parameters,
            &alice_credential_bundle,
            &[required_key_id],
            backend,
        )
        .expect("Error creating gce proposal.");

    let mut proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, gce_proposal)
            .expect("Could not create StagedProposal."),
    );
    log::info!(" >>> Creating commit ...");
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend)
        .expect("Error creating commit");

    log::info!(" >>> Staging & merging commit ...");

    let staged_commit = bob_group
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    bob_group
        .merge_commit(staged_commit)
        .expect("error merging commit");

    alice_group
        .merge_staged_commit(
            create_commit_result.staged_commit,
            &mut proposal_store,
            &mut MessageSecretsStore::new(0),
        )
        .expect("error merging pending commit");

    assert_eq!(
        alice_group
            .export_secret(backend, "label", b"gce test", 32)
            .expect("Error exporting secret."),
        bob_group
            .export_secret(backend, "label", b"gce test", 32)
            .expect("Error exporting secret.")
    )
}
