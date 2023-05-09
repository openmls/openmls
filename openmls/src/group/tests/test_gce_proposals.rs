use crate::{
    credentials::CredentialType,
    extensions::{
        ApplicationIdExtension, Extension, ExtensionType, Extensions, ExternalSender,
        ExternalSendersExtension, RequiredCapabilitiesExtension, SenderExtensionIndex,
    },
    framing::{
        validation::ProcessedMessageContent, FramedContentBody, MlsMessageIn, MlsMessageOut,
    },
    group::core_group::test_core_group::setup_client,
    group::{
        config::CryptoConfig,
        errors::*,
        mls_group::{config::MlsGroupConfig, MlsGroup},
        test_core_group::setup_client_with_extensions,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    messages::{
        external_proposals::{ExternalProposal, JoinProposal},
        proposals::{GroupContextExtensionProposal, Proposal, ProposalOrRef, ProposalType},
    },
    test_utils::*,
    treesync::{
        errors::{LeafNodeValidationError, MemberExtensionValidationError},
        node::leaf_node::Capabilities,
    },
    versions::ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{signatures::Signer, types::Ciphersuite, OpenMlsCryptoProvider};

use super::utils::resign_message;

pub const DEFAULT_PROPOSAL_TYPES: [ProposalType; 6] = [
    ProposalType::Add,
    ProposalType::Update,
    ProposalType::Remove,
    ProposalType::PreSharedKey,
    ProposalType::Reinit,
    ProposalType::GroupContextExtensions,
];

pub const DEFAULT_CREDENTIAL_TYPES: [CredentialType; 1] = [CredentialType::Basic];

#[apply(ciphersuites_and_backends)]
fn gce_are_forwarded_in_welcome(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::ExternalSenders],
        &DEFAULT_PROPOSAL_TYPES,
        &DEFAULT_CREDENTIAL_TYPES,
    );
    let (ds_credential, ..) = setup_client("delivery service", ciphersuite, backend);
    let external_senders = vec![ExternalSender::new(
        ds_credential.signature_key,
        ds_credential.credential,
    )];
    let kp_capabilities = Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::ExternalSenders]),
        None,
        Some(&DEFAULT_CREDENTIAL_TYPES),
    );
    // Bob has been created from a welcome message
    let (alice_group, bob_group, ..) = group_setup(
        ciphersuite,
        required_capabilities.clone(),
        Some(external_senders.clone()),
        Extensions::empty(),
        kp_capabilities,
        backend,
    );
    assert_eq!(
        *alice_group.group_context_extensions(),
        Extensions::from_vec(vec![
            Extension::RequiredCapabilities(required_capabilities),
            Extension::ExternalSenders(external_senders)
        ])
        .unwrap()
    );
    assert_eq!(
        alice_group.group_context_extensions(),
        bob_group.group_context_extensions()
    );
}

#[should_panic]
#[apply(ciphersuites_and_backends)]
fn cannot_create_group_when_keypackage_lacks_required_capability(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities = RequiredCapabilitiesExtension::new(
        // External senders is required...
        &[ExtensionType::ExternalSenders],
        &DEFAULT_PROPOSAL_TYPES,
        &DEFAULT_CREDENTIAL_TYPES,
    );
    let _ = group_setup(
        ciphersuite,
        required_capabilities,
        None,
        // ...but not present in keypackage extensions
        Extensions::empty(),
        Capabilities::default(),
        backend,
    );
}

#[apply(ciphersuites_and_backends)]
fn gce_fails_when_it_contains_unsupported_extensions(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities =
        RequiredCapabilitiesExtension::new(&[], &DEFAULT_PROPOSAL_TYPES, &DEFAULT_CREDENTIAL_TYPES);
    // Bob has been created from a welcome message
    let (mut alice_group, mut bob_group, alice_signer, bob_signer) = group_setup(
        ciphersuite,
        required_capabilities,
        None,
        Extensions::empty(),
        Capabilities::default(),
        backend,
    );
    // Alice tries to add a required capability she doesn't support herself.
    let required_key_id = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
        &[ExtensionType::ExternalSenders],
        &[],
        &[],
    ));
    let e = alice_group.propose_extensions(backend, &alice_signer, Extensions::single(required_key_id.clone()))
        .expect_err("Alice was able to create a gce proposal with a required extensions she doesn't support.");
    assert_eq!(
        e,
        ProposeGroupContextExtensionError::MemberExtensionValidationError(
            MemberExtensionValidationError::LeafNodeValidationError(
                LeafNodeValidationError::UnsupportedExtensions
            )
        )
    );
    // Now Bob wants the ExternalSenders extension to be required.
    // This should fail because Alice doesn't support it.
    let e = bob_group
        .propose_extensions(backend, &bob_signer, Extensions::single(required_key_id))
        .expect_err("Bob was able to create a gce proposal for an extension not supported by all other parties.");
    assert_eq!(
        e,
        ProposeGroupContextExtensionError::MemberExtensionValidationError(
            MemberExtensionValidationError::LeafNodeValidationError(
                LeafNodeValidationError::UnsupportedExtensions
            )
        )
    );
}

#[apply(ciphersuites_and_backends)]
fn gce_proposal_should_overwrite_previous(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let old_required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::ExternalSenders],
        &[
            ProposalType::Add,
            ProposalType::Update,
            ProposalType::Remove,
            ProposalType::PreSharedKey,
            ProposalType::GroupContextExtensions,
        ],
        &DEFAULT_CREDENTIAL_TYPES,
    );
    let new_required_capabilities = RequiredCapabilitiesExtension::new(
        &[ExtensionType::RatchetTree, ExtensionType::ApplicationId],
        &[
            ProposalType::Add,
            ProposalType::Update,
            ProposalType::Remove,
            ProposalType::Reinit,
            ProposalType::GroupContextExtensions,
        ],
        &DEFAULT_CREDENTIAL_TYPES,
    );

    let kp_extensions = Extensions::from_vec(vec![
        Extension::ExternalSenders(ExternalSendersExtension::default()),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[
                ExtensionType::ExternalSenders,
                ExtensionType::RatchetTree,
                ExtensionType::ApplicationId,
            ],
            &DEFAULT_PROPOSAL_TYPES,
            &DEFAULT_CREDENTIAL_TYPES,
        )),
    ])
    .unwrap();

    let kp_capabilities = Capabilities::new(
        None,
        None,
        Some(&[
            ExtensionType::ExternalSenders,
            ExtensionType::RatchetTree,
            ExtensionType::ApplicationId,
        ]),
        None,
        Some(&DEFAULT_CREDENTIAL_TYPES),
    );
    let (mut alice_group, _, alice_signer, _) = group_setup(
        ciphersuite,
        old_required_capabilities,
        None,
        kp_extensions,
        kp_capabilities,
        backend,
    );

    // Alice adds a required capability.
    let new_extensions = Extensions::from_vec(vec![
        Extension::RequiredCapabilities(new_required_capabilities),
        Extension::ApplicationId(ApplicationIdExtension::new(b"test_mls")),
    ])
    .unwrap();
    alice_group
        .propose_extensions(backend, &alice_signer, new_extensions.clone())
        .unwrap();
    alice_group
        .commit_to_pending_proposals(backend, &alice_signer)
        .unwrap();
    alice_group.merge_pending_commit(backend).unwrap();
    assert_eq!(*alice_group.group_context_extensions(), new_extensions);
}

#[apply(ciphersuites_and_backends)]
fn gce_proposal_can_roundtrip(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let required_capabilities =
        RequiredCapabilitiesExtension::new(&[], &DEFAULT_PROPOSAL_TYPES, &DEFAULT_CREDENTIAL_TYPES);
    let (mut alice_group, mut bob_group, alice_signer, bob_signer) = group_setup(
        ciphersuite,
        required_capabilities,
        None,
        Extensions::empty(),
        Capabilities::default(),
        backend,
    );

    // Alice adds an extension
    let new_extensions = Extensions::single(Extension::ApplicationId(ApplicationIdExtension::new(
        b"test_mls",
    )));
    let (gce_proposal, _) = alice_group
        .propose_extensions(backend, &alice_signer, new_extensions.clone())
        .unwrap();
    let processed_message = bob_group
        .process_message(backend, MlsMessageIn::from(gce_proposal))
        .unwrap();
    let ProcessedMessageContent::ProposalMessage(gce_proposal) = processed_message.into_content() else { panic!("Not a remove proposal");};
    bob_group.store_pending_proposal(*gce_proposal);
    let (commit, _, _) = bob_group
        .commit_to_pending_proposals(backend, &bob_signer)
        .unwrap();
    bob_group.merge_pending_commit(backend).unwrap();
    assert_eq!(*bob_group.group_context_extensions(), new_extensions);

    let message = alice_group
        .process_message(backend, MlsMessageIn::from(commit))
        .unwrap();
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) = message.into_content() {
        alice_group
            .merge_staged_commit(backend, *staged_commit)
            .unwrap()
    }
    assert_eq!(*alice_group.group_context_extensions(), new_extensions);
}

#[apply(ciphersuites_and_backends)]
fn creating_commit_with_more_than_one_gce_proposal_should_fail(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities =
        RequiredCapabilitiesExtension::new(&[], &DEFAULT_PROPOSAL_TYPES, &DEFAULT_CREDENTIAL_TYPES);
    let (mut alice_group, _, alice_signer, _) = group_setup(
        ciphersuite,
        required_capabilities,
        None,
        Extensions::empty(),
        Capabilities::default(),
        backend,
    );

    // Alice creates a commit with 2 GroupContextExtension proposals, should fail
    let application_id = Extension::ApplicationId(ApplicationIdExtension::new(b"mls_test"));
    alice_group
        .propose_extensions(backend, &alice_signer, Extensions::single(application_id))
        .unwrap();
    let external_senders = Extension::ExternalSenders(ExternalSendersExtension::default());
    alice_group
        .propose_extensions(backend, &alice_signer, Extensions::single(external_senders))
        .unwrap();
    assert_eq!(alice_group.pending_proposals().count(), 2);
    let commit = alice_group.commit_to_pending_proposals(backend, &alice_signer);
    assert_eq!(
        commit.unwrap_err(),
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::ProposalValidationError(
                ProposalValidationError::TooManyGroupContextExtensions(2)
            )
        )
    );
}

#[apply(ciphersuites_and_backends)]
fn validating_commit_with_more_than_one_gce_proposal_should_fail(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities =
        RequiredCapabilitiesExtension::new(&[], &DEFAULT_PROPOSAL_TYPES, &DEFAULT_CREDENTIAL_TYPES);
    let (mut alice_group, mut bob_group, alice_signer, bob_signer) = group_setup(
        ciphersuite,
        required_capabilities,
        None,
        Extensions::empty(),
        Capabilities::default(),
        backend,
    );

    // Alice creates a commit with 2 GroupContextExtension proposals, should fail
    let application_id = Extension::ApplicationId(ApplicationIdExtension::new(b"test_mls"));
    let (first_gce_proposal, _) = alice_group
        .propose_extensions(backend, &alice_signer, Extensions::single(application_id))
        .unwrap();
    let processed_message = bob_group
        .process_message(backend, MlsMessageIn::from(first_gce_proposal))
        .unwrap();
    let ProcessedMessageContent::ProposalMessage(gce_proposal) = processed_message.into_content() else { panic!("Not a proposal");};
    bob_group.store_pending_proposal(*gce_proposal);

    // Bob creates a commit with just 1 GCE proposal
    let (commit, _, _) = bob_group
        .commit_to_pending_proposals(backend, &bob_signer)
        .unwrap();

    let external_senders = Extension::ExternalSenders(ExternalSendersExtension::default());
    let second_proposal = Proposal::GroupContextExtensions(GroupContextExtensionProposal::new(
        Extensions::single(external_senders),
    ));

    // We create a fake commit with 2 GCE proposal by rewriting the commit message
    // because otherwise the library would prevent us to  do so
    let commit_with_2_gce_proposal = add_gce_proposal_to_commit(
        commit.into(),
        &bob_group,
        &bob_signer,
        second_proposal,
        backend,
    );

    let process = alice_group
        .process_message(backend, commit_with_2_gce_proposal)
        .unwrap_err();
    // Alice does not accept a commit with 2 GCE proposals
    assert_eq!(
        process,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::TooManyGroupContextExtensions(2)
        ))
    );
}

#[apply(ciphersuites_and_backends)]
fn gce_proposal_must_be_applied_first_then_used_to_validate_other_add_proposals(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities =
        RequiredCapabilitiesExtension::new(&[], &DEFAULT_PROPOSAL_TYPES, &DEFAULT_CREDENTIAL_TYPES);
    let kp_extensions = Extensions::from_vec(vec![
        Extension::ExternalSenders(ExternalSendersExtension::default()),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::ExternalSenders],
            &DEFAULT_PROPOSAL_TYPES,
            &DEFAULT_CREDENTIAL_TYPES,
        )),
    ])
    .unwrap();
    let kp_capabilities = Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::ExternalSenders]),
        None,
        Some(&DEFAULT_CREDENTIAL_TYPES),
    );
    // Alice & Bob both support ExternalSenders
    let (mut alice_group, mut bob_group, alice_signer, bob_signer) = group_setup(
        ciphersuite,
        required_capabilities,
        None,
        kp_extensions,
        kp_capabilities,
        backend,
    );

    // Propose to add ExternalSenders to RequiredCapabilities
    let new_required_capabilities =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::ExternalSenders],
            &DEFAULT_PROPOSAL_TYPES,
            &DEFAULT_CREDENTIAL_TYPES,
        ));
    let (gce_proposal, _) = alice_group
        .propose_extensions(
            backend,
            &alice_signer,
            Extensions::single(new_required_capabilities),
        )
        .unwrap();

    // Charlie does not have ExternalSenders in its extensions, hence it should fail to be added to the group
    let (_, charlie_key_package_bundle, ..) = setup_client("Charlie", ciphersuite, backend);
    let (charlie_add_proposal, _) = alice_group
        .propose_add_member(
            backend,
            &alice_signer,
            charlie_key_package_bundle.key_package(),
        )
        .unwrap();

    let processed_message = bob_group
        .process_message(backend, MlsMessageIn::from(charlie_add_proposal))
        .unwrap();
    let ProcessedMessageContent::ProposalMessage(add_proposal) = processed_message.into_content() else { panic!("Not a remove proposal");};
    bob_group.store_pending_proposal(*add_proposal);

    let processed_message = bob_group
        .process_message(backend, MlsMessageIn::from(gce_proposal))
        .unwrap();
    let ProcessedMessageContent::ProposalMessage(gce_proposal) = processed_message.into_content() else { panic!("Not a remove proposal");};
    bob_group.store_pending_proposal(*gce_proposal);

    assert_eq!(bob_group.pending_proposals().count(), 2);
    let commit = bob_group.commit_to_pending_proposals(backend, &bob_signer);
    // Bob does not accept the commit since adding Charlie would go against GCE proposal
    assert!(matches!(
            commit.unwrap_err(),
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::LibraryError(
                e
            )
        ) if e.to_string().contains( "Error description: Keypackage doens't support required capability")
    ));
}

#[apply(ciphersuites_and_backends)]
fn gce_proposal_must_be_applied_first_then_used_to_validate_other_external_add_proposals(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities =
        RequiredCapabilitiesExtension::new(&[], &DEFAULT_PROPOSAL_TYPES, &DEFAULT_CREDENTIAL_TYPES);
    let kp_extensions = Extensions::from_vec(vec![
        Extension::ExternalSenders(ExternalSendersExtension::default()),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::ExternalSenders],
            &DEFAULT_PROPOSAL_TYPES,
            &DEFAULT_CREDENTIAL_TYPES,
        )),
    ])
    .unwrap();
    let kp_capabilities = Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::ExternalSenders]),
        None,
        Some(&DEFAULT_CREDENTIAL_TYPES),
    );
    // Alice support ExternalSenders
    let (mut alice_group, _, alice_signer, _) = group_setup(
        ciphersuite,
        required_capabilities,
        None,
        kp_extensions,
        kp_capabilities,
        backend,
    );

    // Propose to add ExternalSenders to RequiredCapabilities
    let new_required_capabilities =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::ExternalSenders],
            &DEFAULT_PROPOSAL_TYPES,
            &DEFAULT_CREDENTIAL_TYPES,
        ));
    alice_group
        .propose_extensions(
            backend,
            &alice_signer,
            Extensions::single(new_required_capabilities),
        )
        .unwrap();

    // Charlie does not have ExternalSenders in its extensions, hence it should fail to be added to the group
    let (_, charlie_key_package_bundle, charlie_signer, _) =
        setup_client("Charlie", ciphersuite, backend);

    let charlie_add_proposal = JoinProposal::new(
        charlie_key_package_bundle.key_package,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &charlie_signer,
    )
    .unwrap();

    let processed_message = alice_group
        .process_message(backend, MlsMessageIn::from(charlie_add_proposal))
        .unwrap();
    let ProcessedMessageContent::ExternalJoinProposalMessage(charlie_add_proposal) = processed_message.into_content() else { panic!("Not a proposal");};
    alice_group.store_pending_proposal(*charlie_add_proposal);

    assert_eq!(alice_group.pending_proposals().count(), 2);
    let commit = alice_group.commit_to_pending_proposals(backend, &alice_signer);
    // Alice refuses to add Charlie because it does not satisfy GCE proposal
    assert!(matches!(
            commit.unwrap_err(),
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::LibraryError(
                e
            )
        ) if e.to_string().contains( "Error description: Keypackage doens't support required capability")
    ));
}

#[apply(ciphersuites_and_backends)]
fn gce_proposal_must_be_applied_first_but_ignored_for_remove_proposals(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities =
        RequiredCapabilitiesExtension::new(&[], &DEFAULT_PROPOSAL_TYPES, &DEFAULT_CREDENTIAL_TYPES);
    // Alice & Bob have ExternalSenders support even though it is not required
    let external_senders = Extension::ExternalSenders(ExternalSendersExtension::default());
    let kp_extensions = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
        &[ExtensionType::ExternalSenders],
        &DEFAULT_PROPOSAL_TYPES,
        &DEFAULT_CREDENTIAL_TYPES,
    ));
    let kp_capabilities = Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::ExternalSenders]),
        None,
        Some(&DEFAULT_CREDENTIAL_TYPES),
    );
    let (mut alice_group, mut bob_group, alice_signer, _) = group_setup(
        ciphersuite,
        required_capabilities,
        None,
        Extensions::from_vec(vec![external_senders, kp_extensions]).unwrap(),
        kp_capabilities,
        backend,
    );

    // Charlie does not have ExternalSenders in its extensions
    let (_, charlie_key_package_bundle, ..) = setup_client("Charlie", ciphersuite, backend);
    let (commit, ..) = alice_group
        .add_members(
            backend,
            &alice_signer,
            &[charlie_key_package_bundle.key_package().clone()],
        )
        .unwrap();
    let commit = bob_group
        .process_message(backend, MlsMessageIn::from(commit))
        .unwrap();
    if let ProcessedMessageContent::StagedCommitMessage(commit) = commit.into_content() {
        bob_group.merge_staged_commit(backend, *commit).unwrap();
    }
    alice_group.merge_pending_commit(backend).unwrap();

    // Propose requiring ExternalSenders, which Charlie does not support
    let new_required_capabilities =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::ExternalSenders],
            &DEFAULT_PROPOSAL_TYPES,
            &DEFAULT_CREDENTIAL_TYPES,
        ));

    let extension_proposal = alice_group.propose_extensions(
        backend,
        &alice_signer,
        Extensions::single(new_required_capabilities.clone()),
    );
    // because group contains Charlie which is incompatible with new extensions
    assert!(extension_proposal.is_err());
    alice_group.clear_pending_proposals();

    let charlie_index = alice_group
        .members()
        .find(|member| member.credential.identity() == b"Charlie")
        .map(|member| member.index)
        .unwrap();
    let (charlie_remove_proposal, _) = alice_group
        .propose_remove_member(backend, &alice_signer, charlie_index)
        .unwrap();

    // Bob is able to process remove proposal
    bob_group
        .process_message(backend, MlsMessageIn::from(charlie_remove_proposal))
        .unwrap();

    let (extension_proposal, _) = alice_group
        .propose_extensions(
            backend,
            &alice_signer,
            Extensions::single(new_required_capabilities),
        )
        .unwrap();
    assert_eq!(alice_group.pending_proposals().count(), 2);

    // Charlie does not support this extension. But since Charlie is proposed for removal it should not fail.

    // Bob is able to process GCE proposal
    bob_group
        .process_message(backend, MlsMessageIn::from(extension_proposal))
        .unwrap();
    // Bob accepts GCE proposal since it also has one for removing Charlie

    // Once validating proposals, it should not fail as even though Charlie does not support the new
    // required extensions, he is going to be removed from the group
    alice_group
        .commit_to_pending_proposals(backend, &alice_signer)
        .unwrap();
    alice_group.merge_pending_commit(backend).unwrap();
    assert_eq!(alice_group.members().count(), 2);
}

#[apply(ciphersuites_and_backends)]
fn gce_proposal_must_be_applied_first_but_ignored_for_external_remove_proposals(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let (ds_credential_bundle, _, ds_signer, _) = setup_client("DS", ciphersuite, backend);

    let required_capabilities =
        RequiredCapabilitiesExtension::new(&[], &DEFAULT_PROPOSAL_TYPES, &DEFAULT_CREDENTIAL_TYPES);
    // Alice & Bob have ExternalSenders support even though it is not required
    let external_sender = ExternalSender::new(
        ds_credential_bundle.signature_key,
        ds_credential_bundle.credential,
    );
    let external_senders = Extension::ExternalSenders(vec![external_sender.clone()]);
    let kp_extensions = Extensions::from_vec(vec![
        external_senders,
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::ExternalSenders],
            &DEFAULT_PROPOSAL_TYPES,
            &DEFAULT_CREDENTIAL_TYPES,
        )),
    ])
    .unwrap();
    let kp_capabilities = Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::ExternalSenders]),
        None,
        Some(&DEFAULT_CREDENTIAL_TYPES),
    );
    let (mut alice_group, _, alice_signer, _) = group_setup(
        ciphersuite,
        required_capabilities,
        Some(vec![external_sender]),
        kp_extensions,
        kp_capabilities,
        backend,
    );

    // Charlie does not have ExternalSenders in its extensions
    let (_, charlie_key_package_bundle, ..) = setup_client("Charlie", ciphersuite, backend);
    alice_group
        .add_members(
            backend,
            &alice_signer,
            &[charlie_key_package_bundle.key_package().clone()],
        )
        .unwrap();
    alice_group.merge_pending_commit(backend).unwrap();
    assert_eq!(alice_group.members().count(), 3);

    let charlie_index = alice_group
        .members()
        .find(|member| member.credential.identity() == b"Charlie")
        .map(|member| member.index)
        .unwrap();
    let charlie_ext_remove_proposal = ExternalProposal::new_remove(
        charlie_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_signer,
        SenderExtensionIndex::new(0),
    )
    .unwrap();

    let processed_message = alice_group
        .process_message(backend, MlsMessageIn::from(charlie_ext_remove_proposal))
        .unwrap();
    let ProcessedMessageContent::ProposalMessage(charlie_ext_remove_proposal) = processed_message.into_content() else { panic!("Not a remove proposal");};
    alice_group.store_pending_proposal(*charlie_ext_remove_proposal);

    // Propose requiring ExternalSenders, which Charlie does not support
    let new_required_capabilities =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::ExternalSenders],
            &DEFAULT_PROPOSAL_TYPES,
            &DEFAULT_CREDENTIAL_TYPES,
        ));
    alice_group
        .propose_extensions(
            backend,
            &alice_signer,
            Extensions::single(new_required_capabilities),
        )
        .unwrap();
    // Once validating proposals, it should not fail as even though Charlie does not support the new
    // required extensions, he is going to be removed from the group
    let commit = alice_group.commit_to_pending_proposals(backend, &alice_signer);
    assert!(commit.is_ok());
    alice_group.merge_pending_commit(backend).unwrap();
    assert_eq!(alice_group.members().count(), 2);
}

pub fn group_setup(
    ciphersuite: Ciphersuite,
    required_capabilities: RequiredCapabilitiesExtension,
    external_senders: Option<ExternalSendersExtension>,
    kp_extensions: Extensions,
    kp_capabilities: Capabilities,
    backend: &impl OpenMlsCryptoProvider,
) -> (MlsGroup, MlsGroup, SignatureKeyPair, SignatureKeyPair) {
    // Basic group setup.
    let (alice_credential_bundle, _kpb, alice_signer, _pk) = setup_client_with_extensions(
        "Alice",
        ciphersuite,
        backend,
        kp_extensions.clone(),
        kp_capabilities.clone(),
    );
    let (_, bob_key_package_bundle, bob_signer, _pk) = setup_client_with_extensions(
        "Bob",
        ciphersuite,
        backend,
        kp_extensions.clone(),
        kp_capabilities.clone(),
    );

    let external_senders = external_senders.unwrap_or_default();
    let crypto_config = CryptoConfig {
        ciphersuite,
        version: ProtocolVersion::default(),
    };

    let cfg = MlsGroupConfig {
        wire_format_policy: PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        required_capabilities,
        external_senders,
        crypto_config,
        leaf_extensions: kp_extensions,
        leaf_capabilities: Some(kp_capabilities),
        ..Default::default()
    };
    let mut alice_group =
        MlsGroup::new(backend, &alice_signer, &cfg, alice_credential_bundle).unwrap();

    let (_, welcome, _) = alice_group
        .add_members(
            backend,
            &alice_signer,
            &[bob_key_package_bundle.key_package().clone()],
        )
        .unwrap();
    alice_group.merge_pending_commit(backend).unwrap();
    let bob_group = MlsGroup::new_from_welcome(
        backend,
        &cfg,
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap();
    (alice_group, bob_group, alice_signer, bob_signer)
}

fn add_gce_proposal_to_commit(
    commit: MlsMessageIn,
    group: &MlsGroup,
    signer: &impl Signer,
    proposal: Proposal,
    backend: &impl OpenMlsCryptoProvider,
) -> MlsMessageIn {
    let original_pub_msg = commit.into_plaintext().unwrap();
    let mut new_pub_msg = original_pub_msg.clone();

    let mut commit = if let FramedContentBody::Commit(commit) = original_pub_msg.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };
    commit.proposals.push(ProposalOrRef::Proposal(proposal));
    new_pub_msg.set_content(FramedContentBody::Commit(commit));

    let pub_msg = resign_message(group, new_pub_msg, &original_pub_msg, backend, signer);
    MlsMessageIn::from(Into::<MlsMessageOut>::into(pub_msg))
}
