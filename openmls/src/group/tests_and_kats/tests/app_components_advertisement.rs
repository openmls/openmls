//! Tests that a leaf node supporting the `app_data_dictionary` extension
//! advertises the `app_components` component (draft-ietf-mls-extensions-10,
//! Section 4.6), both when OpenMLS produces leaf nodes and when it receives
//! them.

use openmls_traits::types::Ciphersuite;
use tls_codec::{Deserialize as _, Serialize as _};

use super::proposal_validation::{
    insert_proposal_and_resign, validation_test_setup, ProposalValidationTestSetup,
};
use crate::{
    component::{ComponentId, ComponentType},
    extensions::{AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionType},
    framing::{MlsMessageIn, ProcessedMessageContent, ProtocolMessage, PublicMessage},
    group::{tests_and_kats::utils::generate_credential_with_key, *},
    key_packages::{errors::*, KeyPackage, KeyPackageIn},
    messages::proposals::{AddProposal, Proposal, ProposalOrRef},
    prelude::{Capabilities, Extensions, LeafNode},
    test_utils::{app_components_leaf_extensions, frankenstein::*, minimal_capabilities_for},
    treesync::{
        errors::{ApplyOwnUpdatePathError, LeafNodeValidationError},
        node::leaf_node::{validate_app_components_advertised, LeafNodeBuildError},
        LeafNodeParameters, LeafNodeUpdateError,
    },
    versions::ProtocolVersion,
};

const APP_DATA_DICTIONARY: u16 = 6;
const COUNTER_COMPONENT_ID: ComponentId = 0xf042;

fn app_data_dictionary_capabilities(ciphersuite: Ciphersuite) -> Capabilities {
    minimal_capabilities_for(ciphersuite)
        .extensions(vec![ExtensionType::AppDataDictionary])
        .build()
}

fn leaf_extensions_with_dictionary(dictionary: AppDataDictionary) -> Extensions<LeafNode> {
    Extensions::single(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dictionary),
    ))
    .unwrap()
}

#[test]
fn app_components_check_outcomes() {
    let capabilities =
        app_data_dictionary_capabilities(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

    assert_eq!(
        validate_app_components_advertised(&Capabilities::default(), &Extensions::default()),
        Ok(())
    );
    assert_eq!(
        validate_app_components_advertised(&capabilities, &Extensions::default()),
        Err(LeafNodeValidationError::AppComponentsNotAdvertised)
    );

    let mut without_app_components = AppDataDictionary::new();
    without_app_components.insert(COUNTER_COMPONENT_ID, b"state".to_vec());
    assert_eq!(
        validate_app_components_advertised(
            &capabilities,
            &leaf_extensions_with_dictionary(without_app_components)
        ),
        Err(LeafNodeValidationError::AppComponentsNotAdvertised)
    );

    // A length prefix announcing more bytes than follow.
    let mut malformed_app_components = AppDataDictionary::new();
    malformed_app_components.insert(ComponentId::from(ComponentType::AppComponents), vec![0x04]);
    assert_eq!(
        validate_app_components_advertised(
            &capabilities,
            &leaf_extensions_with_dictionary(malformed_app_components)
        ),
        Err(LeafNodeValidationError::AppComponentsNotAdvertised)
    );

    assert_eq!(
        validate_app_components_advertised(&capabilities, &app_components_leaf_extensions(vec![])),
        Ok(())
    );
    assert_eq!(
        validate_app_components_advertised(
            &capabilities,
            &app_components_leaf_extensions(vec![COUNTER_COMPONENT_ID])
        ),
        Ok(())
    );
}

#[openmls_test::openmls_test]
fn key_package_builder_requires_app_components() {
    let provider = &Provider::default();
    let alice =
        generate_credential_with_key(b"alice".into(), ciphersuite.signature_algorithm(), provider);

    let err = KeyPackage::builder()
        .leaf_node_capabilities(app_data_dictionary_capabilities(ciphersuite))
        .build(
            ciphersuite,
            provider,
            &alice.signer,
            alice.credential_with_key.clone(),
        )
        .expect_err("built a KeyPackage that does not advertise app_components");
    assert_eq!(
        err,
        KeyPackageNewError::LeafNodeBuild(LeafNodeBuildError::Validation(
            LeafNodeValidationError::AppComponentsNotAdvertised
        ))
    );

    KeyPackage::builder()
        .leaf_node_capabilities(app_data_dictionary_capabilities(ciphersuite))
        .leaf_node_extensions(app_components_leaf_extensions(vec![COUNTER_COMPONENT_ID]))
        .build(
            ciphersuite,
            provider,
            &alice.signer,
            alice.credential_with_key.clone(),
        )
        .expect("failed to build a KeyPackage that advertises app_components");
}

#[openmls_test::openmls_test]
fn group_creation_requires_app_components() {
    let provider = &Provider::default();
    let alice =
        generate_credential_with_key(b"alice".into(), ciphersuite.signature_algorithm(), provider);

    let err = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_capabilities(app_data_dictionary_capabilities(ciphersuite))
        .build(provider, &alice.signer, alice.credential_with_key.clone())
        .expect_err("created a group whose creator does not advertise app_components");
    assert!(matches!(
        err,
        NewGroupError::LeafNodeBuild(LeafNodeBuildError::Validation(
            LeafNodeValidationError::AppComponentsNotAdvertised
        ))
    ));

    MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_capabilities(app_data_dictionary_capabilities(ciphersuite))
        .with_leaf_node_extensions(app_components_leaf_extensions(vec![COUNTER_COMPONENT_ID]))
        .unwrap()
        .build(provider, &alice.signer, alice.credential_with_key.clone())
        .expect("failed to create a group whose creator advertises app_components");
}

#[openmls_test::openmls_test]
fn self_update_commit_requires_app_components() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ProposalValidationTestSetup {
        mut alice_group,
        alice_credential_with_key_and_signer: alice,
        mut bob_group,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
    );

    let err = alice_group
        .self_update(
            alice_provider,
            &alice.signer,
            LeafNodeParameters::builder()
                .with_capabilities(app_data_dictionary_capabilities(ciphersuite))
                .build(),
        )
        .expect_err("committed a leaf node that does not advertise app_components");
    assert!(matches!(
        err,
        SelfUpdateError::CreateCommitError(CreateCommitError::ApplyOwnUpdatePath(
            ApplyOwnUpdatePathError::LeafNodeBuild(LeafNodeBuildError::Validation(
                LeafNodeValidationError::AppComponentsNotAdvertised
            ))
        ))
    ));

    let commit = alice_group
        .self_update(
            alice_provider,
            &alice.signer,
            LeafNodeParameters::builder()
                .with_capabilities(app_data_dictionary_capabilities(ciphersuite))
                .with_extensions(app_components_leaf_extensions(vec![COUNTER_COMPONENT_ID]))
                .build(),
        )
        .expect("failed to commit a leaf node that advertises app_components")
        .into_commit();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let commit = MlsMessageIn::from(commit)
        .try_into_protocol_message()
        .unwrap();
    let processed = bob_group
        .process_message(bob_provider, commit)
        .expect("failed to process a commit whose path leaf advertises app_components");
    let ProcessedMessageContent::StagedCommitMessage(staged_commit) = processed.into_content()
    else {
        panic!("expected a commit");
    };
    bob_group
        .merge_staged_commit(bob_provider, *staged_commit)
        .unwrap();
}

#[openmls_test::openmls_test]
fn self_update_proposal_requires_app_components() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ProposalValidationTestSetup {
        mut alice_group,
        alice_credential_with_key_and_signer: alice,
        mut bob_group,
        bob_credential_with_key_and_signer: bob,
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
    );

    let err = bob_group
        .propose_self_update(
            bob_provider,
            &bob.signer,
            LeafNodeParameters::builder()
                .with_capabilities(app_data_dictionary_capabilities(ciphersuite))
                .build(),
        )
        .expect_err("proposed a leaf node that does not advertise app_components");
    assert!(matches!(
        err,
        ProposeSelfUpdateError::LeafNodeUpdateError(LeafNodeUpdateError::Validation(
            LeafNodeValidationError::AppComponentsNotAdvertised
        ))
    ));

    let (proposal, _) = bob_group
        .propose_self_update(
            bob_provider,
            &bob.signer,
            LeafNodeParameters::builder()
                .with_capabilities(app_data_dictionary_capabilities(ciphersuite))
                .with_extensions(app_components_leaf_extensions(vec![COUNTER_COMPONENT_ID]))
                .build(),
        )
        .expect("failed to propose a leaf node that advertises app_components");

    let proposal = MlsMessageIn::from(proposal)
        .try_into_protocol_message()
        .unwrap();
    let ProcessedMessageContent::ProposalMessage(proposal) = alice_group
        .process_message(alice_provider, proposal)
        .unwrap()
        .into_content()
    else {
        panic!("expected a proposal");
    };
    alice_group
        .store_pending_proposal(alice_provider.storage(), *proposal)
        .unwrap();
    alice_group
        .commit_to_pending_proposals(alice_provider, &alice.signer)
        .expect("failed to commit an update whose leaf advertises app_components");
}

#[openmls_test::openmls_test]
fn external_commit_requires_app_components() {
    let alice_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let alice = generate_credential_with_key(
        b"alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let charlie = generate_credential_with_key(
        b"charlie".into(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );

    let alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(
            alice_provider,
            &alice.signer,
            alice.credential_with_key.clone(),
        )
        .unwrap();

    let external_commit = |leaf_node_parameters: LeafNodeParameters| {
        let group_info = alice_group
            .export_group_info(alice_provider.crypto(), &alice.signer, false)
            .unwrap()
            .into_verifiable_group_info()
            .unwrap();
        MlsGroup::external_commit_builder()
            .with_ratchet_tree(alice_group.export_ratchet_tree().into())
            .build_group(
                charlie_provider,
                group_info,
                charlie.credential_with_key.clone(),
            )
            .unwrap()
            .leaf_node_parameters(leaf_node_parameters)
            .load_psks(charlie_provider.storage())
            .unwrap()
            .build(
                charlie_provider.rand(),
                charlie_provider.crypto(),
                &charlie.signer,
                |_| true,
            )
    };

    let err = external_commit(
        LeafNodeParameters::builder()
            .with_capabilities(app_data_dictionary_capabilities(ciphersuite))
            .build(),
    )
    .expect_err("joined with a leaf node that does not advertise app_components");
    assert_eq!(
        err,
        CreateCommitError::ApplyOwnUpdatePath(ApplyOwnUpdatePathError::LeafNodeBuild(
            LeafNodeBuildError::Validation(LeafNodeValidationError::AppComponentsNotAdvertised)
        ))
    );

    external_commit(
        LeafNodeParameters::builder()
            .with_capabilities(app_data_dictionary_capabilities(ciphersuite))
            .with_extensions(app_components_leaf_extensions(vec![COUNTER_COMPONENT_ID]))
            .build(),
    )
    .expect("failed to join with a leaf node that advertises app_components");
}

#[openmls_test::openmls_test]
fn received_key_package_requires_app_components() {
    let provider = &Provider::default();
    let alice =
        generate_credential_with_key(b"alice".into(), ciphersuite.signature_algorithm(), provider);
    let key_package = KeyPackage::builder()
        .leaf_node_capabilities(app_data_dictionary_capabilities(ciphersuite))
        .leaf_node_extensions(app_components_leaf_extensions(vec![COUNTER_COMPONENT_ID]))
        .build(
            ciphersuite,
            provider,
            &alice.signer,
            alice.credential_with_key.clone(),
        )
        .unwrap()
        .key_package()
        .clone();

    KeyPackageIn::from(key_package.clone())
        .validate(provider.crypto(), ProtocolVersion::default())
        .expect("rejected a KeyPackage that advertises app_components");

    let mut franken_key_package = FrankenKeyPackage::from(key_package);
    franken_key_package
        .payload
        .leaf_node
        .payload
        .extensions
        .clear();
    franken_key_package.resign(&alice.signer);

    let err = KeyPackageIn::from(franken_key_package)
        .validate(provider.crypto(), ProtocolVersion::default())
        .expect_err("accepted a KeyPackage that does not advertise app_components");
    assert_eq!(
        err,
        KeyPackageVerifyError::LeafNodeValidation(
            LeafNodeValidationError::AppComponentsNotAdvertised
        )
    );
}

#[openmls_test::openmls_test]
fn received_add_requires_app_components() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let ProposalValidationTestSetup {
        mut alice_group,
        alice_credential_with_key_and_signer: alice,
        mut bob_group,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
    );
    let charlie = generate_credential_with_key(
        b"charlie".into(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );
    let charlie_key_package = KeyPackage::builder()
        .leaf_node_capabilities(app_data_dictionary_capabilities(ciphersuite))
        .leaf_node_extensions(app_components_leaf_extensions(vec![COUNTER_COMPONENT_ID]))
        .build(
            ciphersuite,
            charlie_provider,
            &charlie.signer,
            charlie.credential_with_key.clone(),
        )
        .unwrap()
        .key_package()
        .clone();

    // Alice's own validation would refuse to commit an invalid Add, so the
    // Add is inserted into an otherwise valid commit after the fact.
    let mut franken_key_package = FrankenKeyPackage::from(charlie_key_package.clone());
    franken_key_package
        .payload
        .leaf_node
        .payload
        .extensions
        .clear();
    franken_key_package.resign(&charlie.signer);
    let invalid_add = Proposal::add(AddProposal {
        key_package: KeyPackage::from(franken_key_package),
    });

    let serialized_commit = alice_group
        .self_update(alice_provider, &alice.signer, LeafNodeParameters::default())
        .unwrap()
        .into_contents()
        .tls_serialize_detached()
        .unwrap();
    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_commit.as_slice())
        .unwrap()
        .into_plaintext()
        .unwrap();
    let tampered_commit = insert_proposal_and_resign(
        alice_provider,
        ciphersuite,
        vec![ProposalOrRef::proposal(invalid_add)],
        plaintext.clone(),
        &plaintext,
        &alice_group,
        &alice.signer,
    );

    let err = bob_group
        .process_message(bob_provider, ProtocolMessage::from(tampered_commit))
        .expect_err("accepted an Add whose leaf does not advertise app_components");
    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::KeyPackageVerifyError(
            KeyPackageVerifyError::LeafNodeValidation(
                LeafNodeValidationError::AppComponentsNotAdvertised
            )
        ))
    ));

    alice_group
        .clear_pending_commit(alice_provider.storage())
        .unwrap();
    let (commit, _, _) = alice_group
        .add_members(alice_provider, &alice.signer, &[charlie_key_package])
        .expect("failed to add a member that advertises app_components");
    let commit = MlsMessageIn::from(commit)
        .try_into_protocol_message()
        .unwrap();
    bob_group
        .process_message(bob_provider, commit)
        .expect("rejected an Add whose leaf advertises app_components");
}

#[openmls_test::openmls_test]
fn received_update_proposal_requires_app_components() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ProposalValidationTestSetup {
        mut alice_group,
        alice_credential_with_key_and_signer: alice,
        mut bob_group,
        bob_credential_with_key_and_signer: bob,
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
    );

    let (proposal, _) = bob_group
        .propose_self_update(bob_provider, &bob.signer, LeafNodeParameters::default())
        .unwrap();

    // Bob's own validation would refuse to propose an invalid leaf node, so
    // the capabilities are changed after the fact.
    let FrankenMlsMessage {
        body: FrankenMlsMessageBody::PublicMessage(public_message),
        ..
    } = FrankenMlsMessage::from(proposal)
    else {
        panic!("expected a public message");
    };
    let mut content = public_message.content;
    let FrankenFramedContentBody::Proposal(FrankenProposal::Update(ref mut update)) = content.body
    else {
        panic!("expected an update proposal");
    };
    update
        .leaf_node
        .payload
        .capabilities
        .extensions
        .push(APP_DATA_DICTIONARY);
    update
        .leaf_node
        .resign(Some(bob_group.own_tree_position().into()), &bob.signer);

    let group_context = bob_group.export_group_context().clone();
    let tampered_proposal = FrankenPublicMessage::auth(
        bob_provider,
        ciphersuite,
        &bob.signer,
        content,
        Some(&group_context.into()),
        Some(bob_group.message_secrets().membership_key().as_slice()),
        None,
    );

    let ProcessedMessageContent::ProposalMessage(proposal) = alice_group
        .process_message(
            alice_provider,
            ProtocolMessage::from(PublicMessage::from(tampered_proposal)),
        )
        .unwrap()
        .into_content()
    else {
        panic!("expected a proposal");
    };
    alice_group
        .store_pending_proposal(alice_provider.storage(), *proposal)
        .unwrap();

    let err = alice_group
        .commit_to_pending_proposals(alice_provider, &alice.signer)
        .expect_err("committed an Update whose leaf does not advertise app_components");
    assert!(matches!(
        err,
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::ProposalValidationError(
                ProposalValidationError::InsufficientCapabilities
            )
        )
    ));
}

#[openmls_test::openmls_test]
fn received_commit_path_requires_app_components() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let ProposalValidationTestSetup {
        mut alice_group,
        alice_credential_with_key_and_signer: alice,
        mut bob_group,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
    );

    let commit = alice_group
        .self_update(alice_provider, &alice.signer, LeafNodeParameters::default())
        .unwrap()
        .into_commit();

    // Alice's own validation would refuse to commit an invalid leaf node, so
    // the capabilities are changed after the fact.
    let FrankenMlsMessage {
        body: FrankenMlsMessageBody::PublicMessage(public_message),
        ..
    } = FrankenMlsMessage::from(commit)
    else {
        panic!("expected a public message");
    };
    let mut content = public_message.content;
    let FrankenFramedContentBody::Commit(FrankenCommit {
        path: Some(ref mut path),
        ..
    }) = content.body
    else {
        panic!("expected a commit with a path");
    };
    path.leaf_node
        .payload
        .capabilities
        .extensions
        .push(APP_DATA_DICTIONARY);
    path.leaf_node
        .resign(Some(alice_group.own_tree_position().into()), &alice.signer);

    let group_context = alice_group.export_group_context().clone();
    let tampered_commit = FrankenPublicMessage::auth(
        alice_provider,
        ciphersuite,
        &alice.signer,
        content,
        Some(&group_context.into()),
        Some(alice_group.message_secrets().membership_key().as_slice()),
        // A dummy confirmation tag. The leaf node is validated before it.
        Some(vec![0u8; ciphersuite.hash_length()].into()),
    );

    let err = bob_group
        .process_message(
            bob_provider,
            ProtocolMessage::from(PublicMessage::from(tampered_commit)),
        )
        .expect_err("accepted a commit path leaf that does not advertise app_components");
    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::LeafNodeValidation(
            LeafNodeValidationError::AppComponentsNotAdvertised
        ))
    ));
}
