//! This module contains all tests regarding the validation of incoming external
//! commit messages as defined in
//! https://github.com/openmls/openmls/wiki/Message-validation

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::Ciphersuite, OpenMlsCryptoProvider};
use tls_codec::{Deserialize, Serialize};

use rstest::*;
use rstest_reuse::{self, *};

use crate::{
    ciphersuite::{hash_ref::ProposalRef, signable::Verifiable},
    credentials::*,
    framing::*,
    group::{config::CryptoConfig, errors::*, tests::utils::resign_external_commit, *},
    messages::proposals::*,
};

use super::utils::{generate_credential_bundle, generate_key_package};

// Test setup values
struct ECValidationTestSetup {
    alice_group: MlsGroup,
    bob_credential_bundle: CredentialBundle,
    plaintext: PublicMessage,
    original_plaintext: PublicMessage,
}

// Validation test setup
fn validation_test_setup(
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> ECValidationTestSetup {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let bob_credential = generate_credential_bundle(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration

    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    // === Alice creates a group ===
    let alice_group = MlsGroup::new_with_group_id(
        backend,
        &mls_group_config,
        group_id,
        alice_credential.signature_key(),
    )
    .expect("An unexpected error occurred.");

    let bob_credential_bundle = backend
        .key_store()
        .read(
            &bob_credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
        )
        .expect("An unexpected error occurred.");

    // Bob wants to commit externally.

    // Have Alice export everything that bob needs.
    let verifiable_group_info = alice_group
        .export_group_info(backend, false)
        .unwrap()
        .into_group_info()
        .unwrap();
    let tree_option = alice_group.export_ratchet_tree();

    let (_bob_group, message) = MlsGroup::join_by_external_commit(
        backend,
        Some(&tree_option),
        verifiable_group_info,
        alice_group.configuration(),
        &[],
        &bob_credential_bundle,
    )
    .expect("Error initializing group externally.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let message = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    assert!(matches!(message.sender(), Sender::NewMemberCommit));

    let original_plaintext = message.clone();

    ECValidationTestSetup {
        alice_group,
        bob_credential_bundle,
        plaintext: message,
        original_plaintext,
    }
}

// ValSem240: External Commit, inline Proposals: There MUST be at least one ExternalInit proposal.
#[apply(ciphersuites_and_backends)]
fn test_valsem240(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        mut plaintext,
        original_plaintext,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let mut content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // Remove the external init proposal in the commit.
    let proposal_position = content
        .proposals
        .iter()
        .position(|proposal| match proposal {
            ProposalOrRef::Proposal(proposal) => proposal.is_type(ProposalType::ExternalInit),
            ProposalOrRef::Reference(_) => false,
        })
        .expect("Couldn't find external init proposal.");

    content.proposals.remove(proposal_position);

    plaintext.set_content(FramedContentBody::Commit(content));

    let signed_plaintext = resign_external_commit(
        &bob_credential_bundle,
        plaintext,
        &original_plaintext,
        alice_group
            .export_group_context()
            .tls_serialize_detached()
            .expect("error serializing context"),
        backend,
    );

    // Have alice process the commit resulting from external init.
    let message_in = ProtocolMessage::from(signed_plaintext);

    let err = alice_group
        .process_message(backend, message_in)
        .expect_err("Could process message despite missing external init proposal.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::NoExternalInitProposals
        ))
    );

    // Positive case
    alice_group
        .process_message(backend, ProtocolMessage::from(original_plaintext))
        .expect("Unexpected error.");
}

// ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
#[apply(ciphersuites_and_backends)]
fn test_valsem241(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        mut plaintext,
        original_plaintext,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let mut content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // Insert a second external init proposal into the commit.
    let second_ext_init_prop =
        ProposalOrRef::Proposal(Proposal::ExternalInit(ExternalInitProposal::from(vec![
            1, 2, 3,
        ])));

    content.proposals.push(second_ext_init_prop);

    plaintext.set_content(FramedContentBody::Commit(content));

    // We have to re-sign, since we changed the content.
    let signed_plaintext = resign_external_commit(
        &bob_credential_bundle,
        plaintext,
        &original_plaintext,
        alice_group
            .export_group_context()
            .tls_serialize_detached()
            .expect("error serializing context"),
        backend,
    );
    // Have alice process the commit resulting from external init.
    let message_in = ProtocolMessage::from(signed_plaintext);

    let err = alice_group
        .process_message(backend, message_in)
        .expect_err("Could process message despite second ext. init proposal in commit.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::MultipleExternalInitProposals
        ))
    );

    // Positive case
    alice_group
        .process_message(backend, ProtocolMessage::from(original_plaintext))
        .expect("Unexpected error.");
}

// ValSem242: External Commit must only cover inline proposal in allowlist (ExternalInit, Remove, PreSharedKey)
#[apply(ciphersuites_and_backends)]
fn test_valsem242(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Alice has to add Bob first, so that in the external commit, we can have
    // an Update proposal that comes from a leaf that's actually inside of the
    // tree. If that is not the case, we'll get a general proposal validation
    // error before we get the external commit specific one.
    let bob_key_package = generate_key_package(
        &[ciphersuite],
        bob_credential_bundle.credential(),
        Extensions::empty(),
        backend,
    )
    .unwrap();

    let (_message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit().unwrap();

    let add_proposal = || {
        let charlie_credential = generate_credential_bundle(
            "Charlie".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .unwrap();
        let charlie_key_package = generate_key_package(
            &[ciphersuite],
            &charlie_credential,
            Extensions::empty(),
            backend,
        )
        .unwrap();

        ProposalOrRef::Proposal(Proposal::Add(AddProposal {
            key_package: charlie_key_package,
        }))
    };

    let update_proposal = || {
        let bob_key_package = generate_key_package(
            &[ciphersuite],
            bob_credential_bundle.credential(),
            Extensions::empty(),
            backend,
        )
        .unwrap();
        ProposalOrRef::Proposal(Proposal::Update(UpdateProposal {
            leaf_node: bob_key_package.leaf_node().clone(),
        }))
    };

    let reinit_proposal = || {
        ProposalOrRef::Proposal(Proposal::ReInit(ReInitProposal {
            group_id: alice_group.group_id().clone(),
            version: Default::default(),
            ciphersuite,
            extensions: alice_group.group().group_context_extensions().clone(),
        }))
    };

    let gce_proposal = || {
        ProposalOrRef::Proposal(Proposal::GroupContextExtensions(
            GroupContextExtensionProposal::new(
                alice_group.group().group_context_extensions().clone(),
            ),
        ))
    };

    let deny_list = vec![
        update_proposal(),
        add_proposal(),
        reinit_proposal(),
        gce_proposal(),
    ];
    for proposal in deny_list {
        let verifiable_group_info = alice_group
            .export_group_info(backend, true)
            .unwrap()
            .into_group_info()
            .unwrap();

        let (_bob_group, message) = MlsGroup::join_by_external_commit(
            backend,
            None,
            verifiable_group_info,
            alice_group.configuration(),
            &[],
            &bob_credential_bundle,
        )
        .unwrap();

        let serialized_message = message.tls_serialize_detached().unwrap();
        let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
            .expect("Could not deserialize message.")
            .into_plaintext()
            .expect("Message was not a plaintext.");

        assert!(matches!(plaintext.sender(), Sender::NewMemberCommit));
        assert!(matches!(plaintext.content_type(), ContentType::Commit));

        let original_plaintext = plaintext.clone();

        let mut commit = if let FramedContentBody::Commit(commit) = plaintext.content() {
            commit.clone()
        } else {
            panic!("Unexpected content type.");
        };
        commit.proposals.push(proposal);
        plaintext.set_content(FramedContentBody::Commit(commit.clone()));

        // We have to re-sign, since we changed the content.
        let signed_plaintext = resign_external_commit(
            &bob_credential_bundle,
            plaintext,
            &original_plaintext,
            alice_group
                .export_group_context()
                .tls_serialize_detached()
                .expect("error serializing context"),
            backend,
        );

        let processed_msg = alice_group.process_message(backend, signed_plaintext);

        assert_eq!(
            processed_msg.unwrap_err(),
            ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
                ExternalCommitValidationError::InvalidInlineProposals
            ))
        );

        // Positive case
        alice_group
            .process_message(backend, original_plaintext)
            .unwrap();
    }
}

// ValSem243: External Commit, inline Remove Proposal: The identity and the endpoint_id of the removed leaf are identical to the ones in the path KeyPackage.
#[apply(ciphersuites_and_backends)]
fn test_valsem243(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        plaintext: _,
        original_plaintext: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Alice has to add Bob first, so that Bob actually creates a remove
    // proposal to remove his former self.

    let bob_key_package = generate_key_package(
        &[ciphersuite],
        bob_credential_bundle.credential(),
        Extensions::empty(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let (_message, _welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("Could not add member.");

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    // Bob wants to commit externally.

    // Have Alice export everything that bob needs.
    let verifiable_group_info = alice_group
        .export_group_info(backend, false)
        .unwrap()
        .into_group_info()
        .unwrap();
    let tree_option = alice_group.export_ratchet_tree();

    let (_bob_group, message) = MlsGroup::join_by_external_commit(
        backend,
        Some(&tree_option),
        verifiable_group_info.clone(),
        alice_group.configuration(),
        &[],
        &bob_credential_bundle,
    )
    .expect("Error initializing group externally.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    let original_plaintext = plaintext.clone();

    let mut content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // Replace the remove proposal with one targeting alice instead of Bob's old self.
    let proposal_position = content
        .proposals
        .iter()
        .position(|proposal| match proposal {
            ProposalOrRef::Proposal(proposal) => proposal.is_type(ProposalType::Remove),
            ProposalOrRef::Reference(_) => false,
        })
        .expect("Couldn't find remove proposal.");

    content.proposals.remove(proposal_position);

    let remove_proposal = ProposalOrRef::Proposal(Proposal::Remove(RemoveProposal {
        removed: alice_group.own_leaf_index(),
    }));

    content.proposals.push(remove_proposal);

    plaintext.set_content(FramedContentBody::Commit(content));

    // We have to re-sign, since we changed the content.
    let signed_plaintext = resign_external_commit(
        &bob_credential_bundle,
        plaintext,
        &original_plaintext,
        alice_group
            .export_group_context()
            .tls_serialize_detached()
            .expect("error serializing context"),
        backend,
    );

    // Have alice process the commit resulting from external init.
    let message_in = ProtocolMessage::from(signed_plaintext);

    let err = alice_group.process_message(backend, message_in).expect_err(
        "Could process message despite the remove proposal targeting the wrong group member.",
    );

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::InvalidRemoveProposal
        ))
    );

    // Alice, as the creator of the group, should also be able to rejoin the group
    let alice_credential = alice_group
        .credential()
        .expect("An unexpected error occurred.");
    let alice_credential_bundle = backend
        .key_store()
        .read(
            &alice_credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
        )
        .expect("An unexpected error occurred.");
    let alice_external_commit = MlsGroup::join_by_external_commit(
        backend,
        Some(&tree_option),
        verifiable_group_info,
        alice_group.configuration(),
        &[],
        &alice_credential_bundle,
    );
    assert!(alice_external_commit.is_ok());

    // Positive case
    alice_group
        .process_message(backend, ProtocolMessage::from(original_plaintext))
        .expect("Unexpected error.");
}

// ValSem244: External Commit must not include any proposals by reference
#[apply(ciphersuites_and_backends)]
fn test_valsem244(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        mut plaintext,
        original_plaintext,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let mut content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // Add an Add proposal by reference
    let bob_key_package = generate_key_package(
        &[ciphersuite],
        bob_credential_bundle.credential(),
        Extensions::empty(),
        backend,
    )
    .unwrap();

    let add_proposal = Proposal::Add(AddProposal {
        key_package: bob_key_package,
    });

    let proposal_ref = ProposalRef::from_proposal(ciphersuite, backend, &add_proposal).unwrap();

    // Add an Add proposal to the external commit.
    let add_proposal_ref = ProposalOrRef::Reference(proposal_ref);

    content.proposals.push(add_proposal_ref);

    plaintext.set_content(FramedContentBody::Commit(content));

    // We have to re-sign, since we changed the content.
    let signed_plaintext = resign_external_commit(
        &bob_credential_bundle,
        plaintext,
        &original_plaintext,
        alice_group
            .export_group_context()
            .tls_serialize_detached()
            .expect("error serializing context"),
        backend,
    );

    // Have alice process the commit resulting from external init.
    let message_in = ProtocolMessage::from(signed_plaintext);

    // Expect error because the message can't be processed due to the external
    // commit including an external init proposal by reference.
    let err = alice_group
        .process_message(backend, message_in)
        .unwrap_err();

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::ReferencedProposal
        ))
    );

    // Positive case
    alice_group
        .process_message(backend, ProtocolMessage::from(original_plaintext))
        .unwrap();
}

// ValSem245: External Commit: MUST contain a path.
#[apply(ciphersuites_and_backends)]
fn test_valsem245(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        mut plaintext,
        original_plaintext,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let mut content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // Remove the path from the commit
    content.path = None;

    plaintext.set_content(FramedContentBody::Commit(content));

    // We have to re-sign, since we changed the content.
    let signed_plaintext = resign_external_commit(
        &bob_credential_bundle,
        plaintext,
        &original_plaintext,
        alice_group
            .export_group_context()
            .tls_serialize_detached()
            .expect("error serializing context"),
        backend,
    );

    // Have alice process the commit resulting from external init.
    let message_in = ProtocolMessage::from(signed_plaintext);

    let err = alice_group
        .process_message(backend, message_in)
        .expect_err("Could process message despite missing path.");

    assert_eq!(
        err,
        ProcessMessageError::ValidationError(ValidationError::NoPath)
    );

    // Positive case
    alice_group
        .process_message(backend, ProtocolMessage::from(original_plaintext))
        .expect("Unexpected error.");
}

// ValSem246: External Commit: The signature of the PublicMessage MUST be verified with the credential of the KeyPackage in the included `path`.
#[apply(ciphersuites_and_backends)]
fn test_valsem246(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        mut plaintext,
        original_plaintext,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let mut content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // We test that the message is verified using the credential contained in
    // the path by generating a new credential for bob, putting it in the path
    // and then re-signing the message with his original credential.
    let bob_new_credential = generate_credential_bundle(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackage
    let bob_new_key_package = generate_key_package(
        &[ciphersuite],
        &bob_new_credential,
        Extensions::empty(),
        backend,
    )
    .expect("An unexpected error occurred.");

    if let Some(ref mut path) = content.path {
        path.set_leaf_node(bob_new_key_package.leaf_node().clone())
    }

    plaintext.set_content(FramedContentBody::Commit(content));

    // We have to re-sign, since we changed the content.
    let signed_plaintext = resign_external_commit(
        &bob_credential_bundle,
        plaintext,
        &original_plaintext,
        alice_group
            .export_group_context()
            .tls_serialize_detached()
            .expect("error serializing context"),
        backend,
    );

    // Have alice process the commit resulting from external init.
    let message_in = ProtocolMessage::from(signed_plaintext);

    let err = alice_group
        .process_message(backend, message_in)
        .expect_err("Could process message despite wrong signature.");

    // This shows that signature verification fails if the signature is not done
    // using the credential in the path.
    assert_eq!(err, ProcessMessageError::InvalidSignature);

    // This shows that the credential in the original path key package is actually bob's credential.
    let content = if let FramedContentBody::Commit(commit) = original_plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    let path_credential = content
        .path()
        .as_ref()
        .expect("no path in external commit")
        .leaf_node()
        .credential();
    assert_eq!(path_credential, bob_credential_bundle.credential());

    // This shows that the message is actually signed using this credential.
    let decrypted_message = DecryptedMessage::from_inbound_public_message(
        original_plaintext.clone(),
        alice_group.group().message_secrets(),
        backend,
    )
    .unwrap();
    let verification_result: Result<AuthenticatedContent, _> =
        decrypted_message.verifiable_content().clone().verify(
            backend,
            bob_credential_bundle.credential().signature_key(),
            bob_credential_bundle.credential().signature_scheme(),
        );
    assert!(verification_result.is_ok());

    // Positive case
    // This shows it again, since ValSem010 ensures that the signature is
    // correct (which it only is, if alice is using the credential in the path
    // key package).
    alice_group
        .process_message(backend, ProtocolMessage::from(original_plaintext))
        .expect("Unexpected error.");
}

// External Commit should work when group use ciphertext WireFormat
#[apply(ciphersuites_and_backends)]
fn test_pure_ciphertest(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with PrivateMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        plaintext: _,
        original_plaintext: _,
    } = validation_test_setup(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Bob wants to commit externally.

    // Have Alice export everything that bob needs.
    let verifiable_group_info = alice_group
        .export_group_info(backend, true)
        .unwrap()
        .into_group_info()
        .unwrap();

    let (_bob_group, message) = MlsGroup::join_by_external_commit(
        backend,
        None,
        verifiable_group_info,
        alice_group.configuration(),
        &[],
        &bob_credential_bundle,
    )
    .expect("Error initializing group externally.");

    let mls_message_in: MlsMessageIn = message.into();
    assert_eq!(mls_message_in.wire_format(), WireFormat::PublicMessage);

    // Would fail if handshake message processing did not distinguish external messages
    assert!(alice_group.process_message(backend, mls_message_in).is_ok());
}
