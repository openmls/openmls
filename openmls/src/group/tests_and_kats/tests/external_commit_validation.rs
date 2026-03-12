//! This module contains all tests regarding the validation of incoming external
//! commit messages as defined in
//! https://github.com/openmls/openmls/wiki/Message-validation

use tls_codec::{Deserialize, Serialize};

use self::utils::*;
use crate::{
    ciphersuite::{hash_ref::ProposalRef, signable::Verifiable},
    extensions::{Extension, UnknownExtension},
    framing::{
        mls_auth_content_in::AuthenticatedContentIn, ContentType, DecryptedMessage,
        FramedContentBody, MlsMessageIn, ProtocolMessage, Sender,
    },
    group::{
        errors::{
            ExternalCommitValidationError, ProcessMessageError, StageCommitError, ValidationError,
        },
        tests_and_kats::utils::{
            generate_credential_with_key, generate_key_package, resign_external_commit,
        },
        CreateCommitError, Extensions, MlsGroup, MlsGroupCreateConfig, OpenMlsSignaturePublicKey,
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    messages::proposals::{
        AddProposal, ExternalInitProposal, GroupContextExtensionProposal, Proposal, ProposalOrRef,
        ProposalType, ReInitProposal,
    },
    treesync::errors::LeafNodeValidationError,
};

// ValSem240: External Commit, inline Proposals: There MUST be at least one ExternalInit proposal.
#[openmls_test::openmls_test]
fn test_valsem240() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let ECValidationTestSetup {
        mut alice_group,
        bob_credential,
        public_message_commit,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
    );

    // Setup
    let public_message_commit_bad = {
        let commit_bad = {
            let mut commit =
                if let FramedContentBody::Commit(commit) = public_message_commit.content() {
                    commit.clone()
                } else {
                    panic!("Unexpected content type.");
                };

            // Remove the external init proposal in the commit.
            let proposal_position = commit
                .proposals
                .iter()
                .position(|proposal| match proposal {
                    ProposalOrRef::Proposal(proposal) => {
                        proposal.is_type(ProposalType::ExternalInit)
                    }
                    ProposalOrRef::Reference(_) => false,
                })
                .expect("Couldn't find external init proposal.");
            commit.proposals.remove(proposal_position);
            commit
        };

        let mut public_message_commit_bad = public_message_commit.clone();
        public_message_commit_bad.set_content(FramedContentBody::Commit(commit_bad));
        resign_external_commit(
            &bob_credential.signer,
            public_message_commit_bad,
            public_message_commit.confirmation_tag().unwrap().clone(),
            alice_group
                .export_group_context()
                .tls_serialize_detached()
                .unwrap(),
        )
    };

    // Have alice process the commit resulting from external init.
    // Negative case
    let err = alice_group
        .process_message(
            alice_provider,
            ProtocolMessage::from(public_message_commit_bad),
        )
        .expect_err("Could process message despite missing external init proposal.");

    println!("Got the error: {:?}", err);

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::NoExternalInitProposals
        ))
    ));

    // Positive case
    alice_group
        .process_message(alice_provider, ProtocolMessage::from(public_message_commit))
        .unwrap();
}

// ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
#[openmls_test::openmls_test]
fn test_valsem241() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        alice_credential: _,
        bob_credential,
        public_message_commit,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
    );

    // Setup
    let public_message_commit_bad = {
        let mut commit_bad =
            if let FramedContentBody::Commit(commit) = public_message_commit.content() {
                commit.clone()
            } else {
                panic!("Unexpected content type.");
            };

        // Insert a second external init proposal into the commit.
        let second_ext_init_prop =
            ProposalOrRef::proposal(Proposal::external_init(ExternalInitProposal::from(vec![
                1, 2, 3,
            ])));

        commit_bad.proposals.push(second_ext_init_prop);

        let mut public_message_commit_bad = public_message_commit.clone();

        public_message_commit_bad.set_content(FramedContentBody::Commit(commit_bad));

        // We have to re-sign, since we changed the content.
        resign_external_commit(
            &bob_credential.signer,
            public_message_commit_bad,
            public_message_commit.confirmation_tag().unwrap().clone(),
            alice_group
                .export_group_context()
                .tls_serialize_detached()
                .unwrap(),
        )
    };

    // Have alice process the commit resulting from external init.
    // Negative case
    let err = alice_group
        .process_message(
            alice_provider,
            ProtocolMessage::from(public_message_commit_bad),
        )
        .expect_err("Could process message despite second ext. init proposal in commit.");

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::MultipleExternalInitProposals
        ))
    ));

    // Positive case
    alice_group
        .process_message(alice_provider, ProtocolMessage::from(public_message_commit))
        .expect("Unexpected error.");
}

// ValSem242: External Commit must only cover inline proposal in allowlist (ExternalInit, Remove, PreSharedKey)
#[openmls_test::openmls_test]
fn test_valsem242() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        alice_credential,
        bob_credential,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
    );

    // Alice has to add Bob first, so that in the external commit, we can have
    // an Update proposal that comes from a leaf that's actually inside of the
    // tree. If that is not the case, we'll get a general proposal validation
    // error before we get the external commit specific one.
    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        alice_provider,
        bob_credential.clone(),
    );

    alice_group
        .add_members(
            alice_provider,
            &alice_credential.signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_credential.signer, true)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    let (_, public_message_commit) = MlsGroup::external_commit_builder()
        .with_config(alice_group.configuration().clone())
        .build_group(
            bob_provider,
            verifiable_group_info,
            bob_credential.credential_with_key.clone(),
        )
        .unwrap()
        .load_psks(bob_provider.storage())
        .unwrap()
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_credential.signer,
            |_| true,
        )
        .unwrap()
        .finalize(bob_provider)
        .unwrap();

    let public_message_commit = {
        let serialized = public_message_commit
            .into_commit()
            .tls_serialize_detached()
            .unwrap();
        MlsMessageIn::tls_deserialize(&mut serialized.as_slice())
            .unwrap()
            .into_plaintext()
            .unwrap()
    };

    assert!(matches!(
        public_message_commit.sender(),
        Sender::NewMemberCommit
    ));
    assert!(matches!(
        public_message_commit.content_type(),
        ContentType::Commit
    ));

    let deny_list = {
        let add_proposal = {
            let charlie_provider = &Provider::default();
            let charlie_credential = generate_credential_with_key(
                "Charlie".into(),
                ciphersuite.signature_algorithm(),
                charlie_provider,
            );
            let charlie_key_package = generate_key_package(
                ciphersuite,
                Extensions::empty(),
                charlie_provider,
                charlie_credential,
            );

            ProposalOrRef::proposal(Proposal::add(AddProposal {
                key_package: charlie_key_package.key_package().clone(),
            }))
        };

        let reinit_proposal = {
            ProposalOrRef::proposal(Proposal::re_init(ReInitProposal {
                group_id: alice_group.group_id().clone(),
                version: Default::default(),
                ciphersuite,
                extensions: alice_group.context().extensions().clone(),
            }))
        };

        let gce = alice_group.context().extensions().clone();

        let gce_proposal = {
            ProposalOrRef::proposal(Proposal::group_context_extensions(
                GroupContextExtensionProposal::new(gce),
            ))
        };

        vec![add_proposal, reinit_proposal, gce_proposal]
    };

    for proposal in deny_list {
        let public_message_commit_bad = {
            let commit_bad = {
                let mut commit =
                    if let FramedContentBody::Commit(commit) = public_message_commit.content() {
                        commit.clone()
                    } else {
                        panic!("Unexpected content type.");
                    };
                commit.proposals.push(proposal);
                commit
            };

            let mut public_message_commit_bad = public_message_commit.clone();

            public_message_commit_bad.set_content(FramedContentBody::Commit(commit_bad));

            // We have to re-sign, since we changed the content.
            resign_external_commit(
                &bob_credential.signer,
                public_message_commit_bad,
                public_message_commit.confirmation_tag().unwrap().clone(),
                alice_group
                    .export_group_context()
                    .tls_serialize_detached()
                    .unwrap(),
            )
        };

        // Negative case
        let err = alice_group
            .process_message(alice_provider, public_message_commit_bad)
            .unwrap_err();

        assert!(matches!(
            err,
            ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
                ExternalCommitValidationError::InvalidInlineProposals
            ))
        ));

        // Positive case
        alice_group
            .process_message(alice_provider, public_message_commit.clone())
            .unwrap();
    }
}

// ValSem244: External Commit must not include any proposals by reference
#[openmls_test::openmls_test]
fn test_valsem244() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential,
        public_message_commit,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
    );

    // Setup
    let public_message_commit_bad = {
        let mut commit_bad =
            if let FramedContentBody::Commit(commit) = public_message_commit.content() {
                commit.clone()
            } else {
                panic!("Unexpected content type.");
            };

        // Add an Add proposal by reference
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            bob_provider,
            bob_credential.clone(),
        );

        let add_proposal = Proposal::add(AddProposal {
            key_package: bob_key_package.key_package().clone(),
        });

        let proposal_ref =
            ProposalRef::from_raw_proposal(ciphersuite, bob_provider.crypto(), &add_proposal)
                .unwrap();

        // Add an Add proposal to the external commit.
        let add_proposal_ref = ProposalOrRef::reference(proposal_ref);

        commit_bad.proposals.push(add_proposal_ref);

        let mut public_message_commit_bad = public_message_commit.clone();

        public_message_commit_bad.set_content(FramedContentBody::Commit(commit_bad));

        // We have to re-sign, since we changed the content.
        resign_external_commit(
            &bob_credential.signer,
            public_message_commit_bad,
            public_message_commit.confirmation_tag().unwrap().clone(),
            alice_group
                .export_group_context()
                .tls_serialize_detached()
                .unwrap(),
        )
    };

    // Negative case
    // Have alice process the commit resulting from external init.
    // Expect error because the message can't be processed due to the external
    // commit including an external init proposal by reference.
    let err = alice_group
        .process_message(
            alice_provider,
            ProtocolMessage::from(public_message_commit_bad),
        )
        .unwrap_err();

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::ReferencedProposal
        ))
    ));

    // Positive case
    alice_group
        .process_message(alice_provider, ProtocolMessage::from(public_message_commit))
        .unwrap();
}

// ValSem245: External Commit: MUST contain a path.
#[openmls_test::openmls_test]
fn test_valsem245() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential,
        public_message_commit,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
    );

    // Setup
    let public_message_commit_bad = {
        let mut commit_bad =
            if let FramedContentBody::Commit(commit) = public_message_commit.content() {
                commit.clone()
            } else {
                panic!("Unexpected content type.");
            };

        // Remove the path from the commit
        commit_bad.path = None;

        let mut public_message_commit_bad = public_message_commit.clone();

        public_message_commit_bad.set_content(FramedContentBody::Commit(commit_bad));

        // We have to re-sign, since we changed the content.
        resign_external_commit(
            &bob_credential.signer,
            public_message_commit_bad,
            public_message_commit.confirmation_tag().unwrap().clone(),
            alice_group
                .export_group_context()
                .tls_serialize_detached()
                .unwrap(),
        )
    };

    // Have alice process the commit resulting from external init.
    // Negative case
    let err = alice_group
        .process_message(
            alice_provider,
            ProtocolMessage::from(public_message_commit_bad),
        )
        .expect_err("Could process message despite missing path.");

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::NoPath)
    ));

    // Positive case
    alice_group
        .process_message(alice_provider, ProtocolMessage::from(public_message_commit))
        .unwrap();
}

// ValSem246: External Commit: The signature of the PublicMessage MUST be verified with the credential of the KeyPackage in the included `path`.
#[openmls_test::openmls_test]
fn test_valsem246() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential,
        public_message_commit,
        ..
    } = validation_test_setup(
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
    );

    // Setup
    let public_message_commit_bad = {
        let mut commit_bad =
            if let FramedContentBody::Commit(commit) = public_message_commit.content() {
                commit.clone()
            } else {
                panic!("Unexpected content type.");
            };

        // We test that the message is verified using the credential contained in
        // the path by generating a new credential for bob, putting it in the path
        // and then re-signing the message with his original credential.
        let bob_new_credential = generate_credential_with_key(
            "Bob".into(),
            ciphersuite.signature_algorithm(),
            bob_provider,
        );

        // Generate KeyPackage
        let bob_new_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            bob_provider,
            bob_new_credential,
        );

        if let Some(ref mut path) = commit_bad.path {
            path.set_leaf_node(bob_new_key_package.key_package().leaf_node().clone())
        }

        let mut public_message_commit_bad = public_message_commit.clone();

        public_message_commit_bad.set_content(FramedContentBody::Commit(commit_bad));

        // We have to re-sign (with the original credential), since we changed the content.
        resign_external_commit(
            &bob_credential.signer,
            public_message_commit_bad,
            public_message_commit.confirmation_tag().unwrap().clone(),
            alice_group
                .export_group_context()
                .tls_serialize_detached()
                .unwrap(),
        )
    };

    // Have alice process the commit resulting from external init.
    // Negative case
    let err = alice_group
        .process_message(
            alice_provider,
            ProtocolMessage::from(public_message_commit_bad),
        )
        .expect_err("Could process message despite wrong signature.");

    // This shows that signature verification fails if the signature is not done
    // using the credential in the path.
    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::InvalidSignature)
    ));

    // This shows that the credential in the original path key package is actually bob's credential.
    let commit = if let FramedContentBody::Commit(commit) = public_message_commit.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    let path_credential = commit
        .path()
        .as_ref()
        .expect("no path in external commit")
        .leaf_node()
        .credential();
    assert_eq!(
        path_credential,
        &bob_credential.credential_with_key.credential
    );

    // This shows that the message is actually signed using this credential.
    let decrypted_message = DecryptedMessage::from_inbound_public_message(
        public_message_commit.clone().into(),
        alice_group.message_secrets(),
        alice_group.message_secrets().serialized_context().to_vec(),
        alice_provider.crypto(),
        ciphersuite,
    )
    .unwrap();
    let verification_result: Result<AuthenticatedContentIn, _> =
        decrypted_message.verifiable_content().clone().verify(
            alice_provider.crypto(),
            &OpenMlsSignaturePublicKey::from_signature_key(
                bob_credential.credential_with_key.signature_key,
                ciphersuite.signature_algorithm(),
            ),
        );
    assert!(verification_result.is_ok());

    // Positive case
    // This shows it again, since ValSem010 ensures that the signature is
    // correct (which it only is, if alice is using the credential in the path).
    alice_group
        .process_message(alice_provider, ProtocolMessage::from(public_message_commit))
        .expect("Unexpected error.");
}

// External Commit should work when group use ciphertext WireFormat
#[openmls_test::openmls_test]
fn test_pure_ciphertext() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Test with PrivateMessage

    // The setup function already test whether the external commit is a
    // plaintext message.
    let ECValidationTestSetup {
        mut alice_group,
        public_message_commit,
        ..
    } = validation_test_setup(
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        ciphersuite,
        alice_provider,
        bob_provider,
    );

    // Would fail if handshake message processing did not distinguish external messages
    assert!(alice_group
        .process_message(alice_provider, public_message_commit)
        .is_ok());
}

// External Commit: The capabilities of the leaf node in the path MUST
// support all group context extensions.
// https://validation.openmls.tech/#valn0502
#[openmls_test::openmls_test]
fn test_external_commit_unsupported_group_context_extension() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Generate credentials
    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let bob_credential = generate_credential_with_key(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    // Create group context extensions with a custom extension
    let gc_extensions =
        Extensions::single(Extension::Unknown(0x4141, UnknownExtension(vec![0x01])))
            .expect("unknown extensions should be considered valid in group context");

    // Alice creates a group with the custom group context extension
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .with_group_context_extensions(gc_extensions)
        .build();

    let alice_group = MlsGroup::new(
        alice_provider,
        &alice_credential.signer,
        &mls_group_create_config,
        alice_credential.credential_with_key.clone(),
    )
    .unwrap();

    // Export group info for Bob
    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_credential.signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let tree_option = alice_group.export_ratchet_tree();

    // Bob attempts to join via external commit
    // Bob's key package does NOT explicitly support extension 0x4141,
    // therefore it fails
    let err = MlsGroup::external_commit_builder()
        .with_config(alice_group.configuration().clone())
        .with_ratchet_tree(tree_option.into())
        .build_group(
            bob_provider,
            verifiable_group_info,
            bob_credential.credential_with_key.clone(),
        )
        .unwrap()
        .load_psks(bob_provider.storage())
        .unwrap()
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_credential.signer,
            |_| true,
        )
        .expect_err("bob can't join because he doesn't have capabilities for an extension in the group context");

    // Verify error type
    assert!(matches!(
        err,
        CreateCommitError::LeafNodeValidation(LeafNodeValidationError::UnsupportedExtensions)
    ));
}

mod utils {
    use openmls_traits::types::Ciphersuite;

    use crate::{
        framing::{MlsMessageIn, PublicMessage, Sender, WireFormat},
        group::{
            tests_and_kats::utils::{generate_credential_with_key, CredentialWithKeyAndSigner},
            MlsGroup, MlsGroupCreateConfig, WireFormatPolicy,
        },
    };

    // Test setup values
    pub(super) struct ECValidationTestSetup {
        pub alice_group: MlsGroup,
        // We only allow [`CredentialWithKeyAndSigner`] here for new.
        pub alice_credential: CredentialWithKeyAndSigner,
        pub bob_credential: CredentialWithKeyAndSigner,
        pub public_message_commit: PublicMessage,
    }

    // Validation test setup
    pub(super) fn validation_test_setup(
        wire_format_policy: WireFormatPolicy,
        ciphersuite: Ciphersuite,
        alice_provider: &impl crate::storage::OpenMlsProvider,
        bob_provider: &impl crate::storage::OpenMlsProvider,
    ) -> ECValidationTestSetup {
        // Generate credentials with keys
        let alice_credential = generate_credential_with_key(
            "Alice".into(),
            ciphersuite.signature_algorithm(),
            alice_provider,
        );

        let bob_credential = generate_credential_with_key(
            "Bob".into(),
            ciphersuite.signature_algorithm(),
            bob_provider,
        );

        // Define the MlsGroup configuration
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .wire_format_policy(wire_format_policy)
            .ciphersuite(ciphersuite)
            .build();

        // Alice creates a group
        let alice_group = MlsGroup::new(
            alice_provider,
            &alice_credential.signer,
            &mls_group_create_config,
            alice_credential.credential_with_key.clone(),
        )
        .unwrap();

        // Bob wants to commit externally.

        // Have Alice export everything that bob needs.
        let verifiable_group_info = alice_group
            .export_group_info(alice_provider.crypto(), &alice_credential.signer, false)
            .unwrap()
            .into_verifiable_group_info()
            .unwrap();
        let tree_option = alice_group.export_ratchet_tree();

        let (_bob_group, commit_bundle) = MlsGroup::external_commit_builder()
            .with_config(alice_group.configuration().clone())
            .with_ratchet_tree(tree_option.into())
            .build_group(
                bob_provider,
                verifiable_group_info,
                bob_credential.credential_with_key.clone(),
            )
            .unwrap()
            .load_psks(bob_provider.storage())
            .unwrap()
            .build(
                bob_provider.rand(),
                bob_provider.crypto(),
                &bob_credential.signer,
                |_| true,
            )
            .unwrap()
            .finalize(bob_provider)
            .unwrap();

        let mls_message = MlsMessageIn::from(commit_bundle.into_commit());
        assert_eq!(mls_message.wire_format(), WireFormat::PublicMessage);
        let public_message_commit = mls_message
            .into_plaintext()
            .expect("External commit should be plaintext");

        assert!(matches!(
            public_message_commit.sender(),
            Sender::NewMemberCommit
        ));

        ECValidationTestSetup {
            alice_group,
            alice_credential,
            bob_credential,
            public_message_commit,
        }
    }
}
