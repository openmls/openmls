//! This module contains all tests regarding the validation of incoming external
//! commit messages as defined in
//! https://github.com/openmls/openmls/wiki/Message-validation

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use rstest::rstest;
use rstest_reuse::apply;
use tls_codec::{Deserialize, Serialize};

use self::utils::*;
use crate::{
    ciphersuite::{hash_ref::ProposalRef, signable::Verifiable},
    framing::{
        mls_auth_content_in::AuthenticatedContentIn, ContentType, DecryptedMessage,
        FramedContentBody, MlsMessageIn, ProtocolMessage, Sender, WireFormat,
    },
    group::{
        errors::{
            ExternalCommitValidationError, ProcessMessageError, StageCommitError, ValidationError,
        },
        tests::utils::{
            generate_credential_with_key, generate_key_package, resign_external_commit,
        },
        Extensions, MlsGroup, OpenMlsSignaturePublicKey, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    messages::proposals::{
        AddProposal, ExternalInitProposal, GroupContextExtensionProposal, Proposal, ProposalOrRef,
        ProposalType, ReInitProposal, RemoveProposal,
    },
};

// ValSem240: External Commit, inline Proposals: There MUST be at least one ExternalInit proposal.
#[apply(ciphersuites_and_providers)]
fn test_valsem240(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential,
        public_message_commit,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

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
        .process_message(provider, ProtocolMessage::from(public_message_commit_bad))
        .expect_err("Could process message despite missing external init proposal.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::NoExternalInitProposals
        ))
    );

    // Positive case
    alice_group
        .process_message(provider, ProtocolMessage::from(public_message_commit))
        .unwrap();
}

// ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
#[apply(ciphersuites_and_providers)]
fn test_valsem241(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        alice_credential: _,
        bob_credential,
        public_message_commit,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

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
            ProposalOrRef::Proposal(Proposal::ExternalInit(ExternalInitProposal::from(vec![
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
        .process_message(provider, ProtocolMessage::from(public_message_commit_bad))
        .expect_err("Could process message despite second ext. init proposal in commit.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::MultipleExternalInitProposals
        ))
    );

    // Positive case
    alice_group
        .process_message(provider, ProtocolMessage::from(public_message_commit))
        .expect("Unexpected error.");
}

// ValSem242: External Commit must only cover inline proposal in allowlist (ExternalInit, Remove, PreSharedKey)
#[apply(ciphersuites_and_providers)]
fn test_valsem242(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        alice_credential,
        bob_credential,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // Alice has to add Bob first, so that in the external commit, we can have
    // an Update proposal that comes from a leaf that's actually inside of the
    // tree. If that is not the case, we'll get a general proposal validation
    // error before we get the external commit specific one.
    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        provider,
        bob_credential.clone(),
    );

    alice_group
        .add_members(provider, &alice_credential.signer, &[bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit(provider).unwrap();

    let verifiable_group_info = alice_group
        .export_group_info(provider.crypto(), &alice_credential.signer, true)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    let (_, public_message_commit, _) = MlsGroup::join_by_external_commit(
        provider,
        &bob_credential.signer,
        None,
        verifiable_group_info,
        alice_group.configuration(),
        &[],
        bob_credential.credential_with_key.clone(),
    )
    .unwrap();

    let public_message_commit = {
        let serialized = public_message_commit.tls_serialize_detached().unwrap();
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
            let charlie_credential = generate_credential_with_key(
                "Charlie".into(),
                ciphersuite.signature_algorithm(),
                provider,
            );
            let charlie_key_package = generate_key_package(
                ciphersuite,
                Extensions::empty(),
                provider,
                charlie_credential,
            );

            ProposalOrRef::Proposal(Proposal::Add(AddProposal {
                key_package: charlie_key_package,
            }))
        };

        let reinit_proposal = {
            ProposalOrRef::Proposal(Proposal::ReInit(ReInitProposal {
                group_id: alice_group.group_id().clone(),
                version: Default::default(),
                ciphersuite,
                extensions: alice_group.group().group_context_extensions().clone(),
            }))
        };

        let gce_proposal = {
            ProposalOrRef::Proposal(Proposal::GroupContextExtensions(
                GroupContextExtensionProposal::new(
                    alice_group.group().group_context_extensions().clone(),
                ),
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
            .process_message(provider, public_message_commit_bad)
            .unwrap_err();

        assert_eq!(
            err,
            ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
                ExternalCommitValidationError::InvalidInlineProposals
            ))
        );

        // Positive case
        alice_group
            .process_message(provider, public_message_commit.clone())
            .unwrap();
    }
}

// ValSem243: External Commit, inline Remove Proposal: The identity of the
// removed leaf are identical to the ones in the path KeyPackage.
#[apply(ciphersuites_and_providers)]
fn test_valsem243(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let ECValidationTestSetup {
        mut alice_group,
        alice_credential,
        bob_credential,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // Alice has to add Bob first, so that Bob actually creates a remove
    // proposal to remove his former self.

    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        provider,
        bob_credential.clone(),
    );

    alice_group
        .add_members(provider, &alice_credential.signer, &[bob_key_package])
        .unwrap();

    alice_group.merge_pending_commit(provider).unwrap();

    // Bob wants to commit externally.

    // Have Alice export everything that bob needs.
    let verifiable_group_info = alice_group
        .export_group_info(provider.crypto(), &alice_credential.signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let ratchet_tree = alice_group.export_ratchet_tree();

    // Note: This will create a remove proposal because Bob is already a member of the group.
    let (_, public_message_commit, _) = MlsGroup::join_by_external_commit(
        provider,
        &bob_credential.signer,
        Some(ratchet_tree.clone().into()),
        verifiable_group_info.clone(),
        alice_group.configuration(),
        &[],
        bob_credential.credential_with_key,
    )
    .unwrap();

    // MlsMessageOut -> MlsMessageIn
    let serialized_message = public_message_commit.tls_serialize_detached().unwrap();
    let public_message_commit = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .unwrap()
        .into_plaintext()
        .unwrap();

    let public_message_commit_bad = {
        let commit_bad = {
            let mut commit =
                if let FramedContentBody::Commit(commit) = public_message_commit.content() {
                    commit.clone()
                } else {
                    panic!("Unexpected content type.");
                };

            // Replace the remove proposal with one targeting alice instead of Bob's old self.
            let proposal_position = commit
                .proposals
                .iter()
                .position(|proposal| match proposal {
                    ProposalOrRef::Proposal(proposal) => proposal.is_type(ProposalType::Remove),
                    ProposalOrRef::Reference(_) => false,
                })
                .expect("Couldn't find remove proposal.");

            commit.proposals.remove(proposal_position);

            let remove_proposal = ProposalOrRef::Proposal(Proposal::Remove(RemoveProposal {
                removed: alice_group.own_leaf_index(),
            }));

            commit.proposals.push(remove_proposal);

            // Resign the leaf node in the update path of the commit with
            // Alice's leaf index. If we don't do this, we will fail on an
            // invalid signature instead of an invalid remove proposal.
            let mut leaf_node = commit.path.as_ref().unwrap().leaf_node().clone();

            leaf_node.resign_with_position(
                alice_group.own_leaf_index(),
                alice_group.group_id().clone(),
                &bob_credential.signer,
            );

            if let Some(path) = commit.path.as_mut() {
                path.set_leaf_node(leaf_node)
            }

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

    // Have alice process the commit resulting from external init.
    // Negative case
    let err = alice_group
        .process_message(provider, ProtocolMessage::from(public_message_commit_bad))
        .expect_err(
            "Could process message despite the remove proposal targeting the wrong group member.",
        );

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::InvalidRemoveProposal
        ))
    );

    // Alice, as the creator of the group, should also be able to rejoin the group
    let alice_new_group = MlsGroup::join_by_external_commit(
        provider,
        &alice_credential.signer,
        Some(ratchet_tree.into()),
        verifiable_group_info,
        alice_group.configuration(),
        &[],
        alice_credential.credential_with_key,
    );
    assert!(alice_new_group.is_ok());

    // Positive case
    alice_group
        .process_message(provider, ProtocolMessage::from(public_message_commit))
        .expect("Unexpected error.");
}

// ValSem244: External Commit must not include any proposals by reference
#[apply(ciphersuites_and_providers)]
fn test_valsem244(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential,
        public_message_commit,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

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
            provider,
            bob_credential.clone(),
        );

        let add_proposal = Proposal::Add(AddProposal {
            key_package: bob_key_package,
        });

        let proposal_ref =
            ProposalRef::from_raw_proposal(ciphersuite, provider.crypto(), &add_proposal).unwrap();

        // Add an Add proposal to the external commit.
        let add_proposal_ref = ProposalOrRef::Reference(proposal_ref);

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
        .process_message(provider, ProtocolMessage::from(public_message_commit_bad))
        .unwrap_err();

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::ReferencedProposal
        ))
    );

    // Positive case
    alice_group
        .process_message(provider, ProtocolMessage::from(public_message_commit))
        .unwrap();
}

// ValSem245: External Commit: MUST contain a path.
#[apply(ciphersuites_and_providers)]
fn test_valsem245(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential,
        public_message_commit,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

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
        .process_message(provider, ProtocolMessage::from(public_message_commit_bad))
        .expect_err("Could process message despite missing path.");

    assert_eq!(
        err,
        ProcessMessageError::ValidationError(ValidationError::NoPath)
    );

    // Positive case
    alice_group
        .process_message(provider, ProtocolMessage::from(public_message_commit))
        .unwrap();
}

// ValSem246: External Commit: The signature of the PublicMessage MUST be verified with the credential of the KeyPackage in the included `path`.
#[apply(ciphersuites_and_providers)]
fn test_valsem246(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // Test with PublicMessage
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential,
        public_message_commit,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

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
        let bob_new_credential =
            generate_credential_with_key("Bob".into(), ciphersuite.signature_algorithm(), provider);

        // Generate KeyPackage
        let bob_new_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            bob_new_credential,
        );

        if let Some(ref mut path) = commit_bad.path {
            path.set_leaf_node(bob_new_key_package.leaf_node().clone())
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
        .process_message(provider, ProtocolMessage::from(public_message_commit_bad))
        .expect_err("Could process message despite wrong signature.");

    // This shows that signature verification fails if the signature is not done
    // using the credential in the path.
    assert_eq!(err, ProcessMessageError::InvalidSignature);

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
        alice_group.group().message_secrets(),
        alice_group
            .group()
            .message_secrets()
            .serialized_context()
            .to_vec(),
        provider.crypto(),
    )
    .unwrap();
    let verification_result: Result<AuthenticatedContentIn, _> =
        decrypted_message.verifiable_content().clone().verify(
            provider.crypto(),
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
        .process_message(provider, ProtocolMessage::from(public_message_commit))
        .expect("Unexpected error.");
}

// External Commit should work when group use ciphertext WireFormat
#[apply(ciphersuites_and_providers)]
fn test_pure_ciphertest(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // Test with PrivateMessage
    let ECValidationTestSetup {
        mut alice_group,
        alice_credential,
        bob_credential,
        ..
    } = validation_test_setup(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // Bob wants to commit externally.

    // Have Alice export everything that bob needs.
    let verifiable_group_info = alice_group
        .export_group_info(provider.crypto(), &alice_credential.signer, true)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    let (_bob_group, message, _) = MlsGroup::join_by_external_commit(
        provider,
        &bob_credential.signer,
        None,
        verifiable_group_info,
        alice_group.configuration(),
        &[],
        bob_credential.credential_with_key.clone(),
    )
    .expect("Error initializing group externally.");

    let mls_message_in: MlsMessageIn = message.into();
    assert_eq!(mls_message_in.wire_format(), WireFormat::PublicMessage);

    // Would fail if handshake message processing did not distinguish external messages
    assert!(alice_group
        .process_message(provider, mls_message_in)
        .is_ok());
}

mod utils {
    use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
    use tls_codec::{Deserialize, Serialize};

    use crate::{
        framing::{MlsMessageIn, PublicMessage, Sender},
        group::{
            config::CryptoConfig,
            tests::utils::{generate_credential_with_key, CredentialWithKeyAndSigner},
            MlsGroup, MlsGroupConfig, WireFormatPolicy,
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
        provider: &impl OpenMlsProvider,
    ) -> ECValidationTestSetup {
        // Generate credentials with keys
        let alice_credential = generate_credential_with_key(
            "Alice".into(),
            ciphersuite.signature_algorithm(),
            provider,
        );

        let bob_credential =
            generate_credential_with_key("Bob".into(), ciphersuite.signature_algorithm(), provider);

        // Define the MlsGroup configuration
        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(wire_format_policy)
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .build();

        // Alice creates a group
        let alice_group = MlsGroup::new(
            provider,
            &alice_credential.signer,
            &mls_group_config,
            alice_credential.credential_with_key.clone(),
        )
        .unwrap();

        // Bob wants to commit externally.

        // Have Alice export everything that bob needs.
        let verifiable_group_info = alice_group
            .export_group_info(provider.crypto(), &alice_credential.signer, false)
            .unwrap()
            .into_verifiable_group_info()
            .unwrap();
        let tree_option = alice_group.export_ratchet_tree();

        let (_, public_message_commit, _) = MlsGroup::join_by_external_commit(
            provider,
            &bob_credential.signer,
            Some(tree_option.into()),
            verifiable_group_info,
            alice_group.configuration(),
            &[],
            bob_credential.credential_with_key.clone(),
        )
        .unwrap();

        let public_message_commit = {
            let serialized_message = public_message_commit.tls_serialize_detached().unwrap();

            MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
                .unwrap()
                .into_plaintext()
                .unwrap()
        };

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
