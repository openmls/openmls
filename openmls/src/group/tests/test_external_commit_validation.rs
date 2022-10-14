//! This module contains all tests regarding the validation of incoming external
//! commit messages as defined in
//! https://github.com/openmls/openmls/wiki/Message-validation

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::Ciphersuite, OpenMlsCryptoProvider};
use tls_codec::{Deserialize, Serialize};

use rstest::*;
use rstest_reuse::{self, *};

use crate::{
    ciphersuite::signable::{Signable, Verifiable},
    credentials::{errors::*, *},
    framing::*,
    group::{errors::*, *},
    messages::{
        proposals::{
            AddProposal, ExternalInitProposal, Proposal, ProposalOrRef, ProposalType,
            RemoveProposal, UpdateProposal,
        },
        public_group_state::VerifiablePublicGroupState,
    },
};

use super::utils::{generate_credential_bundle, generate_key_package_bundle};

// Test setup values
struct ECValidationTestSetup {
    alice_group: MlsGroup,
    bob_credential_bundle: CredentialBundle,
    plaintext: VerifiableMlsPlaintext,
    original_plaintext: VerifiableMlsPlaintext,
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

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package_bundle(&[ciphersuite], &alice_credential, vec![], backend)
            .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration

    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .build();

    // === Alice creates a group ===
    let alice_group = MlsGroup::new(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice(),
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
    let pgs_encoded: Vec<u8> = alice_group
        .export_public_group_state(backend)
        .expect("Error exporting PGS")
        .tls_serialize_detached()
        .expect("Error serializing PGS");
    let verifiable_public_group_state =
        VerifiablePublicGroupState::tls_deserialize(&mut pgs_encoded.as_slice())
            .expect("Error deserializing PGS");
    let tree_option = alice_group.export_ratchet_tree();

    let (_bob_group, message) = MlsGroup::join_by_external_commit(
        backend,
        Some(&tree_option),
        verifiable_public_group_state,
        alice_group.configuration(),
        &[],
        &bob_credential_bundle,
    )
    .expect("Error initializing group externally.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let message = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

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
    // Test with MlsPlaintext
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        mut plaintext,
        original_plaintext,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let mut content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
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

    plaintext.set_content(MlsPlaintextContentType::Commit(content));

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &bob_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    // Have alice process the commit resulting from external init.
    let message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = alice_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite missing external init proposal.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::NoExternalInitProposals
        ))
    );

    // Positive case
    let unverified_message = alice_group
        .parse_message(MlsMessageIn::from(original_plaintext), backend)
        .expect("Could not parse message.");
    alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
#[apply(ciphersuites_and_backends)]
fn test_valsem241(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        mut plaintext,
        original_plaintext,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let mut content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
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

    plaintext.set_content(MlsPlaintextContentType::Commit(content));

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &bob_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    // Have alice process the commit resulting from external init.
    let message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = alice_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err(
            "Could process unverified message despite second ext. init proposal in commit.",
        );

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::MultipleExternalInitProposals
        ))
    );

    // Positive case
    let unverified_message = alice_group
        .parse_message(MlsMessageIn::from(original_plaintext), backend)
        .expect("Could not parse message.");
    alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem242: External Commit, inline Proposals: There MUST NOT be any Add proposals.
#[apply(ciphersuites_and_backends)]
fn test_valsem242(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        mut plaintext,
        original_plaintext,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let mut content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    let bob_key_package = generate_key_package_bundle(
        &[ciphersuite],
        bob_credential_bundle.credential(),
        vec![],
        backend,
    )
    .expect("An unexpected error occurred.");

    // Add an Add proposal to the external commit.
    let add_proposal = ProposalOrRef::Proposal(Proposal::Add(AddProposal {
        key_package: bob_key_package,
    }));

    content.proposals.push(add_proposal);

    plaintext.set_content(MlsPlaintextContentType::Commit(content));

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &bob_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    // Have alice process the commit resulting from external init.
    let message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = alice_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err(
            "Could process unverified message despite Add proposal in the external commit.",
        );

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::InvalidInlineProposals
        ))
    );

    // Positive case
    let unverified_message = alice_group
        .parse_message(MlsMessageIn::from(original_plaintext), backend)
        .expect("Could not parse message.");
    alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem243: External Commit, inline Proposals: There MUST NOT be any Update proposals.
#[apply(ciphersuites_and_backends)]
fn test_valsem243(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        plaintext: _,
        original_plaintext: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Alice has to add Bob first, so that in the external commit, we can have
    // an update proposal that comes from a leaf that's actually inside of the
    // tree. If that is not the case, we'll get a general proposal validation
    // error before we get the external commit specific one.

    let bob_key_package = generate_key_package_bundle(
        &[ciphersuite],
        bob_credential_bundle.credential(),
        vec![],
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
    let pgs_encoded: Vec<u8> = alice_group
        .export_public_group_state(backend)
        .expect("Error exporting PGS")
        .tls_serialize_detached()
        .expect("Error serializing PGS");
    let verifiable_public_group_state =
        VerifiablePublicGroupState::tls_deserialize(&mut pgs_encoded.as_slice())
            .expect("Error deserializing PGS");
    let tree_option = alice_group.export_ratchet_tree();

    let (_bob_group, message) = MlsGroup::join_by_external_commit(
        backend,
        Some(&tree_option), // Note that this isn't actually used.
        verifiable_public_group_state,
        alice_group.configuration(),
        &[],
        &bob_credential_bundle,
    )
    .expect("Error initializing group externally.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_plaintext = plaintext.clone();

    let mut content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    let bob_key_package = generate_key_package_bundle(
        &[ciphersuite],
        bob_credential_bundle.credential(),
        vec![],
        backend,
    )
    .expect("Error generating key package");

    // Add an Update proposal to the external commit.
    let update_proposal = ProposalOrRef::Proposal(Proposal::Update(UpdateProposal {
        key_package: bob_key_package,
    }));

    content.proposals.push(update_proposal);

    plaintext.set_content(MlsPlaintextContentType::Commit(content));

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &bob_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    // Have alice process the commit resulting from external init.
    let message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = alice_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message Update proposal in the external commit.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::InvalidInlineProposals
        ))
    );

    // Positive case
    let unverified_message = alice_group
        .parse_message(MlsMessageIn::from(original_plaintext), backend)
        .expect("Could not parse message.");
    alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem244: External Commit, inline Remove Proposal: The identity and the endpoint_id of the removed leaf are identical to the ones in the path KeyPackage.
#[apply(ciphersuites_and_backends)]
fn test_valsem244(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        plaintext: _,
        original_plaintext: _,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Alice has to add Bob first, so that Bob actually creates a remove
    // proposal to remove his former self.

    let bob_key_package = generate_key_package_bundle(
        &[ciphersuite],
        bob_credential_bundle.credential(),
        vec![],
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
    let pgs_encoded: Vec<u8> = alice_group
        .export_public_group_state(backend)
        .expect("Error exporting PGS")
        .tls_serialize_detached()
        .expect("Error serializing PGS");
    let verifiable_public_group_state =
        VerifiablePublicGroupState::tls_deserialize(&mut pgs_encoded.as_slice())
            .expect("Error deserializing PGS");
    let tree_option = alice_group.export_ratchet_tree();

    let (_bob_group, message) = MlsGroup::join_by_external_commit(
        backend,
        Some(&tree_option),
        verifiable_public_group_state,
        alice_group.configuration(),
        &[],
        &bob_credential_bundle,
    )
    .expect("Error initializing group externally.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    let original_plaintext = plaintext.clone();

    let mut content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
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
        removed: *alice_group
            .key_package_ref()
            .expect("An unexpected error occurred."),
    }));

    content.proposals.push(remove_proposal);

    plaintext.set_content(MlsPlaintextContentType::Commit(content));

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &bob_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    // Have alice process the commit resulting from external init.
    let message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = alice_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite the remove proposal targeting the wrong group member.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::InvalidRemoveProposal
        ))
    );

    // Positive case
    let unverified_message = alice_group
        .parse_message(MlsMessageIn::from(original_plaintext), backend)
        .expect("Could not parse message.");
    alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem245: External Commit, referenced Proposals: There MUST NOT be any ExternalInit proposals.
#[apply(ciphersuites_and_backends)]
fn test_valsem245(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        mut plaintext,
        original_plaintext,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let mut content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // Add an extra external init proposal by reference.
    // First create an external init proposal.
    let second_ext_init_prop = Proposal::ExternalInit(ExternalInitProposal::from(vec![1, 2, 3]));

    let queued_proposal = QueuedProposal::from_proposal_and_sender(
        ciphersuite,
        backend,
        second_ext_init_prop,
        &Sender::Member(
            *alice_group
                .key_package_ref()
                .expect("An unexpected error occurred."),
        ),
    )
    .expect("error creating queued proposal");

    // Add it to Alice's proposal store
    alice_group.store_pending_proposal(queued_proposal.clone());

    let proposal_reference = ProposalOrRef::Reference(queued_proposal.proposal_reference());

    content.proposals.push(proposal_reference);

    plaintext.set_content(MlsPlaintextContentType::Commit(content));

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &bob_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    // Have alice process the commit resulting from external init.
    let message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = alice_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite the external commit including an external init proposal by reference.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::ExternalCommitValidation(
            ExternalCommitValidationError::MultipleExternalInitProposals
        ))
    );

    // Positive case
    let unverified_message = alice_group
        .parse_message(MlsMessageIn::from(original_plaintext), backend)
        .expect("Could not parse message.");
    alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem246: External Commit: MUST contain a path.
#[apply(ciphersuites_and_backends)]
fn test_valsem246(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        mut plaintext,
        original_plaintext,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let mut content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // Remove the path from the commit
    content.path = None;

    plaintext.set_content(MlsPlaintextContentType::Commit(content));

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &bob_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    // Have alice process the commit resulting from external init.
    let message_in = MlsMessageIn::from(verifiable_plaintext);

    let err = alice_group
        .parse_message(message_in, backend)
        .expect_err("Could process unverified message despite missing path.");

    assert_eq!(
        err,
        ParseMessageError::ValidationError(ValidationError::NoPath)
    );

    // Positive case
    let unverified_message = alice_group
        .parse_message(MlsMessageIn::from(original_plaintext), backend)
        .expect("Could not parse message.");
    alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem247: External Commit: The signature of the MLSPlaintext MUST be verified with the credential of the KeyPackage in the included `path`.
#[apply(ciphersuites_and_backends)]
fn test_valsem247(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let ECValidationTestSetup {
        mut alice_group,
        bob_credential_bundle,
        mut plaintext,
        original_plaintext,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let mut content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
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
    let bob_new_key_package =
        generate_key_package_bundle(&[ciphersuite], &bob_new_credential, vec![], backend)
            .expect("An unexpected error occurred.");

    if let Some(ref mut path) = content.path {
        path.set_leaf_key_package(bob_new_key_package)
    }

    plaintext.set_content(MlsPlaintextContentType::Commit(content));

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &bob_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    // Have alice process the commit resulting from external init.
    let message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = alice_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err = alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite wrong signature.");

    // This shows that signature verification fails if the signature is not done
    // using the credential in the path.
    assert_eq!(err, UnverifiedMessageError::InvalidSignature);

    // This shows that the credential in the original path key package is actually bob's credential.
    let content = if let MlsPlaintextContentType::Commit(commit) = original_plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    let path_credential = content
        .path()
        .as_ref()
        .expect("no path in external commit")
        .leaf_key_package()
        .credential();
    assert_eq!(path_credential, bob_credential_bundle.credential());

    // This shows that the message is actually signed using this credential.
    let verification_result: Result<MlsPlaintext, CredentialError> = original_plaintext
        .clone()
        .verify(backend, bob_credential_bundle.credential());
    assert!(verification_result.is_ok());

    // Positive case
    // This shows it again, since ValSem010 ensures that the signature is
    // correct (which it only is, if alice is using the credential in the path
    // key package).
    let unverified_message = alice_group
        .parse_message(MlsMessageIn::from(original_plaintext), backend)
        .expect("Could not parse message.");
    alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}
