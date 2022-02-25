//! This module tests the validation of commits as defined in
//! https://openmls.tech/book/message_validation.html#commit-message-validation

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::key_store::OpenMlsKeyStore;
use openmls_traits::types::Ciphersuite;
use tls_codec::{Deserialize, Serialize};

use rstest::*;
use rstest_reuse::{self, *};

use crate::group::*;
use crate::{
    ciphersuite::signable::{Signable, Verifiable},
    credentials::*,
    framing::*,
    group::errors::*,
    messages::proposals::ProposalOrRef,
    treesync::errors::ApplyUpdatePathError,
};

use super::utils::{generate_credential_bundle, generate_key_package_bundle};

struct CommitValidationTestSetup {
    alice_group: MlsGroup,
    bob_group: MlsGroup,
}

// Validation test setup
fn validation_test_setup(
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> CommitValidationTestSetup {
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

    let bob_key_package =
        generate_key_package_bundle(&[ciphersuite], &bob_credential, vec![], backend)
            .expect("An unexpected error occurred.");

    // Define the MlsGroup configuration

    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new(
        backend,
        &mls_group_config,
        group_id,
        alice_key_package
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice(),
    )
    .expect("An unexpected error occurred.");

    let (_message, welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("error adding Bob to group");

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    let bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("error creating group from welcome");

    CommitValidationTestSetup {
        alice_group,
        bob_group,
    }
}

// ValSem200: Commit must not cover inline self Remove proposal
#[apply(ciphersuites_and_backends)]
fn test_valsem200(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let CommitValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let alice_hash_ref = *alice_group
        .key_package_ref()
        .expect("Couldn't find key package ref.");

    // Since Alice won't commit to her own removal directly, we have to create
    // proposal and commit independently and then insert the proposal into the
    // commit manually.
    let serialized_proposal_message = alice_group
        .propose_remove_member(backend, &alice_hash_ref)
        .expect("error creating commit")
        .tls_serialize_detached()
        .expect("serialization error");

    // Let's get the proposal out of the message.
    let proposal_message =
        VerifiableMlsPlaintext::tls_deserialize(&mut serialized_proposal_message.as_slice())
            .expect("Could not deserialize message.");

    let proposal = if let MlsPlaintextContentType::Proposal(proposal) = proposal_message.content() {
        proposal.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // We have to clear the pending proposals so Alice doesn't try to commit to
    // her own remove.
    alice_group.clear_pending_proposals();

    // Now let's stick it in the commit.
    let serialized_message = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let mut commit_content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    commit_content
        .proposals
        .push(ProposalOrRef::Proposal(proposal));

    plaintext.set_content(MlsPlaintextContentType::Commit(commit_content));

    let alice_credential_bundle = backend
        .key_store()
        .read(
            &alice_group
                .credential()
                .expect("error retrieving credential")
                .signature_key()
                .tls_serialize_detached()
                .expect("error serializing credential"),
        )
        .expect("error retrieving credential bundle");

    let serialized_context = alice_group
        .export_group_context()
        .tls_serialize_detached()
        .expect("error serializing context");
    plaintext.set_context(serialized_context.clone());

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &alice_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let membership_key = alice_group.group().message_secrets().membership_key();

    signed_plaintext
        .set_membership_tag(backend, &serialized_context, membership_key)
        .expect("error refreshing membership tag");

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    // Have Bob try to process the commit.
    let message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = bob_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err: UnverifiedMessageError = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite self remove.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::AttemptedSelfRemoval)
    );

    // Positive case
    let unverified_message = bob_group
        .parse_message(MlsMessageIn::from(original_plaintext), backend)
        .expect("Could not parse message.");
    bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem201: Path must be present, if Commit contains Removes or Updates
#[apply(ciphersuites_and_backends)]
fn test_valsem201(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let wire_format_policy = PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
    // Test with MlsPlaintext
    let CommitValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(wire_format_policy, ciphersuite, backend);

    // This case is simple: Have Alice generate a self-updating commit, clear
    // the pending commit and then create a remove commit.

    // Start with the update
    // Create the self-update
    let serialized_update = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("error serializing plaintext");

    let mut update = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.");

    // The self-update currently contains an update proposal. This should change
    // with a future spec-change issue, but for now, we have to remove it
    // manually to create a completely empty commit.
    let mut commit_content = if let MlsPlaintextContentType::Commit(commit) = update.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    commit_content.proposals = vec![].into();

    update.set_content(MlsPlaintextContentType::Commit(commit_content));

    let serialized_update = update
        .tls_serialize_detached()
        .expect("error serializing plaintext");

    let update_message_in = erase_path(backend, &serialized_update, &alice_group);

    let unverified_message = bob_group
        .parse_message(update_message_in, backend)
        .expect("Could not parse message.");

    let err = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite missing path.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::RequiredPathNotFound)
    );

    let original_update_plaintext =
        VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    let unverified_message = bob_group
        .parse_message(MlsMessageIn::from(original_update_plaintext), backend)
        .expect("Could not parse message.");
    bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");

    // Now do the remove
    // Clear the pending commit.
    alice_group.clear_pending_commit();

    // Before we can test the commit, we first have to add Charlie so we can
    // actually remove someone and have someone else process the commit.
    let charlie_credential = generate_credential_bundle(
        "Charlie".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let charlie_key_package =
        generate_key_package_bundle(&[ciphersuite], &charlie_credential, vec![], backend)
            .expect("An unexpected error occurred.");

    let (_msg_out, welcome) = alice_group
        .add_members(backend, &[charlie_key_package])
        .expect("error adding charlie");

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .build();

    let mut charlie_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )
    .expect("Error creating group.");

    // Create the remove.
    let serialized_remove = alice_group
        .remove_members(
            backend,
            &[*bob_group
                .key_package_ref()
                .expect("error retrieving kp ref")],
        )
        .expect("Error creating remove")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let remove_message_in = erase_path(backend, &serialized_remove, &alice_group);

    // Have Charlie process everything
    let unverified_message = charlie_group
        .parse_message(remove_message_in, backend)
        .expect("Could not parse message.");

    let err = charlie_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite missing path.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::RequiredPathNotFound)
    );

    let original_remove_plaintext =
        VerifiableMlsPlaintext::tls_deserialize(&mut serialized_remove.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    let unverified_message = charlie_group
        .parse_message(MlsMessageIn::from(original_remove_plaintext), backend)
        .expect("Could not parse message.");
    if let ProcessedMessage::StagedCommitMessage(staged_commit) = charlie_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.")
    {
        charlie_group
            .merge_staged_commit(*staged_commit)
            .expect("error merging staged commit");
    } else {
        panic!("Expected a staged commit.");
    };

    // Make sure that alice' and charlies states match up.
    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    // Create a commit covering an update proposal.
    // Have charlie create an update proposal and then let Alice commit to it.
    let charlie_update_proposal = charlie_group
        .propose_self_update(backend, None)
        .expect("error creating self-update proposal");

    let unverified_message = alice_group
        .parse_message(charlie_update_proposal.into(), backend)
        .expect("error parsing proposal");
    alice_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("error processing proposal");

    let serialized_update = alice_group
        .commit_to_pending_proposals(backend)
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    // Erase the path.
    let update_message_in = erase_path(backend, &serialized_update, &alice_group);

    // Have charlie process it.
    let unverified_message = charlie_group
        .parse_message(update_message_in, backend)
        .expect("Could not parse message.");

    let err = charlie_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite missing path.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::RequiredPathNotFound)
    );

    let original_update_plaintext =
        VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    let unverified_message = charlie_group
        .parse_message(MlsMessageIn::from(original_update_plaintext), backend)
        .expect("Could not parse message.");
    charlie_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

fn erase_path(
    backend: &impl OpenMlsCryptoProvider,
    mut pt: &[u8],
    alice_group: &MlsGroup,
) -> MlsMessageIn {
    let mut plaintext =
        VerifiableMlsPlaintext::tls_deserialize(&mut pt).expect("Could not deserialize message.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let mut commit_content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };
    commit_content.path = None;

    plaintext.set_content(MlsPlaintextContentType::Commit(commit_content));

    let alice_credential_bundle = backend
        .key_store()
        .read(
            &alice_group
                .credential()
                .expect("error retrieving credential")
                .signature_key()
                .tls_serialize_detached()
                .expect("error serializing credential"),
        )
        .expect("error retrieving credential bundle");

    let serialized_context = alice_group
        .export_group_context()
        .tls_serialize_detached()
        .expect("error serializing context");
    plaintext.set_context(serialized_context.clone());

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &alice_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let membership_key = alice_group.group().message_secrets().membership_key();

    signed_plaintext
        .set_membership_tag(backend, &serialized_context, membership_key)
        .expect("error refreshing membership tag");

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    MlsMessageIn::from(verifiable_plaintext)
}

// ValSem202: Path must be the right length
#[apply(ciphersuites_and_backends)]
fn test_valsem202(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let CommitValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Have Alice generate a self-updating commit, remove a node from the path,
    // re-sign and have Bob process it.

    // Create the self-update
    let serialized_update = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let mut commit_content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };
    if let Some(ref mut path) = commit_content.path {
        path.pop();
    };

    plaintext.set_content(MlsPlaintextContentType::Commit(commit_content));

    let alice_credential_bundle = backend
        .key_store()
        .read(
            &alice_group
                .credential()
                .expect("error retrieving credential")
                .signature_key()
                .tls_serialize_detached()
                .expect("error serializing credential"),
        )
        .expect("error retrieving credential bundle");

    let serialized_context = alice_group
        .export_group_context()
        .tls_serialize_detached()
        .expect("error serializing context");
    plaintext.set_context(serialized_context.clone());

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &alice_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let membership_key = alice_group.group().message_secrets().membership_key();

    signed_plaintext
        .set_membership_tag(backend, &serialized_context, membership_key)
        .expect("error refreshing membership tag");

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    let update_message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = bob_group
        .parse_message(update_message_in, backend)
        .expect("Could not parse message.");

    let err = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite path length mismatch.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::UpdatePathError(
            ApplyUpdatePathError::PathLengthMismatch
        ))
    );

    let original_update_plaintext =
        VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    let unverified_message = bob_group
        .parse_message(MlsMessageIn::from(original_update_plaintext), backend)
        .expect("Could not parse message.");
    bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem203: Path secrets must decrypt correctly
#[apply(ciphersuites_and_backends)]
fn test_valsem203(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let CommitValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Have Alice generate a self-updating commit, scramble some ciphertexts and
    // have Bob process the resulting commit.

    // Create the self-update
    let serialized_update = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let mut commit_content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // This should cause decryption to fail.
    if let Some(ref mut path) = commit_content.path {
        path.flip_eps_bytes();
    };

    plaintext.set_content(MlsPlaintextContentType::Commit(commit_content));

    let alice_credential_bundle = backend
        .key_store()
        .read(
            &alice_group
                .credential()
                .expect("error retrieving credential")
                .signature_key()
                .tls_serialize_detached()
                .expect("error serializing credential"),
        )
        .expect("error retrieving credential bundle");

    let serialized_context = alice_group
        .export_group_context()
        .tls_serialize_detached()
        .expect("error serializing context");
    plaintext.set_context(serialized_context.clone());

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &alice_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let membership_key = alice_group.group().message_secrets().membership_key();

    signed_plaintext
        .set_membership_tag(backend, &serialized_context, membership_key)
        .expect("error refreshing membership tag");

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    let update_message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = bob_group
        .parse_message(update_message_in, backend)
        .expect("Could not parse message.");

    let err = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite scrambled ciphertexts.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::UpdatePathError(
            ApplyUpdatePathError::UnableToDecrypt
        ))
    );

    let original_update_plaintext =
        VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    let unverified_message = bob_group
        .parse_message(MlsMessageIn::from(original_update_plaintext), backend)
        .expect("Could not parse message.");
    bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem204: Public keys from Path must be verified and match the private keys from the direct path
#[apply(ciphersuites_and_backends)]
fn test_valsem204(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let CommitValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Have Alice generate a self-updating commit, flip the last byte of one of
    // the public keys in the path and have Bob process the commit.

    // Create the self-update
    let serialized_update = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let mut commit_content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // This should cause decryption to fail.
    if let Some(ref mut path) = commit_content.path {
        path.flip_node_bytes();
    };

    plaintext.set_content(MlsPlaintextContentType::Commit(commit_content));

    let alice_credential_bundle = backend
        .key_store()
        .read(
            &alice_group
                .credential()
                .expect("error retrieving credential")
                .signature_key()
                .tls_serialize_detached()
                .expect("error serializing credential"),
        )
        .expect("error retrieving credential bundle");

    let serialized_context = alice_group
        .export_group_context()
        .tls_serialize_detached()
        .expect("error serializing context");
    plaintext.set_context(serialized_context.clone());

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &alice_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let membership_key = alice_group.group().message_secrets().membership_key();

    signed_plaintext
        .set_membership_tag(backend, &serialized_context, membership_key)
        .expect("error refreshing membership tag");

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    let update_message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = bob_group
        .parse_message(update_message_in, backend)
        .expect("Could not parse message.");

    let err = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite modified public key in path.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::UpdatePathError(
            ApplyUpdatePathError::PathMismatch
        ))
    );

    let original_update_plaintext =
        VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    let unverified_message = bob_group
        .parse_message(MlsMessageIn::from(original_update_plaintext), backend)
        .expect("Could not parse message.");
    bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}

// ValSem205: Confirmation tag must be successfully verified
#[apply(ciphersuites_and_backends)]
fn test_valsem205(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let CommitValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Have Alice generate a self-updating commit, flip the last bit of the
    // confirmation tag and have Bob process the commit.

    // Create the self-update
    let serialized_update = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let mut new_confirmation_tag = plaintext
        .confirmation_tag()
        .expect("no confirmation tag on commit")
        .clone();

    new_confirmation_tag.0.flip_last_byte();

    plaintext.set_confirmation_tag(Some(new_confirmation_tag));

    // Since the membership tag covers the confirmation tag, we have to refresh it.
    let membership_key = alice_group.group().message_secrets().membership_key();

    let serialized_context = alice_group
        .export_group_context()
        .tls_serialize_detached()
        .expect("error serializing context");
    plaintext.set_context(serialized_context.clone());

    // Verify the plaintext so we have access to the membership tag computation
    // function.
    let mut verified_plaintext: MlsPlaintext = plaintext
        .verify(
            backend,
            alice_group
                .credential()
                .expect("error getting credential from group"),
        )
        .expect("error verifying plaintext");

    verified_plaintext
        .set_membership_tag(backend, &serialized_context, membership_key)
        .expect("error refreshing membership tag");

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(verified_plaintext, None);

    let update_message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = bob_group
        .parse_message(update_message_in, backend)
        .expect("Could not parse message.");

    let err = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite confirmation tag mismatch.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::ConfirmationTagMismatch)
    );

    // Positive case
    let unverified_message = bob_group
        .parse_message(MlsMessageIn::from(original_plaintext), backend)
        .expect("Could not parse message.");
    bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");
}
