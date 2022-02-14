//! This module tests the validation of commits as defined in
//! https://openmls.tech/book/message_validation.html#commit-message-validation

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::key_store::OpenMlsKeyStore;
use tls_codec::{Deserialize, Serialize};

use rstest::*;
use rstest_reuse::{self, *};

use crate::{
    config::*,
    credentials::*,
    framing::*,
    group::errors::ExternalCommitValidationError,
    group::*,
    messages::{
        public_group_state::VerifiablePublicGroupState, AddProposal, ExternalInitProposal,
        Proposal, ProposalOrRef, ProposalType, RemoveProposal, UpdateProposal,
    },
    prelude_test::signable::{Signable, Verifiable},
};

use super::utils::{generate_credential_bundle, generate_key_package_bundle};

struct CommitValidationTestSetup {
    alice_group: MlsGroup,
    bob_group: MlsGroup,
}

// Validation test setup
fn validation_test_setup(
    wire_format_policy: WireFormatPolicy,
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> CommitValidationTestSetup {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let bob_credential = generate_credential_bundle(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package_bundle(&[ciphersuite.name()], &alice_credential, vec![], backend)
            .expect("An unexpected error occurred.");

    let bob_key_package =
        generate_key_package_bundle(&[ciphersuite.name()], &bob_credential, vec![], backend)
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

    let (message, welcome) = alice_group
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
//#[apply(ciphersuites_and_backends)]
fn test_valsem200(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test with MlsPlaintext
    let CommitValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(*PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    let alice_hash_ref = alice_group
        .key_package_ref()
        .expect("Couldn't find key package ref.")
        .clone();

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

    let mut proposal =
        if let MlsPlaintextContentType::Proposal(proposal) = proposal_message.content() {
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
        .expect("Error committing to pending proposals")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
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

    let serialized_context = alice_group
        .export_group_context()
        .tls_serialize_detached()
        .expect("error serializing context");
    // TODO: Figure out how to get hold of the membership secret
    signed_plaintext
        .set_membership_tag(backend, &serialized_context, alice_group.membership_key)
        .expect("error refreshing membership tag");

    let verifiable_plaintext: VerifiableMlsPlaintext =
        VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    // Have Bob try to process the commit.
    let message_in = MlsMessageIn::from(verifiable_plaintext);

    let unverified_message = bob_group
        .parse_message(message_in, backend)
        .expect("Could not parse message.");

    let err = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite missing external init proposal.");

    assert_eq!(
        err,
        MlsGroupError::Group(CoreGroupError::ExternalCommitValidationError(
            ExternalCommitValidationError::NoExternalInitProposals
        ))
    );

    // Positive case
    let unverified_message = bob_group
        .parse_message(MlsMessageIn::from(original_plaintext), backend)
        .expect("Could not parse message.");
    bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect("Unexpected error.");

    //// Remove the external init proposal in the commit.
    //let proposal_position = content
    //    .proposals
    //    .iter()
    //    .position(|proposal| match proposal {
    //        crate::messages::ProposalOrRef::Proposal(proposal) => {
    //            proposal.is_type(ProposalType::ExternalInit)
    //        }
    //        crate::messages::ProposalOrRef::Reference(_) => false,
    //    })
    //    .expect("Couldn't find external init proposal.");

    //content.proposals.remove(proposal_position);

    //plaintext.set_content(MlsPlaintextContentType::Commit(content));

    //// We have to re-sign, since we changed the content.
    //let mut signed_plaintext: MlsPlaintext = plaintext
    //    .payload()
    //    .clone()
    //    .sign(backend, &bob_credential_bundle)
    //    .expect("Error signing modified payload.");

    //// Set old confirmation tag
    //signed_plaintext.set_confirmation_tag(
    //    original_plaintext
    //        .confirmation_tag()
    //        .expect("no confirmation tag on original message")
    //        .clone(),
    //);

    //let verifiable_plaintext: VerifiableMlsPlaintext =
    //    VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None);

    //// Have alice process the commit resulting from external init.
    //let message_in = MlsMessageIn::from(verifiable_plaintext);

    //let unverified_message = alice_group
    //    .parse_message(message_in, backend)
    //    .expect("Could not parse message.");

    //let err = alice_group
    //    .process_unverified_message(unverified_message, None, backend)
    //    .expect_err("Could process unverified message despite missing external init proposal.");

    //assert_eq!(
    //    err,
    //    MlsGroupError::Group(CoreGroupError::ExternalCommitValidationError(
    //        ExternalCommitValidationError::NoExternalInitProposals
    //    ))
    //);

    //// Positive case
    //let unverified_message = alice_group
    //    .parse_message(MlsMessageIn::from(original_plaintext), backend)
    //    .expect("Could not parse message.");
    //alice_group
    //    .process_unverified_message(unverified_message, None, backend)
    //    .expect("Unexpected error.");
}
