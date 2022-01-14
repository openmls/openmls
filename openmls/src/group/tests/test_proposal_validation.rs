//! This module tests the validation of proposals as defined in
//! https://openmls.tech/book/message_validation.html#semantic-validation-of-proposals-covered-by-a-commit

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;

use rstest::*;
use rstest_reuse::{self, *};

use crate::{
    config::*,
    credentials::*,
    group::errors::*,
    group::*,
    key_packages::*,
    prelude_test::{FramingParameters, MlsPlaintext, WireFormat},
};

/// Helper function to generate a CredentialBundle
fn generate_credential_bundle(
    identity: Vec<u8>,
    ciphersuite: &Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> CredentialBundle {
    CredentialBundle::new(
        identity,
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("Failed to generate CredentialBundle.")
}

/// Helper function to generate a KeyPackageBundle
fn generate_key_package_bundle(
    credential_bundle: &CredentialBundle,
    ciphersuite: &Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> KeyPackageBundle {
    KeyPackageBundle::new(&[ciphersuite.name()], credential_bundle, backend, vec![])
        .expect("Failed to generate KeyPackageBundle")
}

/// Helper function to generate a CredentialBundle and KeyPackageBundle
fn generate_credential_bundle_and_key_package_bundle(
    identity: Vec<u8>,
    ciphersuite: &Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (CredentialBundle, KeyPackageBundle) {
    let credential_bundle = generate_credential_bundle(identity, ciphersuite, backend);
    let key_package_bundle = generate_key_package_bundle(&credential_bundle, ciphersuite, backend);
    (credential_bundle, key_package_bundle)
}

fn generate_proposal_store(
    proposals: &[MlsPlaintext],
    ciphersuite: &Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> ProposalStore {
    let mut proposal_store = ProposalStore::new();
    for proposal in proposals {
        proposal_store.add(
            QueuedProposal::from_mls_plaintext(ciphersuite, backend, proposal.to_owned())
                .expect("Could not create QueuedProposal from MlsPlaintext"),
        );
    }
    proposal_store
}

/// ValSem100:
/// Add Proposal:
/// Identity in proposals must be unique among proposals
#[apply(ciphersuites_and_backends)]
fn test_valsem100(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (alice_credential_bundle, alice_key_package_bundle) =
        generate_credential_bundle_and_key_package_bundle("Alice".into(), ciphersuite, backend);

    // 0. Create Bob and Charlie with the same identity
    let (_bob_credential_bundle, bob_key_package_bundle) =
        generate_credential_bundle_and_key_package_bundle("42".into(), ciphersuite, backend);
    let bob_key_package = bob_key_package_bundle.key_package().clone();

    let (_charlie_credential_bundle, charlie_key_package_bundle) =
        generate_credential_bundle_and_key_package_bundle("42".into(), ciphersuite, backend);
    let charlie_key_package = charlie_key_package_bundle.key_package().clone();

    // 1. Alice creates a group
    let group_aad = b"Alice's Friends";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsCiphertext);
    let alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Error creating group.");

    // 2. Alice creates a proposal to add Bob
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package,
            backend,
        )
        .expect("Could not create proposal to add Bob.");

    // 3. Alice creates a proposal to add Charlie
    let charlie_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            charlie_key_package,
            backend,
        )
        .expect("Could not create proposal to add Charlie.");

    // 4. Alice queues these proposals
    let proposal_store = generate_proposal_store(
        &[bob_add_proposal, charlie_add_proposal],
        ciphersuite,
        backend,
    );

    // 5. Alice tries to generate a commit message
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .build();
    let err = alice_group
        .create_commit(params, backend)
        .expect_err("Created commit when the proposals have a duplicate identity!");
    assert_eq!(
        err,
        CoreGroupError::ProposalValidationError(
            ProposalValidationError::DuplicateIdentityAddProposal
        )
    );

    // TODO #525: Also test that we are correctly validating incoming proposals.
}

/// ValSem103:
/// Add Proposal:
/// Identity in proposals must be unique among existing group members
#[apply(ciphersuites_and_backends)]
fn test_valsem103(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (alice_credential_bundle, alice_key_package_bundle) =
        generate_credential_bundle_and_key_package_bundle("42".into(), ciphersuite, backend);

    // 0. Create Bob with the same identity as Alice
    let (_bob_credential_bundle, bob_key_package_bundle) =
        generate_credential_bundle_and_key_package_bundle("42".into(), ciphersuite, backend);
    let bob_key_package = bob_key_package_bundle.key_package().clone();

    // 1. Alice creates a group
    let group_aad = b"Alice's Friends";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsCiphertext);
    let alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Error creating group.");

    // 2. Alice creates a proposal to add Bob
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package,
            backend,
        )
        .expect("Could not create proposal to add Bob.");

    // 4. Alice queues the proposal
    let proposal_store = generate_proposal_store(&[bob_add_proposal], ciphersuite, backend);

    // 5. Alice tries to generate a commit message
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .build();
    let err = alice_group
        .create_commit(params, backend)
        .expect_err("Created commit when the proposal has the same identity as a group member!");
    assert_eq!(
        err,
        CoreGroupError::ProposalValidationError(
            ProposalValidationError::ExistingIdentityAddProposal
        )
    );

    // TODO #525: Also test that we are correctly validating incoming proposals.
}
