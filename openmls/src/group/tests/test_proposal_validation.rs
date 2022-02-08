//! This module tests the validation of proposals as defined in
//! https://openmls.tech/book/message_validation.html#semantic-validation-of-proposals-covered-by-a-commit

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};

use rstest::*;
use rstest_reuse::{self, *};
use tls_codec::Serialize;

use crate::{
    config::*,
    credentials::*,
    framing::{FramingParameters, MlsPlaintext, WireFormat},
    group::errors::*,
    group::*,
    key_packages::*,
};

use super::utils::{generate_credential_bundle, generate_key_package_bundle};

/// Helper function to generate and output CredentialBundle and KeyPackageBundle
fn generate_credential_bundle_and_key_package_bundle(
    identity: Vec<u8>,
    ciphersuite: &Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (CredentialBundle, KeyPackageBundle) {
    let credential = generate_credential_bundle(
        identity,
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("Failed to generate CredentialBundle.");
    let credential_bundle = backend
        .key_store()
        .read::<CredentialBundle>(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
        )
        .expect("An unexpected error occurred.");

    let key_package =
        generate_key_package_bundle(&[ciphersuite.name()], &credential, vec![], backend)
            .expect("Failed to generate KeyPackage.");
    let key_package_bundle = backend
        .key_store()
        .read(
            key_package
                .hash_ref(backend.crypto())
                .expect("Could not hash KeyPackage")
                .value(),
        )
        .expect("An unexpected error occurred.");

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

/// Helper function to create a group, create proposals to add bob and charlie,
/// and return the result of committing those proposals.
fn create_commit_to_add_bob_and_charlie(
    alice_credential_bundle: CredentialBundle,
    alice_key_package_bundle: KeyPackageBundle,
    bob_key_package: KeyPackage,
    charlie_key_package: KeyPackage,
    ciphersuite: &Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<CreateCommitResult, CoreGroupError> {
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

    alice_group.create_commit(params, backend)
}

enum KeyUniqueness {
    /// Positive Case: the proposals have different keys.
    PositiveDifferentKey,
    /// Negative Case: the proposals have the same key.
    NegativeSameKey,
}

/// ValSem100:
/// Add Proposal:
/// Identity in proposals must be unique among proposals
#[apply(ciphersuites_and_backends)]
fn test_valsem100(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for (bob_id, charlie_id) in [
        ("42", "42"), // Negative Case: Bob and Charlie have same identity
        ("42", "24"), // Positive Case: Bob and Charlie have different identity
    ] {
        let (alice_credential_bundle, alice_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle("Alice".into(), ciphersuite, backend);

        // 0. Initialize Bob and Charlie
        let (_bob_credential_bundle, bob_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle(bob_id.into(), ciphersuite, backend);
        let bob_key_package = bob_key_package_bundle.key_package().clone();

        let (_charlie_credential_bundle, charlie_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle(
                charlie_id.into(),
                ciphersuite,
                backend,
            );
        let charlie_key_package = charlie_key_package_bundle.key_package().clone();

        // 1. Create a group and try to create a commit to add Bob and Charlie
        let res = create_commit_to_add_bob_and_charlie(
            alice_credential_bundle,
            alice_key_package_bundle,
            bob_key_package,
            charlie_key_package,
            ciphersuite,
            backend,
        );

        if bob_id == charlie_id {
            // Negative Case: we should output an error
            let err =
                res.expect_err("Created commit when the proposals have a duplicate identity!");
            assert_eq!(
                err,
                CoreGroupError::ProposalValidationError(
                    ProposalValidationError::DuplicateIdentityAddProposal
                )
            );
        } else {
            // Positive Case: we should succeed
            let _ = res.expect("Failed to create commit with different identities!");
        }
    }

    // TODO #525: Add test for incoming proposals.
}

/// ValSem101:
/// Add Proposal:
/// Signature public key in proposals must be unique among proposals
#[apply(ciphersuites_and_backends)]
fn test_valsem101(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for bob_and_charlie_share_keys in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveDifferentKey,
    ] {
        // 0. Initialize Alice
        let (alice_credential_bundle, alice_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle("Alice".into(), ciphersuite, backend);

        // 1. Initialize Bob and Charlie
        let bob_signature_keypair: SignatureKeypair;
        let charlie_signature_keypair: SignatureKeypair;

        match bob_and_charlie_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let shared_signature_keypair =
                    SignatureKeypair::new(ciphersuite.signature_scheme(), backend)
                        .expect("failed to generate signature keypair");

                bob_signature_keypair = shared_signature_keypair.clone();
                charlie_signature_keypair = shared_signature_keypair.clone();
            }
            KeyUniqueness::PositiveDifferentKey => {
                bob_signature_keypair =
                    SignatureKeypair::new(ciphersuite.signature_scheme(), backend)
                        .expect("failed to generate signature keypair");
                charlie_signature_keypair =
                    SignatureKeypair::new(ciphersuite.signature_scheme(), backend)
                        .expect("failed to generate signature keypair");
            }
        }

        let bob_credential_bundle =
            CredentialBundle::from_parts("Bob".into(), bob_signature_keypair);
        let charlie_credential_bundle =
            CredentialBundle::from_parts("Charlie".into(), charlie_signature_keypair);

        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            backend,
            vec![],
        )
        .expect("failed to generate key package");
        let bob_key_package = bob_key_package_bundle.key_package().clone();
        let charlie_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &charlie_credential_bundle,
            backend,
            vec![],
        )
        .expect("failed to generate key package");
        let charlie_key_package = charlie_key_package_bundle.key_package().clone();

        // 2. Create a group and try to create a commit to add Bob and Charlie
        let res = create_commit_to_add_bob_and_charlie(
            alice_credential_bundle,
            alice_key_package_bundle,
            bob_key_package,
            charlie_key_package,
            ciphersuite,
            backend,
        );

        match bob_and_charlie_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let err = res
                    .expect_err("Created commit when the proposals have the same signature key!");
                assert_eq!(
                    err,
                    CoreGroupError::ProposalValidationError(
                        ProposalValidationError::DuplicateSignatureKeyAddProposal
                    )
                );
            }
            KeyUniqueness::PositiveDifferentKey => {
                let _ = res.expect("Failed to create commit with different signature keypairs!");
            }
        }
    }

    // TODO #525: Add test for incoming proposals.
}

/// ValSem102:
/// Add Proposal:
/// HPKE init key in proposals must be unique among proposals
#[apply(ciphersuites_and_backends)]
fn test_valsem102(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for bob_and_charlie_share_keys in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveDifferentKey,
    ] {
        // 0. Initialize Alice, Bob, and Charlie
        let (alice_credential_bundle, alice_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle("Alice".into(), ciphersuite, backend);
        let (bob_credential_bundle, mut bob_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle("Bob".into(), ciphersuite, backend);
        let (charlie_credential_bundle, mut charlie_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle(
                "Charlie".into(),
                ciphersuite,
                backend,
            );

        match bob_and_charlie_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let shared_leaf_secret = Secret::random(
                    bob_key_package_bundle.key_package().ciphersuite(),
                    backend,
                    bob_key_package_bundle.key_package().protocol_version(),
                )
                .expect("failed to generate random leaf secret");

                bob_key_package_bundle = KeyPackageBundle::new_from_leaf_secret(
                    &[ciphersuite.name()],
                    backend,
                    &bob_credential_bundle,
                    vec![],
                    shared_leaf_secret.clone(),
                )
                .expect("failed to generate key package");
                charlie_key_package_bundle = KeyPackageBundle::new_from_leaf_secret(
                    &[ciphersuite.name()],
                    backend,
                    &charlie_credential_bundle,
                    vec![],
                    shared_leaf_secret.clone(),
                )
                .expect("failed to generate key package");
            }
            KeyUniqueness::PositiveDifferentKey => {
                // don't need to do anything since the keys are already
                // different.
            }
        }

        let bob_key_package = bob_key_package_bundle.key_package().clone();
        let charlie_key_package = charlie_key_package_bundle.key_package().clone();

        // 1. Create a group and try to create a commit to add Bob and Charlie
        let res = create_commit_to_add_bob_and_charlie(
            alice_credential_bundle,
            alice_key_package_bundle,
            bob_key_package,
            charlie_key_package,
            ciphersuite,
            backend,
        );

        match bob_and_charlie_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let err =
                    res.expect_err("Created commit when the proposals have a same HPKE init key!");
                assert_eq!(
                    err,
                    CoreGroupError::ProposalValidationError(
                        ProposalValidationError::DuplicatePublicKeyAddProposal
                    )
                );
            }
            KeyUniqueness::PositiveDifferentKey => {
                let _ = res.expect("Failed to create commit with different HPKE init keys!");
            }
        }
    }

    // TODO #525: Add test for incoming proposals.
}

/// ValSem103:
/// Add Proposal:
/// Identity in proposals must be unique among existing group members
#[apply(ciphersuites_and_backends)]
fn test_valsem103(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for (alice_id, bob_id) in [
        ("42", "42"), // Negative Case: Alice and Bob have same identity
        ("42", "24"), // Positive Case: Alice and Bob have different identity
    ] {
        // 0. Initialize Alice and Bob
        let (alice_credential_bundle, alice_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle(
                alice_id.into(),
                ciphersuite,
                backend,
            );
        let (_bob_credential_bundle, bob_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle(bob_id.into(), ciphersuite, backend);
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
        let res = alice_group.create_commit(params, backend);

        if alice_id == bob_id {
            // Negative Case: we should output an error
            let err = res.expect_err(
                "Created commit when the proposal has the same identity as a group member!",
            );
            assert_eq!(
                err,
                CoreGroupError::ProposalValidationError(
                    ProposalValidationError::ExistingIdentityAddProposal
                )
            );
        } else {
            // Positive Case: we should succeed
            let _ = res.expect("Failed to create commit with different identities!");
        }
    }

    // TODO #525: Add test for incoming proposals.
}
