//! This module tests the validation of proposals as defined in
//! https://openmls.tech/book/message_validation.html#semantic-validation-of-proposals-covered-by-a-commit

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};

use rstest::*;
use rstest_reuse::{self, *};
use tls_codec::{Deserialize, Serialize};

use crate::{
    ciphersuite::signable::Signable,
    credentials::*,
    framing::{
        MlsMessageIn, MlsMessageOut, MlsPlaintext, MlsPlaintextContentType, VerifiableMlsPlaintext,
    },
    group::errors::*,
    group::*,
    key_packages::*,
    messages::{AddProposal, Proposal, ProposalOrRef, Welcome},
};

use super::utils::{generate_credential_bundle, generate_key_package_bundle};

/// Helper function to generate and output CredentialBundle and KeyPackageBundle
fn generate_credential_bundle_and_key_package_bundle(
    identity: Vec<u8>,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (CredentialBundle, KeyPackageBundle) {
    let credential = generate_credential_bundle(
        identity,
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
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

    let key_package = generate_key_package_bundle(&[ciphersuite], &credential, vec![], backend)
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

/// Helper function to create a group and try to add `members` to it.
fn create_group_with_members(
    alice_key_package_bundle: KeyPackageBundle,
    member_key_packages: &[KeyPackage],
    backend: &impl OpenMlsCryptoProvider,
) -> Result<(MlsMessageOut, Welcome), AddMembersError> {
    let mut alice_group = MlsGroup::new(
        backend,
        &MlsGroupConfig::default(),
        GroupId::from_slice(b"Alice's Friends"),
        alice_key_package_bundle
            .key_package()
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice(),
    )
    .expect("An unexpected error occurred.");

    alice_group.add_members(backend, member_key_packages)
}

struct ProposalValidationTestSetup {
    alice_group: MlsGroup,
    bob_group: MlsGroup,
}

// Validation test setup
fn validation_test_setup(
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> ProposalValidationTestSetup {
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

    ProposalValidationTestSetup {
        alice_group,
        bob_group,
    }
}

fn insert_proposal_and_resign(
    backend: &impl OpenMlsCryptoProvider,
    proposal: Proposal,
    mut plaintext: VerifiableMlsPlaintext,
    original_plaintext: VerifiableMlsPlaintext,
    committer_group: &MlsGroup,
) -> VerifiableMlsPlaintext {
    let mut commit_content = if let MlsPlaintextContentType::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    commit_content
        .proposals
        .push(ProposalOrRef::Proposal(proposal));

    plaintext.set_content(MlsPlaintextContentType::Commit(commit_content));

    let committer_credential_bundle = backend
        .key_store()
        .read(
            &committer_group
                .credential()
                .expect("error retrieving credential")
                .signature_key()
                .tls_serialize_detached()
                .expect("error serializing credential"),
        )
        .expect("error retrieving credential bundle");

    let serialized_context = committer_group
        .export_group_context()
        .tls_serialize_detached()
        .expect("error serializing context");
    plaintext.set_context(serialized_context.clone());

    // We have to re-sign, since we changed the content.
    let mut signed_plaintext: MlsPlaintext = plaintext
        .payload()
        .clone()
        .sign(backend, &committer_credential_bundle)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let membership_key = committer_group.group().message_secrets().membership_key();

    signed_plaintext
        .set_membership_tag(backend, &serialized_context, membership_key)
        .expect("error refreshing membership tag");

    VerifiableMlsPlaintext::from_plaintext(signed_plaintext, None)
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
fn test_valsem100(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for (bob_id, charlie_id) in [
        ("42", "42"), // Negative Case: Bob and Charlie have same identity
        ("42", "24"), // Positive Case: Bob and Charlie have different identity
    ] {
        let (_alice_credential_bundle, alice_key_package_bundle) =
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

        // 1. Alice creates a group and tries to add Bob and Charlie to it
        let res = create_group_with_members(
            alice_key_package_bundle,
            &[bob_key_package, charlie_key_package],
            backend,
        );

        if bob_id == charlie_id {
            // Negative Case: we should output an error
            let err = res.expect_err("was able to add users with the same identity!");
            assert_eq!(
                err,
                AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                    ProposalValidationError::DuplicateIdentityAddProposal
                ))
            );
        } else {
            // Positive Case: we should succeed
            let _ = res.expect("failed to add users with different identities!");
        }
    }

    // We now test if ValSem100 is also performed when a client receives a
    // commit.  Before we can test reception of (invalid) proposals, we set up a
    // new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(*PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We now have alice create a commit with an add proposal. Then we
    // artificially add another add proposal with the same identity.
    let (_charlie_credential_bundle, charlie_key_package_bundle) =
        generate_credential_bundle_and_key_package_bundle("Charlie".into(), ciphersuite, backend);
    let charlie_key_package = charlie_key_package_bundle.key_package().clone();

    // Create the Commit with Add proposal.
    let serialized_update = alice_group
        .add_members(backend, &[charlie_key_package])
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    // Now let's create a second proposal and insert it into the commit. We want
    // a different signature key, different hpke public key, but the same
    // identity.
    let (_charlie_credential_bundle, charlie_key_package_bundle) =
        generate_credential_bundle_and_key_package_bundle("Charlie".into(), ciphersuite, backend);
    let charlie_key_package = charlie_key_package_bundle.key_package().clone();
    let second_add_proposal = Proposal::Add(AddProposal {
        key_package: charlie_key_package,
    });

    let verifiable_plaintext: VerifiableMlsPlaintext = insert_proposal_and_resign(
        backend,
        second_add_proposal,
        plaintext,
        original_plaintext,
        &alice_group,
    );

    let update_message_in = MlsMessageIn::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let unverified_message = bob_group
        .parse_message(update_message_in, backend)
        .expect("Could not parse message.");

    let err = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite modified public key in path.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::DuplicateIdentityAddProposal
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

/// ValSem101:
/// Add Proposal:
/// Signature public key in proposals must be unique among proposals
#[apply(ciphersuites_and_backends)]
fn test_valsem101(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for bob_and_charlie_share_keys in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveDifferentKey,
    ] {
        // 0. Initialize Alice
        let (_alice_credential_bundle, alice_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle("Alice".into(), ciphersuite, backend);

        // 1. Initialize Bob and Charlie
        let bob_signature_keypair: SignatureKeypair;
        let charlie_signature_keypair: SignatureKeypair;

        match bob_and_charlie_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let shared_signature_keypair =
                    SignatureKeypair::new(ciphersuite.signature_algorithm(), backend)
                        .expect("failed to generate signature keypair");

                bob_signature_keypair = shared_signature_keypair.clone();
                charlie_signature_keypair = shared_signature_keypair.clone();
            }
            KeyUniqueness::PositiveDifferentKey => {
                bob_signature_keypair =
                    SignatureKeypair::new(ciphersuite.signature_algorithm(), backend)
                        .expect("failed to generate signature keypair");
                charlie_signature_keypair =
                    SignatureKeypair::new(ciphersuite.signature_algorithm(), backend)
                        .expect("failed to generate signature keypair");
            }
        }

        let bob_credential_bundle =
            CredentialBundle::from_parts("Bob".into(), bob_signature_keypair);
        let charlie_credential_bundle =
            CredentialBundle::from_parts("Charlie".into(), charlie_signature_keypair);

        let bob_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &bob_credential_bundle, backend, vec![])
                .expect("failed to generate key package");
        let bob_key_package = bob_key_package_bundle.key_package().clone();
        let charlie_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &charlie_credential_bundle, backend, vec![])
                .expect("failed to generate key package");
        let charlie_key_package = charlie_key_package_bundle.key_package().clone();

        // 1. Alice creates a group and tries to add Bob and Charlie to it
        let res = create_group_with_members(
            alice_key_package_bundle,
            &[bob_key_package, charlie_key_package],
            backend,
        );

        match bob_and_charlie_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let err = res.expect_err("was able to add users with the same signature key!");
                assert_eq!(
                    err,
                    AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                        ProposalValidationError::DuplicateSignatureKeyAddProposal
                    ))
                );
            }
            KeyUniqueness::PositiveDifferentKey => {
                let _ = res.expect("failed to add users with different signature keypairs!");
            }
        }
    }

    // We now test if ValSem101 is also performed when a client receives a
    // commit.  Before we can test reception of (invalid) proposals, we set up a
    // new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(*PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We now have alice create a commit with an add proposal. Then we
    // artificially add another add proposal with a different identity,
    // different hpke public key, but the same signature public key.
    let (charlie_credential_bundle, charlie_key_package_bundle) =
        generate_credential_bundle_and_key_package_bundle("Charlie".into(), ciphersuite, backend);
    let charlie_key_package = charlie_key_package_bundle.key_package().clone();

    // Create the Commit with Add proposal.
    let serialized_update = alice_group
        .add_members(backend, &[charlie_key_package])
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    // Now let's create a second proposal and insert it into the commit. We want
    // a different hpke key, different identity, but the same signature key.
    let dave_credential_bundle =
        CredentialBundle::from_parts("Dave".into(), charlie_credential_bundle.key_pair());

    let mut kpb_payload = KeyPackageBundlePayload::from(charlie_key_package_bundle);
    kpb_payload.exchange_credential(dave_credential_bundle.credential().clone());
    let dave_key_package_bundle = kpb_payload
        .sign(backend, &dave_credential_bundle)
        .expect("error signing credential bundle");
    let second_add_proposal = Proposal::Add(AddProposal {
        key_package: dave_key_package_bundle.key_package().clone(),
    });

    let verifiable_plaintext: VerifiableMlsPlaintext = insert_proposal_and_resign(
        backend,
        second_add_proposal,
        plaintext,
        original_plaintext,
        &alice_group,
    );

    let update_message_in = MlsMessageIn::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let unverified_message = bob_group
        .parse_message(update_message_in, backend)
        .expect("Could not parse message.");

    let err = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite modified public key in path.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::DuplicateSignatureKeyAddProposal
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

/// ValSem102:
/// Add Proposal:
/// HPKE init key in proposals must be unique among proposals
#[apply(ciphersuites_and_backends)]
fn test_valsem102(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for bob_and_charlie_share_keys in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveDifferentKey,
    ] {
        // 0. Initialize Alice, Bob, and Charlie
        let (_alice_credential_bundle, alice_key_package_bundle) =
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
                    &[ciphersuite],
                    backend,
                    &bob_credential_bundle,
                    vec![],
                    shared_leaf_secret.clone(),
                )
                .expect("failed to generate key package");
                charlie_key_package_bundle = KeyPackageBundle::new_from_leaf_secret(
                    &[ciphersuite],
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

        // 1. Alice creates a group and tries to add Bob and Charlie to it
        let res = create_group_with_members(
            alice_key_package_bundle,
            &[bob_key_package, charlie_key_package],
            backend,
        );

        match bob_and_charlie_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let err = res.expect_err("was able to add users with the same HPKE init key!");
                assert_eq!(
                    err,
                    AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                        ProposalValidationError::DuplicatePublicKeyAddProposal
                    ))
                );
            }
            KeyUniqueness::PositiveDifferentKey => {
                let _ = res.expect("failed to add users with different HPKE init keys!");
            }
        }
    }

    // We now test if ValSem102 is also performed when a client receives a
    // commit.  Before we can test reception of (invalid) proposals, we set up a
    // new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(*PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We now have alice create a commit with an add proposal. Then we
    // artificially add another add proposal with a different identity,
    // different signature key, but the same hpke public key.
    let (_charlie_credential_bundle, charlie_key_package_bundle) =
        generate_credential_bundle_and_key_package_bundle("Charlie".into(), ciphersuite, backend);
    let charlie_key_package = charlie_key_package_bundle.key_package().clone();

    // Create the Commit with Add proposal.
    let serialized_update = alice_group
        .add_members(backend, &[charlie_key_package])
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    // Now let's create a second proposal and insert it into the commit. We want
    // a different signature key, different identity, but the same hpke public
    // key. The easiest way to get there is to re-sign the same KPB with a new
    // credential.
    let (dave_credential_bundle, _) =
        generate_credential_bundle_and_key_package_bundle("Dave".into(), ciphersuite, backend);
    let mut kpb_payload = KeyPackageBundlePayload::from(charlie_key_package_bundle);
    kpb_payload.exchange_credential(dave_credential_bundle.credential().clone());
    let dave_key_package_bundle = kpb_payload
        .sign(backend, &dave_credential_bundle)
        .expect("error signing credential bundle");
    let second_add_proposal = Proposal::Add(AddProposal {
        key_package: dave_key_package_bundle.key_package().clone(),
    });

    let verifiable_plaintext: VerifiableMlsPlaintext = insert_proposal_and_resign(
        backend,
        second_add_proposal,
        plaintext,
        original_plaintext,
        &alice_group,
    );

    let update_message_in = MlsMessageIn::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let unverified_message = bob_group
        .parse_message(update_message_in, backend)
        .expect("Could not parse message.");

    let err = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite modified public key in path.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::DuplicatePublicKeyAddProposal
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

/// ValSem103:
/// Add Proposal:
/// Identity in proposals must be unique among existing group members
#[apply(ciphersuites_and_backends)]
fn test_valsem103(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for (alice_id, bob_id) in [
        ("42", "42"), // Negative Case: Alice and Bob have same identity
        ("42", "24"), // Positive Case: Alice and Bob have different identity
    ] {
        // 0. Initialize Alice and Bob
        let (_alice_credential_bundle, alice_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle(
                alice_id.into(),
                ciphersuite,
                backend,
            );
        let (_bob_credential_bundle, bob_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle(bob_id.into(), ciphersuite, backend);
        let bob_key_package = bob_key_package_bundle.key_package().clone();

        // 1. Alice creates a group and tries to add Bob to it
        let res = create_group_with_members(alice_key_package_bundle, &[bob_key_package], backend);

        if alice_id == bob_id {
            // Negative Case: we should output an error
            let err = res.expect_err(
                "was able to add a user with the same identity as someone in the group!",
            );
            assert_eq!(
                err,
                AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                    ProposalValidationError::ExistingIdentityAddProposal
                ))
            );
        } else {
            // Positive Case: we should succeed
            let _ = res
                .expect("failed to add a user with an identity distinct from anyone in the group!");
        }
    }

    // We now test if ValSem103 is also performed when a client receives a
    // commit. Before we can test reception of (invalid) proposals, we set up a
    // new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(*PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We now have alice create a commit. Then we artificially add an Add
    // proposal with an existing identity (Bob).
    let (_bob_credential_bundle, bob_key_package_bundle) =
        generate_credential_bundle_and_key_package_bundle("Bob".into(), ciphersuite, backend);
    let bob_key_package = bob_key_package_bundle.key_package().clone();

    // Create the Commit.
    let serialized_update = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let add_proposal = Proposal::Add(AddProposal {
        key_package: bob_key_package,
    });

    // Artificially add a proposal trying to add (another) Bob.
    let verifiable_plaintext: VerifiableMlsPlaintext = insert_proposal_and_resign(
        backend,
        add_proposal,
        plaintext,
        original_plaintext,
        &alice_group,
    );

    let update_message_in = MlsMessageIn::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let unverified_message = bob_group
        .parse_message(update_message_in, backend)
        .expect("Could not parse message.");

    let err = bob_group
        .process_unverified_message(unverified_message, None, backend)
        .expect_err("Could process unverified message despite modified public key in path.");

    assert_eq!(
        err,
        UnverifiedMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::ExistingIdentityAddProposal
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

/// ValSem104:
/// Add Proposal:
/// Signature public key in proposals must be unique among existing group
/// members
#[apply(ciphersuites_and_backends)]
fn test_valsem104(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for alice_and_bob_share_keys in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveDifferentKey,
    ] {
        // 0. Initialize Alice and Bob
        let (alice_signature_keypair, bob_signature_keypair) = match alice_and_bob_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let shared_signature_keypair =
                    SignatureKeypair::new(ciphersuite.signature_algorithm(), backend)
                        .expect("failed to generate signature keypair");
                (
                    shared_signature_keypair.clone(),
                    shared_signature_keypair.clone(),
                )
            }
            KeyUniqueness::PositiveDifferentKey => (
                SignatureKeypair::new(ciphersuite.signature_algorithm(), backend)
                    .expect("failed to generate signature keypair"),
                SignatureKeypair::new(ciphersuite.signature_algorithm(), backend)
                    .expect("failed to generate signature keypair"),
            ),
        };

        let alice_credential_bundle =
            CredentialBundle::from_parts("Alice".into(), alice_signature_keypair);
        let alice_credential = alice_credential_bundle.credential().clone();
        backend
            .key_store()
            .store(
                &alice_credential
                    .signature_key()
                    .tls_serialize_detached()
                    .expect("Error serializing signature key."),
                &alice_credential_bundle,
            )
            .expect("An unexpected error occurred.");

        let bob_credential_bundle =
            CredentialBundle::from_parts("Bob".into(), bob_signature_keypair);

        let alice_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &alice_credential_bundle, backend, vec![])
                .expect("failed to generate key package");
        let alice_key_package = alice_key_package_bundle.key_package().clone();
        backend
            .key_store()
            .store(
                alice_key_package
                    .hash_ref(backend.crypto())
                    .expect("Could not hash KeyPackage.")
                    .value(),
                &alice_key_package_bundle,
            )
            .expect("An unexpected error occurred.");

        let bob_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &bob_credential_bundle, backend, vec![])
                .expect("failed to generate key package");
        let bob_key_package = bob_key_package_bundle.key_package().clone();

        // 1. Alice creates a group and tries to add Bob to it
        let res = create_group_with_members(alice_key_package_bundle, &[bob_key_package], backend);

        match alice_and_bob_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let err = res
                    .expect_err("was able to add user with same signature key as a group member!");
                assert_eq!(
                    err,
                    AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                        ProposalValidationError::ExistingSignatureKeyAddProposal
                    ))
                );
            }
            KeyUniqueness::PositiveDifferentKey => {
                let _ = res.expect("failed to add user with different signature keypair!");
            }
        }
    }

    // TODO #525: Add test for incoming proposals.
}

/// ValSem105:
/// Add Proposal:
/// HPKE init key in proposals must be unique among existing group members
#[apply(ciphersuites_and_backends)]
fn test_valsem105(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for alice_and_bob_share_keys in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveDifferentKey,
    ] {
        // 0. Initialize Alice and Bob
        let (alice_credential_bundle, mut alice_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle("Alice".into(), ciphersuite, backend);
        let (bob_credential_bundle, mut bob_key_package_bundle) =
            generate_credential_bundle_and_key_package_bundle("Bob".into(), ciphersuite, backend);

        match alice_and_bob_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let shared_leaf_secret = Secret::random(
                    alice_key_package_bundle.key_package().ciphersuite(),
                    backend,
                    alice_key_package_bundle.key_package().protocol_version(),
                )
                .expect("failed to generate random leaf secret");

                alice_key_package_bundle = KeyPackageBundle::new_from_leaf_secret(
                    &[ciphersuite],
                    backend,
                    &alice_credential_bundle,
                    vec![],
                    shared_leaf_secret.clone(),
                )
                .expect("failed to generate key package");
                bob_key_package_bundle = KeyPackageBundle::new_from_leaf_secret(
                    &[ciphersuite],
                    backend,
                    &bob_credential_bundle,
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

        let alice_key_package = alice_key_package_bundle.key_package().clone();
        backend
            .key_store()
            .store(
                alice_key_package
                    .hash_ref(backend.crypto())
                    .expect("Could not hash KeyPackage.")
                    .value(),
                &alice_key_package_bundle,
            )
            .expect("An unexpected error occurred.");
        let bob_key_package = bob_key_package_bundle.key_package().clone();

        // 1. Alice creates a group and tries to add Bob to it
        let res = create_group_with_members(alice_key_package_bundle, &[bob_key_package], backend);

        match alice_and_bob_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let err =
                    res.expect_err("was able to add user with same HPKE init key as group member!");
                assert_eq!(
                    err,
                    AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                        ProposalValidationError::ExistingPublicKeyAddProposal
                    ))
                );
            }
            KeyUniqueness::PositiveDifferentKey => {
                let _ = res.expect("failed to add user with different HPKE init key!");
            }
        }
    }

    // TODO #525: Add test for incoming proposals.
}
