//! This module tests the validation of proposals as defined in
//! https://openmls.tech/book/message_validation.html#semantic-validation-of-proposals-covered-by-a-commit

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::Ciphersuite, OpenMlsCryptoProvider};

use rstest::*;
use rstest_reuse::{self, *};
use tls_codec::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::hash_ref::ProposalRef,
    credentials::*,
    framing::{
        mls_content::FramedContentBody, MlsMessageIn, MlsMessageOut, ProcessedMessageContent,
        ProtocolMessage, PublicMessage, Sender,
    },
    group::{config::CryptoConfig, errors::*, *},
    key_packages::*,
    messages::{
        proposals::{AddProposal, Proposal, ProposalOrRef, RemoveProposal, UpdateProposal},
        Welcome,
    },
    treesync::errors::ApplyUpdatePathError,
    versions::ProtocolVersion,
};

use super::utils::{generate_credential_bundle, generate_key_package, resign_message};

/// Helper function to generate and output CredentialBundle and KeyPackage
fn generate_credential_bundle_and_key_package(
    identity: Vec<u8>,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (CredentialBundle, KeyPackage) {
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

    let key_package = generate_key_package(&[ciphersuite], &credential, vec![], backend)
        .expect("Failed to generate KeyPackage.");

    (credential_bundle, key_package)
}

/// Helper function to create a group and try to add `members` to it.
fn create_group_with_members(
    alice_key_package: KeyPackage,
    member_key_packages: &[KeyPackage],
    backend: &impl OpenMlsCryptoProvider,
) -> Result<(MlsMessageIn, Welcome), AddMembersError> {
    let mut alice_group = MlsGroup::new_with_group_id(
        backend,
        &MlsGroupConfig::default(),
        GroupId::from_slice(b"Alice's Friends"),
        alice_key_package,
    )
    .expect("An unexpected error occurred.");

    alice_group.add_members(backend, member_key_packages).map(
        |(msg, welcome): (MlsMessageOut, MlsMessageOut)| {
            (
                msg.into(),
                welcome.into_welcome().expect("Unexpected message type."),
            )
        },
    )
}

struct ProposalValidationTestSetup {
    alice_group: MlsGroup,
    bob_group: MlsGroup,
}

// Creates a standalone group
fn new_test_group(
    identity: &str,
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> MlsGroup {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let credential = generate_credential_bundle(
        identity.into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .unwrap();

    // Generate KeyPackages
    let key_package = generate_key_package(&[ciphersuite], &credential, vec![], backend).unwrap();

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .build();

    MlsGroup::new_with_group_id(backend, &mls_group_config, group_id, key_package).unwrap()
}

// Validation test setup
fn validation_test_setup(
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> ProposalValidationTestSetup {
    // === Alice creates a group ===
    let mut alice_group = new_test_group("Alice", wire_format_policy, ciphersuite, backend);

    let bob_credential = generate_credential_bundle(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let bob_key_package = generate_key_package(&[ciphersuite], &bob_credential, vec![], backend)
        .expect("An unexpected error occurred.");

    let (_message, welcome) = alice_group
        .add_members(backend, &[bob_key_package])
        .expect("error adding Bob to group");

    alice_group
        .merge_pending_commit()
        .expect("error merging pending commit");

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format_policy(wire_format_policy)
        .build();

    let bob_group = MlsGroup::new_from_welcome(
        backend,
        &mls_group_config,
        welcome.into_welcome().expect("Unexpected message type."),
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
    mut proposal_or_ref: Vec<ProposalOrRef>,
    mut plaintext: PublicMessage,
    original_plaintext: &PublicMessage,
    committer_group: &MlsGroup,
) -> PublicMessage {
    let mut commit_content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    commit_content.proposals.append(&mut proposal_or_ref);

    plaintext.set_content(FramedContentBody::Commit(commit_content));

    let mut signed_plaintext =
        resign_message(committer_group, plaintext, original_plaintext, backend);

    let membership_key = committer_group.group().message_secrets().membership_key();

    signed_plaintext
        .set_membership_tag(backend, membership_key)
        .expect("error refreshing membership tag");

    signed_plaintext
}

enum KeyUniqueness {
    /// Positive Case: the proposals have different keys.
    PositiveDifferentKey,
    /// Negative Case: the proposals have the same key.
    NegativeSameKey,
    /// Positive Case: the proposals have the same key but it has remove so its valid
    PositiveSameKeyWithRemove,
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
        let (_, alice_key_package) =
            generate_credential_bundle_and_key_package("Alice".into(), ciphersuite, backend);

        // 0. Initialize Bob and Charlie
        let (_bob_credential_bundle, bob_key_package_bundle) =
            generate_credential_bundle_and_key_package(bob_id.into(), ciphersuite, backend);
        let bob_key_package = bob_key_package_bundle.clone();

        let (_charlie_credential_bundle, charlie_key_package_bundle) =
            generate_credential_bundle_and_key_package(charlie_id.into(), ciphersuite, backend);
        let charlie_key_package = charlie_key_package_bundle.clone();

        // 1. Alice creates a group and tries to add Bob and Charlie to it
        let res = create_group_with_members(
            alice_key_package,
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
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We now have alice create a commit with an add proposal. Then we
    // artificially add another add proposal with the same identity.
    let (_charlie_credential_bundle, charlie_key_package_bundle) =
        generate_credential_bundle_and_key_package("Charlie".into(), ciphersuite, backend);
    let charlie_key_package = charlie_key_package_bundle;

    // Create the Commit with Add proposal.
    let serialized_update = alice_group
        .add_members(backend, &[charlie_key_package])
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    // Now let's create a second proposal and insert it into the commit. We want
    // a different signature key, different hpke public key, but the same
    // identity.
    let (_charlie_credential_bundle, charlie_key_package_bundle) =
        generate_credential_bundle_and_key_package("Charlie".into(), ciphersuite, backend);
    let charlie_key_package = charlie_key_package_bundle;
    let second_add_proposal = Proposal::Add(AddProposal {
        key_package: charlie_key_package,
    });

    let verifiable_plaintext = insert_proposal_and_resign(
        backend,
        vec![ProposalOrRef::Proposal(second_add_proposal)],
        plaintext,
        &original_plaintext,
        &alice_group,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(backend, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::DuplicateIdentityAddProposal
        ))
    );

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(backend, original_update_plaintext.into())
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
        let (_, alice_key_package) =
            generate_credential_bundle_and_key_package("Alice".into(), ciphersuite, backend);

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
            KeyUniqueness::PositiveSameKeyWithRemove => unreachable!(),
        }

        let bob_credential_bundle =
            CredentialBundle::from_parts("Bob".into(), bob_signature_keypair);
        let charlie_credential_bundle =
            CredentialBundle::from_parts("Charlie".into(), charlie_signature_keypair);

        let bob_key_package = KeyPackage::builder()
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                backend,
                &bob_credential_bundle,
            )
            .unwrap();
        let charlie_key_package = KeyPackage::builder()
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                backend,
                &charlie_credential_bundle,
            )
            .unwrap();

        // 1. Alice creates a group and tries to add Bob and Charlie to it
        let res = create_group_with_members(
            alice_key_package,
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
            KeyUniqueness::PositiveSameKeyWithRemove => unreachable!(),
        }
    }

    // We now test if ValSem101 is also performed when a client receives a
    // commit.  Before we can test reception of (invalid) proposals, we set up a
    // new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We now have alice create a commit with an add proposal. Then we
    // artificially add another add proposal with a different identity,
    // different hpke public key, but the same signature public key.
    let (charlie_credential_bundle, charlie_key_package) =
        generate_credential_bundle_and_key_package("Charlie".into(), ciphersuite, backend);

    // Create the Commit with Add proposal.
    let serialized_update = alice_group
        .add_members(backend, &[charlie_key_package])
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    // Now let's create a second proposal and insert it into the commit. We want
    // a different hpke key, different identity, but the same signature key.
    let dave_credential_bundle =
        CredentialBundle::from_parts("Dave".into(), charlie_credential_bundle.key_pair());

    let dave_key_package = KeyPackage::builder()
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            backend,
            &dave_credential_bundle,
        )
        .unwrap();
    let second_add_proposal = Proposal::Add(AddProposal {
        key_package: dave_key_package,
    });

    let verifiable_plaintext = insert_proposal_and_resign(
        backend,
        vec![ProposalOrRef::Proposal(second_add_proposal)],
        plaintext,
        &original_plaintext,
        &alice_group,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(backend, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::DuplicateSignatureKeyAddProposal
        ))
    );

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(backend, original_update_plaintext.into())
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
        let (_, alice_key_package) =
            generate_credential_bundle_and_key_package("Alice".into(), ciphersuite, backend);
        let (bob_credential_bundle, mut bob_key_package) =
            generate_credential_bundle_and_key_package("Bob".into(), ciphersuite, backend);
        let (_, charlie_key_package) =
            generate_credential_bundle_and_key_package("Charlie".into(), ciphersuite, backend);

        match bob_and_charlie_share_keys {
            KeyUniqueness::NegativeSameKey => {
                // Create a new key package for bob with the init key from Charlie.
                bob_key_package = KeyPackage::new_from_keys_test(
                    CryptoConfig {
                        ciphersuite,
                        version: ProtocolVersion::default(),
                    },
                    backend,
                    &bob_credential_bundle,
                    vec![],
                    vec![],
                    charlie_key_package.hpke_init_key().as_slice().to_vec(),
                )
                .unwrap();
            }
            KeyUniqueness::PositiveDifferentKey => {
                // don't need to do anything since the keys are already
                // different.
            }
            KeyUniqueness::PositiveSameKeyWithRemove => unreachable!(),
        }

        // 1. Alice creates a group and tries to add Bob and Charlie to it
        let res = create_group_with_members(
            alice_key_package,
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
            KeyUniqueness::PositiveSameKeyWithRemove => unreachable!(),
        }
    }

    // We now test if ValSem102 is also performed when a client receives a
    // commit.  Before we can test reception of (invalid) proposals, we set up a
    // new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We now have alice create a commit with an add proposal. Then we
    // artificially add another add proposal with a different identity,
    // different signature key, but the same hpke public key.
    let (_charlie_credential_bundle, charlie_key_package) =
        generate_credential_bundle_and_key_package("Charlie".into(), ciphersuite, backend);

    // Create the Commit with Add proposal.
    let serialized_update = alice_group
        .add_members(backend, &[charlie_key_package.clone()])
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    // Now let's create a second proposal and insert it into the commit. We want
    // a different signature key, different identity, but the same hpke public
    // key. The easiest way to get there is to re-sign the same KPB with a new
    // credential.
    let (dave_credential_bundle, _) =
        generate_credential_bundle_and_key_package("Dave".into(), ciphersuite, backend);
    let dave_key_package = charlie_key_package.resign(backend, &dave_credential_bundle);
    let second_add_proposal = Proposal::Add(AddProposal {
        key_package: dave_key_package,
    });

    let verifiable_plaintext = insert_proposal_and_resign(
        backend,
        vec![ProposalOrRef::Proposal(second_add_proposal)],
        plaintext,
        &original_plaintext,
        &alice_group,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(backend, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::DuplicatePublicKeyAddProposal
        ))
    );

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(backend, original_update_plaintext.into())
        .expect("Unexpected error.");
}

/// ValSem103:
/// Add Proposal:
/// Identity in proposals must be unique among existing group members
#[apply(ciphersuites_and_backends)]
fn test_valsem103(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    for alice_and_bob_share_identities in [
        KeyUniqueness::PositiveDifferentKey,
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveSameKeyWithRemove,
    ] {
        let (alice_id, bob_id, target_id) = match alice_and_bob_share_identities {
            KeyUniqueness::NegativeSameKey => ("Alice", "Bob", "Alice"), // Negative Case: Alice and Bob have same identity
            KeyUniqueness::PositiveDifferentKey => ("Alice", "Bob", "Charlie"), // Positive Case: Alice and Bob have different identity
            KeyUniqueness::PositiveSameKeyWithRemove => ("Alice", "Bob", "Bob"), // Positive Case: Alice and Bob has same keys but Bob has a remove proposal
        };

        // 0. Initialize Alice and Bob
        let (_, alice_key_package) =
            generate_credential_bundle_and_key_package(alice_id.into(), ciphersuite, backend);
        let (_bob_credential_bundle, bob_key_package) =
            generate_credential_bundle_and_key_package(bob_id.into(), ciphersuite, backend);
        let (_target_credential_bundle, target_key_package) =
            generate_credential_bundle_and_key_package(target_id.into(), ciphersuite, backend);

        // 1. Alice creates a group and tries to add Bob to it
        let mut alice_group = MlsGroup::new_with_group_id(
            backend,
            &MlsGroupConfig::default(),
            GroupId::from_slice(b"Alice's Friends"),
            alice_key_package,
        )
        .unwrap();

        match alice_and_bob_share_identities {
            KeyUniqueness::NegativeSameKey => {
                // Negative Case: we should output an error
                let err = alice_group
                    .add_members(backend, &[bob_key_package, target_key_package])
                    .expect_err(
                        "was able to add a user with the same identity as someone in the group!",
                    );
                assert_eq!(
                    err,
                    AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                        ProposalValidationError::ExistingIdentityAddProposal
                    ))
                );
            }
            KeyUniqueness::PositiveDifferentKey => {
                // Positive Case: we should succeed
                alice_group
                    .add_members(backend, &[bob_key_package, target_key_package])
                    .expect(
                        "failed to add a user with an identity distinct from anyone in the group!",
                    );
            }
            KeyUniqueness::PositiveSameKeyWithRemove => {
                // Positice Case: we should succeed
                // Find Bob's index in the group
                alice_group
                    .add_members(backend, &[bob_key_package])
                    .unwrap();
                alice_group.merge_pending_commit().unwrap();
                let bob_index = alice_group
                    .members()
                    .find_map(|member| {
                        if member.identity == target_id.as_bytes() {
                            Some(member.index)
                        } else {
                            None
                        }
                    })
                    .unwrap();
                alice_group
                    .propose_remove_member(backend, bob_index)
                    .unwrap();
                alice_group
                    .add_members(backend, &[target_key_package])
                    .expect(
                    "failed to add a user with the same identity as someone in the group (with a remove proposal)!",
                );
            }
        }
    }

    for alice_and_bob_share_identities in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveSameKeyWithRemove,
    ] {
        // We now test if ValSem103 is also performed when a client receives a
        // commit. Before we can test reception of (invalid) proposals, we set up a
        // new group with Alice and Bob.
        let ProposalValidationTestSetup {
            mut alice_group,
            mut bob_group,
        } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

        // We now have alice create a commit. Then we artificially add an Add
        // proposal with an existing identity (Bob).
        let (_bob_credential_bundle, bob_key_package) =
            generate_credential_bundle_and_key_package("Bob".into(), ciphersuite, backend);

        // Create the Commit.
        let serialized_update = alice_group
            .self_update(backend, None)
            .expect("Error creating self-update")
            .tls_serialize_detached()
            .expect("Could not serialize message.");

        let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.")
            .into_plaintext()
            .expect("Message was not a plaintext.");
        // Keep the original plaintext for positive test later.
        let original_plaintext = plaintext.clone();

        let proposals = match alice_and_bob_share_identities {
            KeyUniqueness::NegativeSameKey => {
                let add_proposal = ProposalOrRef::Proposal(Proposal::Add(AddProposal {
                    key_package: bob_key_package,
                }));
                vec![add_proposal]
            }
            KeyUniqueness::PositiveSameKeyWithRemove => {
                let add_proposal = ProposalOrRef::Proposal(Proposal::Add(AddProposal {
                    key_package: bob_key_package,
                }));
                // find bob's index
                let bob_index = alice_group
                    .members()
                    .find_map(|member| {
                        if member.identity == b"Bob" {
                            Some(member.index)
                        } else {
                            None
                        }
                    })
                    .unwrap();
                let remove_proposal = ProposalOrRef::Proposal(Proposal::Remove(RemoveProposal {
                    removed: bob_index,
                }));
                vec![add_proposal, remove_proposal]
            }
            KeyUniqueness::PositiveDifferentKey => unreachable!(),
        };

        // Artificially add a proposal trying to add (another) Bob.
        let verifiable_plaintext = insert_proposal_and_resign(
            backend,
            proposals,
            plaintext,
            &original_plaintext,
            &alice_group,
        );

        match alice_and_bob_share_identities {
            KeyUniqueness::NegativeSameKey => {
                // Have bob process the resulting plaintext
                let err = bob_group
                    .process_message(backend, verifiable_plaintext.into())
                    .expect_err("Could process message despite modified public key in path.");

                assert_eq!(
                    err,
                    ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                        ProposalValidationError::ExistingIdentityAddProposal
                    ))
                );
            }
            KeyUniqueness::PositiveSameKeyWithRemove => {
                bob_group
                    .process_message(backend, verifiable_plaintext.into())
                    .expect(
                        "Could not process message despite having a remove proposal in the commit",
                    );
            }
            KeyUniqueness::PositiveDifferentKey => unreachable!(),
        }

        let original_update_plaintext =
            MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
                .expect("Could not deserialize message.")
                .into_plaintext()
                .expect("Unexpected message type.");

        // Positive case
        bob_group
            .process_message(backend, original_update_plaintext.into())
            .expect("Unexpected error.");
    }
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
        KeyUniqueness::PositiveSameKeyWithRemove,
    ] {
        // 0. Initialize Alice and Bob
        let new_kp = || SignatureKeypair::new(ciphersuite.signature_algorithm(), backend).unwrap();
        let shared_signature_keypair = new_kp();
        let [alice_credential_bundle, bob_credential_bundle, target_credential_bundle] =
            match alice_and_bob_share_keys {
                KeyUniqueness::NegativeSameKey => [
                    ("Alice", shared_signature_keypair.clone()),
                    ("Bob", new_kp()),
                    ("Charlie", shared_signature_keypair.clone()),
                ],
                KeyUniqueness::PositiveDifferentKey => [
                    ("Alice", new_kp()),
                    ("Bob", new_kp()),
                    ("Charlie", new_kp()),
                ],
                KeyUniqueness::PositiveSameKeyWithRemove => [
                    ("Alice", new_kp()),
                    ("Bob", shared_signature_keypair.clone()),
                    ("Charlie", shared_signature_keypair.clone()),
                ],
            }
            .map(|(name, keypair)| CredentialBundle::from_parts(name.into(), keypair));

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

        let alice_key_package = KeyPackage::builder()
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                backend,
                &alice_credential_bundle,
            )
            .unwrap();

        let bob_key_package = KeyPackage::builder()
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                backend,
                &bob_credential_bundle,
            )
            .unwrap();

        let target_key_package = KeyPackage::builder()
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                backend,
                &target_credential_bundle,
            )
            .unwrap();

        // 1. Alice creates a group and tries to add Bob to it
        let mut alice_group = MlsGroup::new_with_group_id(
            backend,
            &MlsGroupConfig::default(),
            GroupId::from_slice(b"Alice's Friends"),
            alice_key_package,
        )
        .unwrap();

        match alice_and_bob_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let err = alice_group
                    .add_members(backend, &[bob_key_package, target_key_package])
                    .expect_err("was able to add user with same signature key as a group member!");
                assert_eq!(
                    err,
                    AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                        ProposalValidationError::ExistingSignatureKeyAddProposal
                    ))
                );
            }
            KeyUniqueness::PositiveDifferentKey => {
                alice_group
                    .add_members(backend, &[bob_key_package, target_key_package])
                    .expect("failed to add user with different signature keypair!");
            }
            KeyUniqueness::PositiveSameKeyWithRemove => {
                alice_group
                    .add_members(backend, &[bob_key_package.clone()])
                    .unwrap();
                alice_group.merge_pending_commit().unwrap();
                let bob_index = alice_group
                    .members()
                    .find_map(|member| {
                        if member.identity == b"Bob" {
                            Some(member.index)
                        } else {
                            None
                        }
                    })
                    .unwrap();
                alice_group
                    .propose_remove_member(backend, bob_index)
                    .unwrap();
                alice_group
                    .add_members(backend, &[target_key_package])
                    .expect(
                    "failed to add a user with the same identity as someone in the group (with a remove proposal)!",
                );
            }
        }
    }

    for alice_and_bob_share_keys in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveSameKeyWithRemove,
    ] {
        // Before we can test reception of (invalid) proposals, we set up a new
        // group with Alice and Bob.
        let ProposalValidationTestSetup {
            mut alice_group,
            mut bob_group,
        } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

        // We now have alice create a commit. Then we artificially add an Add
        // proposal with a different identity, but with the same signature public
        // key as Bob.
        // Create the Commit.
        let serialized_update = alice_group
            .self_update(backend, None)
            .expect("Error creating self-update")
            .tls_serialize_detached()
            .expect("Could not serialize message.");

        let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.")
            .into_plaintext()
            .expect("Message was not a plaintext.");

        // Keep the original plaintext for positive test later.
        let original_plaintext = plaintext.clone();

        let bob_credential_bundle = backend
            .key_store()
            .read::<CredentialBundle>(
                &bob_group
                    .credential()
                    .expect("error retrieving credential from group")
                    .signature_key()
                    .tls_serialize_detached()
                    .expect("Error serializing signature key."),
            )
            .expect("An unexpected error occurred.");

        // Create the credential bundle using a copy of Bob's key pair.
        let dave_credential_bundle =
            CredentialBundle::from_parts("Dave".into(), bob_credential_bundle.key_pair());

        let dave_key_package = KeyPackage::builder()
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                backend,
                &dave_credential_bundle,
            )
            .unwrap();

        let proposals = match alice_and_bob_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let add_proposal = ProposalOrRef::Proposal(Proposal::Add(AddProposal {
                    key_package: dave_key_package.clone(),
                }));
                vec![add_proposal]
            }
            KeyUniqueness::PositiveSameKeyWithRemove => {
                let add_proposal = ProposalOrRef::Proposal(Proposal::Add(AddProposal {
                    key_package: dave_key_package.clone(),
                }));
                // find bob's index
                let bob_index = alice_group
                    .members()
                    .find_map(|member| {
                        if member.identity == b"Bob" {
                            Some(member.index)
                        } else {
                            None
                        }
                    })
                    .unwrap();
                let remove_proposal = ProposalOrRef::Proposal(Proposal::Remove(RemoveProposal {
                    removed: bob_index,
                }));
                vec![add_proposal, remove_proposal]
            }
            KeyUniqueness::PositiveDifferentKey => unreachable!(),
        };

        // Artificially add a proposal trying to add (another) Bob.
        let verifiable_plaintext = insert_proposal_and_resign(
            backend,
            proposals,
            plaintext,
            &original_plaintext,
            &alice_group,
        );

        match alice_and_bob_share_keys {
            KeyUniqueness::NegativeSameKey => {
                // Have bob process the resulting plaintext
                let err = bob_group
                    .process_message(backend, verifiable_plaintext.into())
                    .expect_err("Could process message despite modified public key in path.");

                assert_eq!(
                    err,
                    ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                        ProposalValidationError::ExistingSignatureKeyAddProposal
                    ))
                );
            }
            KeyUniqueness::PositiveSameKeyWithRemove => {
                bob_group
                    .process_message(backend, verifiable_plaintext.into())
                    .expect(
                        "Could not process message despite having a remove proposal in the commit",
                    );
            }
            KeyUniqueness::PositiveDifferentKey => unreachable!(),
        }

        let original_update_plaintext =
            MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
                .expect("Could not deserialize message.");

        // Positive case
        bob_group
            .process_message(backend, original_update_plaintext.into())
            .expect("Unexpected error.");
    }
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
        let (_, alice_key_package) =
            generate_credential_bundle_and_key_package("Alice".into(), ciphersuite, backend);
        let (bob_credential_bundle, mut bob_key_package) =
            generate_credential_bundle_and_key_package("Bob".into(), ciphersuite, backend);

        match alice_and_bob_share_keys {
            KeyUniqueness::NegativeSameKey => {
                // Create a new key package for bob with the init key from Charlie.
                bob_key_package = KeyPackage::new_from_keys_test(
                    CryptoConfig {
                        ciphersuite,
                        version: ProtocolVersion::default(),
                    },
                    backend,
                    &bob_credential_bundle,
                    vec![],
                    vec![],
                    alice_key_package.hpke_init_key().as_slice().to_vec(),
                )
                .unwrap();
            }
            KeyUniqueness::PositiveDifferentKey => {
                // don't need to do anything since the keys are already
                // different.
            }
            KeyUniqueness::PositiveSameKeyWithRemove => unreachable!(),
        }

        // 1. Alice creates a group and tries to add Bob to it
        let res = create_group_with_members(alice_key_package, &[bob_key_package], backend);

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
            KeyUniqueness::PositiveSameKeyWithRemove => unreachable!(),
        }
    }

    // Before we can test reception of (invalid) proposals, we set up a new
    // group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We now have alice create a commit. Then we artificially add an Add
    // proposal with an existing HPKE public key.

    // Create the Commit.
    let serialized_update = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    // We now pull bob's public key from his leaf.
    let bob_public_key = bob_group
        .group()
        .treesync()
        .own_leaf_node()
        .expect("No own leaf")
        .encryption_key()
        .clone();

    // Generate fresh key material for Dave.
    let (dave_credential_bundle, _) =
        generate_credential_bundle_and_key_package("Dave".into(), ciphersuite, backend);

    // Insert Bob's public key into Dave's KPB and resign.
    // XXX[FK]: Do we delete the private key because there's only one?
    let dave_key_package = KeyPackage::new_from_keys_test(
        CryptoConfig {
            ciphersuite,
            version: ProtocolVersion::default(),
        },
        backend,
        &dave_credential_bundle,
        vec![],
        vec![],
        bob_public_key.into(),
    )
    .unwrap();

    // Use the resulting KP to create an Add proposal.
    let add_proposal = Proposal::Add(AddProposal {
        key_package: dave_key_package,
    });

    // Artificially add a proposal trying to add someone with an existing HPKE
    // public key.
    let verifiable_plaintext = insert_proposal_and_resign(
        backend,
        vec![ProposalOrRef::Proposal(add_proposal)],
        plaintext,
        &original_plaintext,
        &alice_group,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(backend, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::ExistingPublicKeyAddProposal
        ))
    );

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(backend, original_update_plaintext.into())
        .expect("Unexpected error.");
}

#[derive(Debug)]
enum KeyPackageTestVersion {
    WrongCiphersuite,
    UnsupportedVersion,
    UnsupportedCiphersuite,
    ValidTestCase,
}

enum ProposalInclusion {
    ByValue,
    ByReference,
}

/// ValSem106:
/// Add Proposal:
/// Required capabilities
#[apply(ciphersuites_and_backends)]
fn test_valsem106(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Let's set up a group with Alice and Bob as members.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // Required capabilities validation includes two types of checks on the
    // capabilities of the `KeyPackage` in the Add proposal: One against the
    // ciphersuite and the version of the group and one against a potential
    // RequiredCapabilities extension present in the group.

    // Since RequiredCapabilities can only contain non-MTI extensions and
    // proposals and OpenMLS doesn't support any of those, we can't test
    // conformance of a given KeyPackage with those yet.

    // We now create a bunch of KeyPackages for Charly:
    // - one that matches all requirements (positive test)
    // - one that doesn't support the version of the group
    // - one that doesn't support the ciphersuite of the group

    // We then subsequently try to have Alice commit them, once by value and
    // once by reference.

    // We then have Alice create a self-update commit and insert the Add
    // proposal with the relevant KeyPackage artificially afterwards, so that we
    // can have Bob try to process it.

    // We begin with the creation of KeyPackages
    for key_package_version in [
        KeyPackageTestVersion::WrongCiphersuite,
        KeyPackageTestVersion::UnsupportedVersion,
        KeyPackageTestVersion::UnsupportedCiphersuite,
        KeyPackageTestVersion::ValidTestCase,
    ] {
        let (charlie_credential_bundle, mut charlie_key_package) =
            generate_credential_bundle_and_key_package("Charlie".into(), ciphersuite, backend);

        // Let's just pick a ciphersuite that's not the one we're testing right now.
        let wrong_ciphersuite = match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            }
            _ => Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        };
        match key_package_version {
            KeyPackageTestVersion::WrongCiphersuite => {
                charlie_key_package.set_ciphersuite(wrong_ciphersuite)
            }
            KeyPackageTestVersion::UnsupportedVersion => {
                let mut new_leaf_node = charlie_key_package.leaf_node().clone();
                new_leaf_node
                    .capabilities_mut()
                    .set_versions(vec![ProtocolVersion::Mls10Draft11]);
                charlie_key_package.set_leaf_node(new_leaf_node);
            }
            KeyPackageTestVersion::UnsupportedCiphersuite => {
                let mut new_leaf_node = charlie_key_package.leaf_node().clone();
                new_leaf_node.capabilities_mut().set_ciphersuites(vec![
                    Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
                ]);
                charlie_key_package.set_leaf_node(new_leaf_node);
            }
            KeyPackageTestVersion::ValidTestCase => (),
        };
        let test_kp = charlie_key_package.resign(backend, &charlie_credential_bundle);

        // Try to have Alice commit an Add with the test KeyPackage.
        for proposal_inclusion in [ProposalInclusion::ByReference, ProposalInclusion::ByValue] {
            match proposal_inclusion {
                ProposalInclusion::ByReference => {
                    let _proposal = alice_group
                        .propose_add_member(backend, &test_kp)
                        .expect("error proposing test add");

                    let result = alice_group.commit_to_pending_proposals(backend);

                    // The error types differ, so we have to check the error inside the `match`.
                    match key_package_version {
                        KeyPackageTestVersion::ValidTestCase => {
                            assert!(result.is_ok())
                        }
                        _ => {
                            assert_eq!(
                                result.expect_err(
                                    "no error when committing add with key package with insufficient capabilities",
                                ),
                                CommitToPendingProposalsError::CreateCommitError(
                                    CreateCommitError::ProposalValidationError(
                                        ProposalValidationError::InsufficientCapabilities
                                    )
                                )
                            )
                        }
                    }
                }
                ProposalInclusion::ByValue => {
                    let result = alice_group
                        .add_members(backend, &[test_kp.clone()])
                        .map(|(msg, welcome)| (msg, Some(welcome)));

                    match key_package_version {
                        KeyPackageTestVersion::ValidTestCase => {
                            assert!(result.is_ok())
                        }
                        _ => {
                            assert_eq!(
                                result.expect_err(
                                    "no error when committing add with key package with insufficient capabilities",
                                ),
                                AddMembersError::CreateCommitError(
                                    CreateCommitError::ProposalValidationError(
                                        ProposalValidationError::InsufficientCapabilities
                                    )
                                )
                            )
                        }
                    }
                }
            };
            // Reset alice's group state for the next test case.
            alice_group.clear_pending_commit();
        }
        // Now we create a valid commit and add the proposal afterwards. Once by value, once by reference.
        alice_group.clear_pending_proposals();

        // Create the Commit.
        let serialized_update = alice_group
            .self_update(backend, None)
            .expect("Error creating self-update")
            .tls_serialize_detached()
            .expect("Could not serialize message.");

        let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.")
            .into_plaintext()
            .expect("Message was not a plaintext.");

        // Keep the original plaintext for positive test later.
        let original_plaintext = plaintext.clone();

        // Create a proposal from the test KPB.
        let add_proposal = Proposal::Add(AddProposal {
            key_package: test_kp,
        });

        for proposal_inclusion in [ProposalInclusion::ByValue, ProposalInclusion::ByReference] {
            let proposal_or_ref = match proposal_inclusion {
                ProposalInclusion::ByValue => ProposalOrRef::Proposal(add_proposal.clone()),
                ProposalInclusion::ByReference => ProposalOrRef::Reference(
                    ProposalRef::from_proposal(ciphersuite, backend, &add_proposal)
                        .expect("error creating hash reference"),
                ),
            };
            // Artificially add the proposal.
            let verifiable_plaintext = insert_proposal_and_resign(
                backend,
                vec![proposal_or_ref],
                plaintext.clone(),
                &original_plaintext,
                &alice_group,
            );

            let update_message_in = ProtocolMessage::from(verifiable_plaintext);

            // If we're including by reference, we have to sneak the proposal
            // into Bob's queue.
            if matches!(proposal_inclusion, ProposalInclusion::ByReference) {
                bob_group.store_pending_proposal(
                    QueuedProposal::from_proposal_and_sender(
                        ciphersuite,
                        backend,
                        add_proposal.clone(),
                        &Sender::build_member(alice_group.own_leaf_index()),
                    )
                    .expect("error creating queued proposal"),
                )
            }

            // Have bob process the resulting plaintext
            let err = bob_group
                .process_message(backend, update_message_in)
                .expect_err("Could process message despite injected add proposal.");

            let expected_error = match key_package_version {
                // We get an error even if the key package is valid. This is
                // because Bob would expect the encrypted path in the commit to
                // be longer due to the included Add proposal. Since we added
                // the Add artificially, we thus have a path length mismatch.
                KeyPackageTestVersion::ValidTestCase => ProcessMessageError::InvalidCommit(
                    StageCommitError::UpdatePathError(ApplyUpdatePathError::PathLengthMismatch),
                ),
                _ => ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                    ProposalValidationError::InsufficientCapabilities,
                )),
            };

            assert_eq!(err, expected_error);

            let original_update_plaintext =
                MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
                    .expect("Could not deserialize message.");

            // Positive case
            bob_group
                .process_message(backend, original_update_plaintext.into())
                .expect("Unexpected error.");
        }

        alice_group.clear_pending_commit();
    }
}

/// ValSem107:
/// Remove Proposal:
/// Removed member must be unique among proposals
#[apply(ciphersuites_and_backends)]
fn test_valsem107(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Before we can test creation of (invalid) proposals, we set up a new group
    // with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We first try to make Alice create a commit with two remove proposals for
    // Bob.

    // There are two ways in which we could use the MlsGroup API to commit to
    // remove proposals: Create the proposals and then commit them manually or
    // use the `remove_members` endpoint with two times the same KeyPackageRef
    // as input. We first create both commits and then make sure they look as
    // expected.
    let bob_leaf_index = bob_group.own_leaf_index();

    // We first go the manual route
    let _remove_proposal1 = alice_group
        .propose_remove_member(backend, bob_leaf_index)
        .expect("error while creating remove proposal");
    let _remove_proposal2 = alice_group
        .propose_remove_member(backend, bob_leaf_index)
        .expect("error while creating remove proposal");
    // While this shouldn't fail, it should produce a valid commit, i.e. one
    // that contains only one remove proposal.
    let (manual_commit, _welcome) = alice_group
        .commit_to_pending_proposals(backend)
        .expect("error while trying to commit to colliding remove proposals");

    // Clear commit to try another way of committing two identical removes.
    alice_group.clear_pending_commit();

    let (combined_commit, _welcome) = alice_group
        .remove_members(backend, &[bob_leaf_index, bob_leaf_index])
        .expect("error while trying to remove the same member twice");

    // Now let's verify that both commits only contain one proposal.
    for commit in [manual_commit, combined_commit] {
        let serialized_message = commit
            .tls_serialize_detached()
            .expect("error serializing plaintext");

        let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
            .expect("Could not deserialize message.")
            .into_plaintext()
            .expect("Message was not a plaintext.");

        let commit_content = if let FramedContentBody::Commit(commit) = plaintext.content() {
            commit.clone()
        } else {
            panic!("Unexpected content type.");
        };

        // The commit should contain only one proposal.
        assert_eq!(commit_content.proposals.len(), 1);

        // And it should be the proposal to remove bob.
        // Depending on the commit, the proposal is either inline or it's a
        // reference.
        let expected_inline_proposal = Proposal::Remove(RemoveProposal {
            removed: bob_leaf_index,
        });
        let expected_reference_proposal =
            ProposalRef::from_proposal(ciphersuite, backend, &expected_inline_proposal)
                .expect("error creating hash reference");
        let committed_proposal = commit_content
            .proposals
            .as_slice()
            .last()
            .expect("expected remove proposal");
        match committed_proposal {
            ProposalOrRef::Proposal(inline_proposal) => {
                assert_eq!(&expected_inline_proposal, inline_proposal)
            }
            ProposalOrRef::Reference(reference_proposal) => {
                assert_eq!(&expected_reference_proposal, reference_proposal)
            }
        }
    }

    // It remains to verify this behaviour on the receiver side. However, this
    // is not really possible, since the `ProposalQueue` logic on the receiver
    // side automatically de-duplicates proposals with the same Proposal
    // reference. This is the case for Bob's proposal, both in the case of
    // inline and reference proposal.
}

/// ValSem108
/// Remove Proposal:
/// Removed member must be an existing group member
#[apply(ciphersuites_and_backends)]
fn test_valsem108(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Before we can test creation or reception of (invalid) proposals, we set
    // up a new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We first try to make Alice create a commit with a proposal targeting a
    // non-existing group member.

    // There are two ways in which we could use the MlsGroup API to commit to
    // remove proposals: Create the proposals and then commit them manually or
    // use the `remove_members` endpoint.
    let fake_leaf_index = LeafNodeIndex::new(9238754);

    // We first go the manual route
    let _remove_proposal1 = alice_group
        .propose_remove_member(backend, fake_leaf_index)
        .expect_err("Successfully created remove proposal for leaf not in the tree");
    let _ = alice_group
        .commit_to_pending_proposals(backend)
        .expect("No error while committing empty proposals");
    // FIXME: #1098 This shouldn't be necessary. Something is broken in the state logic.
    alice_group.clear_pending_commit();

    // Creating the proposal should fail already because the member is not known.
    let err = alice_group
        .propose_remove_member(backend, fake_leaf_index)
        .expect_err("Successfully created remove proposal for unknown member");

    assert_eq!(err, ProposeRemoveMemberError::UnknownMember);

    // Clear commit to try another way of committing a remove of a non-member.
    alice_group.clear_pending_commit();
    alice_group.clear_pending_proposals();

    let err = alice_group
        .remove_members(backend, &[fake_leaf_index])
        .expect_err("no error while trying to remove non-group-member");

    assert_eq!(
        err,
        RemoveMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
            ProposalValidationError::UnknownMemberRemoval
        ))
    );

    // We now have alice create a commit. Then we artificially add an invalid
    // remove proposal targeting a member that is not part of the group.

    // Create the Commit.
    let serialized_update = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    // Use a random leaf index that doesn't exist to create a remove proposal.
    let remove_proposal = Proposal::Remove(RemoveProposal {
        removed: LeafNodeIndex::new(987),
    });

    // Artificially add a proposal trying to remove someone that is not in a
    // group.
    let verifiable_plaintext = insert_proposal_and_resign(
        backend,
        vec![ProposalOrRef::Proposal(remove_proposal)],
        plaintext,
        &original_plaintext,
        &alice_group,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(backend, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::UnknownMemberRemoval
        ))
    );

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(backend, original_update_plaintext.into())
        .expect("Unexpected error.");
}

/// ValSem109
/// Update Proposal:
/// Identity must be unchanged between existing member and new proposal
#[apply(ciphersuites_and_backends)]
fn test_valsem109(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Before we can test creation or reception of (invalid) proposals, we set
    // up a new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We can't test this by having Alice propose an update herself, so we have
    // to have Bob propose the update. This is due to the commit logic filtering
    // out own proposals and just including a path instead.

    // We first try make Alice create a commit, where she commits an update
    // proposal by bob that changes his identity.

    // We begin by creating a KPB with a different identity.
    let new_cb = CredentialBundle::new(
        "Bobby".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("error creating credential bundle");
    let credential_id = new_cb
        .credential()
        .signature_key()
        .tls_serialize_detached()
        .expect("Error serializing signature key.");
    // Store the credential bundle into the key store so OpenMLS has access
    // to it.
    backend
        .key_store()
        .store(&credential_id, &new_cb)
        .expect("An unexpected error occurred.");

    let update_kp = KeyPackage::builder()
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            backend,
            &new_cb,
        )
        .unwrap();

    // We first go the manual route
    let update_proposal = bob_group
        .propose_self_update(backend, Some(update_kp))
        .expect("error while creating remove proposal");

    // Have Alice process this proposal.
    if let ProcessedMessageContent::ProposalMessage(proposal) = alice_group
        .process_message(backend, update_proposal.into_protocol_message().unwrap())
        .expect("error processing proposal")
        .into_content()
    {
        alice_group.store_pending_proposal(*proposal)
    } else {
        panic!("Unexpected message type");
    };

    // This should fail, since the identity doesn't match.
    let err = alice_group
        .commit_to_pending_proposals(backend)
        .expect_err("no error while trying to commit to update proposal with differing identity");

    assert_eq!(
        err,
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::ProposalValidationError(
                ProposalValidationError::UpdateProposalIdentityMismatch
            )
        )
    );

    // Clear commit to try another way of committing with a mismatching identity.
    alice_group.clear_pending_commit();
    alice_group.clear_pending_proposals();

    // We now have Alice create a commit. Then we artificially add a
    // update proposal that changes the updater's identity.

    // Create the Commit.
    let serialized_update = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let kpb = KeyPackageBundle::new(backend, ciphersuite, &new_cb);

    let update_proposal = Proposal::Update(UpdateProposal {
        leaf_node: kpb.key_package().leaf_node().clone(),
    });

    // Artificially add the proposal.
    let verifiable_plaintext = insert_proposal_and_resign(
        backend,
        vec![ProposalOrRef::Proposal(update_proposal)],
        plaintext,
        &original_plaintext,
        &alice_group,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(backend, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::CommitterIncludedOwnUpdate
        ))
    );

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(backend, original_update_plaintext.into())
        .expect("Unexpected error.");
}

/// ValSem110
/// Update Proposal:
/// HPKE init key must be unique among existing members
#[apply(ciphersuites_and_backends)]
fn test_valsem110(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Before we can test creation or reception of (invalid) proposals, we set
    // up a new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We can't test this by having Alice propose an update herself, so we have
    // to have Bob propose the update. This is due to the commit logic filtering
    // out own proposals and just including a path instead.

    // We first try make Alice create a commit, where she commits an update
    // proposal by bob that contains alice's existing HPKE key.

    // We begin by creating a KPB with a colliding HPKE key.
    let bob_leaf_node = bob_group
        .group()
        .treesync()
        .own_leaf_node()
        .expect("error getting own leaf node")
        .clone();

    let bob_credential_bundle = backend
        .key_store()
        .read::<CredentialBundle>(
            &bob_group
                .credential()
                .expect("error fetching credential")
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
        )
        .expect("An unexpected error occurred.");

    let mut update_leaf_node = bob_leaf_node;
    update_leaf_node
        .rekey(
            bob_group.group_id(),
            ciphersuite,
            ProtocolVersion::Mls10,
            &bob_credential_bundle,
            backend,
        )
        .unwrap();

    // TODO[FK]: This must go in again when #819 is finished and the leaf node
    //           uses an encryption key that's different from the init key in the
    //           key package.
    //           Right now we can't do this because we don't have Bob's private
    //           key any more.

    // let mut update_key_package = KeyPackage::builder().build(
    //     CryptoConfig {
    //         ciphersuite,
    //         version: ProtocolVersion::default(),
    //     },
    //     backend,
    //     &bob_credential_bundle,
    // )
    // .unwrap();
    // update_key_package.set_public_key(bob_leaf_node.encryption_key().clone());

    // // We first go the manual route
    // let update_proposal = bob_group
    //     .propose_self_update(backend, Some(update_key_package.clone()))
    //     .expect("error while creating remove proposal");

    // // Have Alice process this proposal.
    // if let ProcessedMessageContent::ProposalMessage(proposal) = alice_group
    //     .process_message(backend, update_proposal.into())
    //     .expect("error processing proposal")
    //     .into_content()
    // {
    //     alice_group.store_pending_proposal(*proposal)
    // } else {
    //     panic!("Unexpected message type");
    // };

    // // This should fail, since the hpke keys collide.
    // let err = alice_group
    //     .commit_to_pending_proposals(backend)
    //     .expect_err("no error while trying to commit to update proposal with differing identity");

    // assert_eq!(
    //     err,
    //     CommitToPendingProposalsError::CreateCommitError(
    //         CreateCommitError::ProposalValidationError(
    //             ProposalValidationError::ExistingPublicKeyUpdateProposal
    //         )
    //     )
    // );

    // // Clear commit to try another way of committing two identical removes.
    // alice_group.clear_pending_commit();
    // alice_group.clear_pending_proposals();

    // We now have Alice create a commit. Then we artificially add an
    // update proposal with a colliding hpke key.

    // Create the Commit.
    let serialized_update = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update")
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    let update_proposal = Proposal::Update(UpdateProposal {
        leaf_node: update_leaf_node.clone().into(),
    });

    // Artificially add the proposal.
    let verifiable_plaintext = insert_proposal_and_resign(
        backend,
        vec![ProposalOrRef::Proposal(update_proposal)],
        plaintext,
        &original_plaintext,
        &alice_group,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(backend, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::CommitterIncludedOwnUpdate
        ))
    );

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(backend, original_update_plaintext.into())
        .expect("Unexpected error.");
}

/// ValSem111
/// Update Proposal:
/// The sender of a full Commit must not include own update proposals
#[apply(ciphersuites_and_backends)]
fn test_valsem111(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Before we can test creation or reception of (invalid) proposals, we set
    // up a new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // We can't test this by having Alice propose an update herself. This is due
    // to the commit logic filtering out own proposals and just including a path
    // instead.

    // However, we can test the receiving side by crafting such a commit
    // manually. We have to test two scenarios: One, where the proposal is
    // inline and one, where it's committed by reference.

    // We begin by creating an update proposal for alice.
    let update_kp = generate_key_package(
        &[ciphersuite],
        alice_group.credential().expect("error fetching credential"),
        vec![],
        backend,
    )
    .expect("error creating kpb");

    let update_proposal = Proposal::Update(UpdateProposal {
        leaf_node: update_kp.leaf_node().clone(),
    });

    // We now have Alice create a commit. That commit should not contain any
    // proposals, just a path.
    let commit = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update");

    // Check that there's no proposal in it.
    let serialized_message = commit
        .tls_serialize_detached()
        .expect("error serializing plaintext");

    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    let commit_content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    // The commit should contain no proposals.
    assert_eq!(commit_content.proposals.len(), 0);

    let serialized_update = commit
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    // Let's insert the proposal into the commit.
    let verifiable_plaintext = insert_proposal_and_resign(
        backend,
        vec![ProposalOrRef::Proposal(update_proposal.clone())],
        plaintext,
        &original_plaintext,
        &alice_group,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(backend, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::CommitterIncludedOwnUpdate
        ))
    );

    // Now we insert the proposal into Bob's proposal store so we can include it
    // in the commit by reference.
    bob_group.store_pending_proposal(
        QueuedProposal::from_proposal_and_sender(
            ciphersuite,
            backend,
            update_proposal.clone(),
            &Sender::build_member(alice_group.own_leaf_index()),
        )
        .expect("error creating queued proposal"),
    );

    // Now we can have Alice create a new commit and insert the proposal by
    // reference.

    // Wipe any pending commit first.
    alice_group.clear_pending_commit();

    let commit = alice_group
        .self_update(backend, None)
        .expect("Error creating self-update");

    let serialized_update = commit
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    // Let's insert the proposal into the commit.
    // Artificially add the proposal.
    let verifiable_plaintext = insert_proposal_and_resign(
        backend,
        vec![ProposalOrRef::Reference(
            ProposalRef::from_proposal(ciphersuite, backend, &update_proposal)
                .expect("error creating hash reference"),
        )],
        plaintext,
        &original_plaintext,
        &alice_group,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(backend, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::CommitterIncludedOwnUpdate
        ))
    );

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(backend, original_update_plaintext.into())
        .expect("Unexpected error.");
}

/// ValSem112
/// Update Proposal:
/// The sender of a standalone update proposal must be of type member
#[apply(ciphersuites_and_backends)]
fn test_valsem112(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Before we can test creation or reception of (invalid) proposals, we set
    // up a new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        mut bob_group,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, backend);

    // This can really only be tested by the receiver, as there is no way to
    // make a client create a proposal with a different sender type than
    // `member`.

    // However, we can test the receiving side by crafting such a proposal
    // manually.
    let commit = alice_group
        .propose_self_update(backend, None)
        .expect("Error creating self-update");

    // Check that the sender type is indeed `member`.
    let serialized_update = commit
        .tls_serialize_detached()
        .expect("error serializing plaintext");

    let mut plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    assert!(plaintext.sender().is_member());

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    // Now let's change the sender type to NewMemberCommit.
    plaintext.set_sender(Sender::NewMemberCommit);

    let update_message_in = ProtocolMessage::from(plaintext.clone());

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(backend, update_message_in)
        .expect_err("Could parse message despite modified public key in path.");

    assert_eq!(
        err,
        ProcessMessageError::ValidationError(ValidationError::NotACommit)
    );

    // We can't test with sender type External, since that currently panics
    // with `unimplemented`.
    // TODO This test should thus be extended when fixing #106.

    // Positive case
    bob_group
        .process_message(backend, ProtocolMessage::from(original_plaintext))
        .expect("Unexpected error.");
}
