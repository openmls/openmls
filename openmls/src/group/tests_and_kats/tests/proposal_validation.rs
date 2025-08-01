//! This module tests the validation of proposals as defined in
//! https://book.openmls.tech/message_validation.html#semantic-validation-of-proposals-covered-by-a-commit

use crate::{
    storage::OpenMlsProvider,
    test_utils::frankenstein::*,
    treesync::{errors::LeafNodeValidationError, LeafNodeParameters},
};
use openmls_traits::{prelude::openmls_types::*, signatures::Signer};
use proposal_store::QueuedProposal;
use tls_codec::{Deserialize, Serialize};

use crate::group::tests_and_kats::utils::{
    generate_credential_with_key, generate_key_package, resign_message, CredentialWithKeyAndSigner,
};
use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::hash_ref::ProposalRef,
    credentials::*,
    framing::{
        mls_content::FramedContentBody, validation::ProcessedMessageContent, AuthenticatedContent,
        FramedContent, MlsMessageIn, MlsMessageOut, ProtocolMessage, PublicMessage, Sender,
    },
    group::*,
    key_packages::{errors::*, *},
    messages::{
        proposals::{
            AddProposal, CustomProposal, Proposal, ProposalOrRef, ProposalType, RemoveProposal,
            UpdateProposal,
        },
        Commit, Welcome,
    },
    prelude::{Capabilities, MlsMessageBodyIn},
    schedule::PreSharedKeyId,
    test_utils::frankenstein::FrankenKeyPackage,
    treesync::errors::ApplyUpdatePathError,
    versions::ProtocolVersion,
};

/// Helper function to generate and output CredentialWithKeyAndSigner and KeyPackage
fn generate_credential_with_key_and_key_package(
    identity: Vec<u8>,
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKeyAndSigner, KeyPackageBundle) {
    let credential_with_key_and_signer =
        generate_credential_with_key(identity, ciphersuite.signature_algorithm(), provider);

    let key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        provider,
        credential_with_key_and_signer.clone(),
    );

    (credential_with_key_and_signer, key_package)
}

/// Helper function to create a group and try to add `members` to it.
fn create_group_with_members<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    alice_credential_with_key_and_signer: &CredentialWithKeyAndSigner,
    member_key_packages: &[KeyPackage],
    provider: &Provider,
) -> Result<(MlsMessageIn, Welcome), AddMembersError<<Provider as OpenMlsProvider>::StorageError>> {
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_credential_with_key_and_signer.signer,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .build(),
        GroupId::random(provider.rand()),
        alice_credential_with_key_and_signer
            .credential_with_key
            .clone(),
    )
    .expect("An unexpected error occurred.");

    alice_group
        .add_members(
            provider,
            &alice_credential_with_key_and_signer.signer,
            member_key_packages,
        )
        .map(|(msg, welcome, _group_info)| {
            (
                msg.into(),
                welcome.into_welcome().expect("Unexpected message type."),
            )
        })
}

struct ProposalValidationTestSetup {
    alice_group: MlsGroup,
    alice_credential_with_key_and_signer: CredentialWithKeyAndSigner,
    bob_group: MlsGroup,
    bob_credential_with_key_and_signer: CredentialWithKeyAndSigner,
}

// Creates a standalone group
fn new_test_group(
    identity: &str,
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) -> (MlsGroup, CredentialWithKeyAndSigner) {
    let group_id = GroupId::random(provider.rand());

    // Generate credentials with keys
    let credential_with_key_and_signer =
        generate_credential_with_key(identity.into(), ciphersuite.signature_algorithm(), provider);

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(wire_format_policy)
        .ciphersuite(ciphersuite)
        .build();

    (
        MlsGroup::new_with_group_id(
            provider,
            &credential_with_key_and_signer.signer,
            &mls_group_create_config,
            group_id,
            credential_with_key_and_signer.credential_with_key.clone(),
        )
        .unwrap(),
        credential_with_key_and_signer,
    )
}

// Validation test setup
fn validation_test_setup(
    wire_format_policy: WireFormatPolicy,
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) -> ProposalValidationTestSetup {
    // === Alice creates a group ===
    let (mut alice_group, alice_credential_with_key_and_signer) =
        new_test_group("Alice", wire_format_policy, ciphersuite, provider);

    let bob_credential_with_key_and_signer =
        generate_credential_with_key("Bob".into(), ciphersuite.signature_algorithm(), provider);

    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        provider,
        bob_credential_with_key_and_signer.clone(),
    );

    let (_message, welcome, _group_info) = alice_group
        .add_members(
            provider,
            &alice_credential_with_key_and_signer.signer,
            &[bob_key_package.key_package().clone()],
        )
        .unwrap();

    alice_group.merge_pending_commit(provider).unwrap();

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(wire_format_policy)
        .build();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    let bob_group = StagedWelcome::new_from_welcome(
        provider,
        &mls_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(provider)
    .unwrap();

    ProposalValidationTestSetup {
        alice_group,
        alice_credential_with_key_and_signer,
        bob_group,
        bob_credential_with_key_and_signer,
    }
}

fn insert_proposal_and_resign(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    mut proposal_or_ref: Vec<ProposalOrRef>,
    mut plaintext: PublicMessage,
    original_plaintext: &PublicMessage,
    committer_group: &MlsGroup,
    signer: &impl Signer,
) -> PublicMessage {
    let mut commit_content = if let FramedContentBody::Commit(commit) = plaintext.content() {
        commit.clone()
    } else {
        panic!("Unexpected content type.");
    };

    commit_content.proposals.append(&mut proposal_or_ref);

    plaintext.set_content(FramedContentBody::Commit(commit_content));

    let mut signed_plaintext = resign_message(
        committer_group,
        plaintext,
        original_plaintext,
        provider,
        signer,
        ciphersuite,
    );

    let membership_key = committer_group.message_secrets().membership_key();

    signed_plaintext
        .set_membership_tag(
            provider.crypto(),
            ciphersuite,
            membership_key,
            committer_group.message_secrets().serialized_context(),
        )
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

/// ValSem101:
/// Add Proposal:
/// Signature public key in proposals must be unique among proposals
#[openmls_test::openmls_test]
fn test_valsem101a() {
    for bob_and_charlie_share_keys in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveDifferentKey,
    ] {
        // 0. Initialize Alice
        let (alice_credential_with_keys, _) =
            generate_credential_with_key_and_key_package("Alice".into(), ciphersuite, provider);

        // 1. Initialize Bob and Charlie
        let bob_credential_with_keys = generate_credential_with_key(
            b"Bob".to_vec(),
            ciphersuite.signature_algorithm(),
            provider,
        );
        let mut charlie_credential_with_keys = generate_credential_with_key(
            b"Charlie".to_vec(),
            ciphersuite.signature_algorithm(),
            provider,
        );

        match bob_and_charlie_share_keys {
            KeyUniqueness::NegativeSameKey => {
                // The same key but a different identity.
                // The identity check kicks in first and would throw a different
                // error.
                let charlie_credential = charlie_credential_with_keys
                    .credential_with_key
                    .credential
                    .clone();
                charlie_credential_with_keys = bob_credential_with_keys.clone();
                charlie_credential_with_keys.credential_with_key.credential = charlie_credential;
            }
            KeyUniqueness::PositiveDifferentKey => {
                // Nothing to do in this case because the keys are different.
            }
            KeyUniqueness::PositiveSameKeyWithRemove => unreachable!(),
        }

        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            bob_credential_with_keys.clone(),
        );
        let charlie_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            charlie_credential_with_keys.clone(),
        );

        // 1. Alice creates a group and tries to add Bob and Charlie to it
        let res = create_group_with_members(
            ciphersuite,
            &alice_credential_with_keys,
            &[
                bob_key_package.key_package().clone(),
                charlie_key_package.key_package().clone(),
            ],
            provider,
        );

        match bob_and_charlie_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let err = res.expect_err("was able to add users with the same signature key!");
                assert!(matches!(
                    err,
                    AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                        ProposalValidationError::DuplicateSignatureKey
                    ))
                ));
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
        alice_credential_with_key_and_signer,
        mut bob_group,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // We now have alice create a commit with an add proposal. Then we
    // artificially add another add proposal with a different identity,
    // different hpke public key, but the same signature public key.
    let (charlie_credential_with_key, charlie_key_package) =
        generate_credential_with_key_and_key_package("Charlie".into(), ciphersuite, provider);

    // Create the Commit with Add proposal.
    let serialized_update = alice_group
        .add_members(
            provider,
            &alice_credential_with_key_and_signer.signer,
            &[charlie_key_package.key_package().clone()],
        )
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
    let dave_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            provider,
            &charlie_credential_with_key.signer,
            CredentialWithKey {
                credential: BasicCredential::new(b"Dave".to_vec()).into(),
                signature_key: charlie_credential_with_key
                    .credential_with_key
                    .signature_key,
            },
        )
        .unwrap();

    let second_add_proposal = Proposal::Add(AddProposal {
        key_package: dave_key_package.key_package().clone(),
    });

    let verifiable_plaintext = insert_proposal_and_resign(
        provider,
        ciphersuite,
        vec![ProposalOrRef::Proposal(second_add_proposal)],
        plaintext,
        &original_plaintext,
        &alice_group,
        &alice_credential_with_key_and_signer.signer,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(provider, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::DuplicateSignatureKey
        ))
    ));

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(
            provider,
            original_update_plaintext
                .try_into_protocol_message()
                .unwrap(),
        )
        .expect("Unexpected error.");
}

/// ValSem102:
/// Add Proposal:
/// HPKE init key in proposals must be unique among proposals
#[openmls_test::openmls_test]
fn test_valsem102() {
    for bob_and_charlie_share_keys in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveDifferentKey,
    ] {
        // 0. Initialize Alice, Bob, and Charlie
        let (alice_credential_with_key, _) =
            generate_credential_with_key_and_key_package("Alice".into(), ciphersuite, provider);
        let (bob_credential_with_key, mut bob_key_package) =
            generate_credential_with_key_and_key_package("Bob".into(), ciphersuite, provider);
        let (_charlie_credential_with_key, charlie_key_package) =
            generate_credential_with_key_and_key_package("Charlie".into(), ciphersuite, provider);

        match bob_and_charlie_share_keys {
            KeyUniqueness::NegativeSameKey => {
                // Create a new key package for bob with the init key from Charlie.
                let encryption_private_key = bob_key_package.encryption_private_key().clone();
                let mut franken_key_package = FrankenKeyPackage::from(bob_key_package);
                franken_key_package.init_key = charlie_key_package
                    .key_package()
                    .hpke_init_key()
                    .as_slice()
                    .to_owned()
                    .into();
                franken_key_package.resign(&bob_credential_with_key.signer);
                bob_key_package = {
                    let kp = KeyPackage::from(franken_key_package.clone());
                    KeyPackageBundle::new(
                        kp,
                        charlie_key_package.init_private_key().clone(),
                        encryption_private_key.into(),
                    )
                };
            }
            KeyUniqueness::PositiveDifferentKey => {
                // don't need to do anything since the keys are already
                // different.
            }
            KeyUniqueness::PositiveSameKeyWithRemove => unreachable!(),
        }

        // 1. Alice creates a group and tries to add Bob and Charlie to it
        let res = create_group_with_members(
            ciphersuite,
            &alice_credential_with_key,
            &[
                bob_key_package.key_package().clone(),
                charlie_key_package.key_package().clone(),
            ],
            provider,
        );

        match bob_and_charlie_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let err = res.expect_err("was able to add users with the same HPKE init key!");
                assert!(matches!(
                    err,
                    AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                        ProposalValidationError::DuplicateInitKey
                    ))
                ));
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
        alice_credential_with_key_and_signer,
        mut bob_group,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // We now have alice create a commit with an add proposal. Then we
    // artificially add another add proposal with a different identity,
    // different signature key, but the same hpke public key.
    let (_charlie_credential_with_key, charlie_key_package) =
        generate_credential_with_key_and_key_package("Charlie".into(), ciphersuite, provider);

    // Create the Commit with Add proposal.
    let serialized_update = alice_group
        .add_members(
            provider,
            &alice_credential_with_key_and_signer.signer,
            &[charlie_key_package.key_package().clone()],
        )
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
    // a different signature key, different identity, but the same hpke init
    // key.
    let (dave_credential_with_key_and_signer, dave_key_package) =
        generate_credential_with_key_and_key_package("Dave".into(), ciphersuite, provider);
    // Change the init key and re-sign.
    let mut franken_key_package = FrankenKeyPackage::from(dave_key_package);
    franken_key_package.init_key = charlie_key_package
        .key_package()
        .hpke_init_key()
        .as_slice()
        .to_owned()
        .into();
    franken_key_package.resign(&dave_credential_with_key_and_signer.signer);
    let dave_key_package = KeyPackage::from(franken_key_package);

    let second_add_proposal = Proposal::Add(AddProposal {
        key_package: dave_key_package,
    });

    let verifiable_plaintext = insert_proposal_and_resign(
        provider,
        ciphersuite,
        vec![ProposalOrRef::Proposal(second_add_proposal)],
        plaintext,
        &original_plaintext,
        &alice_group,
        &alice_credential_with_key_and_signer.signer,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(provider, update_message_in)
        .expect_err("Could process message despite modified encryption key in path.");

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::DuplicateInitKey
        ))
    ));

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(
            provider,
            original_update_plaintext
                .try_into_protocol_message()
                .unwrap(),
        )
        .expect("Unexpected error.");
}

/// ValSem101:
/// Add Proposal:
/// Signature public key in proposals must be unique among existing group
/// members
#[openmls_test::openmls_test]
fn test_valsem101b() {
    for alice_and_bob_share_keys in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveDifferentKey,
        KeyUniqueness::PositiveSameKeyWithRemove,
    ] {
        // 0. Initialize Alice and Bob
        let new_kp = || {
            openmls_basic_credential::SignatureKeyPair::new(ciphersuite.signature_algorithm())
                .unwrap()
        };
        let shared_signature_keypair = new_kp();
        let [alice_credential_with_key, bob_credential_with_key, target_credential_with_key] =
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
            .map(|(name, keypair)| CredentialWithKeyAndSigner {
                credential_with_key: CredentialWithKey {
                    credential: BasicCredential::new(name.into()).into(),
                    signature_key: keypair.to_public_vec().into(),
                },
                signer: keypair,
            });

        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            bob_credential_with_key.clone(),
        );
        let target_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            target_credential_with_key.clone(),
        );

        // 1. Alice creates a group and tries to add Bob to it
        let mut alice_group = MlsGroup::new_with_group_id(
            provider,
            &alice_credential_with_key.signer,
            &MlsGroupCreateConfig::builder()
                .ciphersuite(ciphersuite)
                .build(),
            GroupId::random(provider.rand()),
            alice_credential_with_key.credential_with_key.clone(),
        )
        .unwrap();

        match alice_and_bob_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let err = alice_group
                    .add_members(
                        provider,
                        &alice_credential_with_key.signer,
                        &[
                            bob_key_package.key_package().clone(),
                            target_key_package.key_package().clone(),
                        ],
                    )
                    .expect_err("was able to add user with same signature key as a group member!");
                assert!(matches!(
                    err,
                    AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                        ProposalValidationError::DuplicateSignatureKey
                    ))
                ));
            }
            KeyUniqueness::PositiveDifferentKey => {
                alice_group
                    .add_members(
                        provider,
                        &alice_credential_with_key.signer,
                        &[
                            bob_key_package.key_package().clone(),
                            target_key_package.key_package().clone(),
                        ],
                    )
                    .expect("failed to add user with different signature keypair!");
            }
            KeyUniqueness::PositiveSameKeyWithRemove => {
                alice_group
                    .add_members(
                        provider,
                        &alice_credential_with_key.signer,
                        &[bob_key_package.key_package().clone()],
                    )
                    .unwrap();
                alice_group.merge_pending_commit(provider).unwrap();
                let bob_index = alice_group
                    .members()
                    .find_map(|member| {
                        if member.credential.serialized_content() == b"Bob" {
                            Some(member.index)
                        } else {
                            None
                        }
                    })
                    .unwrap();
                alice_group
                    .propose_remove_member(provider, &alice_credential_with_key.signer, bob_index)
                    .unwrap();
                alice_group
                    .add_members(provider, &alice_credential_with_key.signer, &[target_key_package.key_package().clone()])
                    .expect(
                    "failed to add a user with the same identity as someone in the group (with a remove proposal)!",
                );
            }
        }
    }

    // TODO #1187: This part of the test needs to be adapted to the new parent hashes.
    /* for alice_and_bob_share_keys in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveSameKeyWithRemove,
    ] {
        // Before we can test reception of (invalid) proposals, we set up a new
        // group with Alice and Bob.
        let ProposalValidationTestSetup {
            mut alice_group,
            mut bob_group,
        } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

        // We now have alice create a commit. Then we artificially add an Add
        // proposal with a different identity, but with the same signature public
        // key as Bob.
        // Create the Commit.
        let serialized_update = alice_group
            .self_update(provider)
            .expect("Error creating self-update")
            .tls_serialize_detached()
            .expect("Could not serialize message.");

        let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.")
            .into_plaintext()
            .expect("Message was not a plaintext.");

        // Keep the original plaintext for positive test later.
        let original_plaintext = plaintext.clone();

        let bob_credential_bundle = provider
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
                ciphersuite
                provider,
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
                        if member.credential.identity() == b"Bob" {
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
            provider,
            proposals,
            plaintext,
            &original_plaintext,
            &alice_group,
        );

        match alice_and_bob_share_keys {
            KeyUniqueness::NegativeSameKey => {
                // Have bob process the resulting plaintext
                let err = bob_group
                    .process_message(provider, verifiable_plaintext)
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
                    .process_message(provider, verifiable_plaintext)
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
            .process_message(provider, original_update_plaintext)
            .expect("Unexpected error.");
    } */
}

/// ValSem103:
/// Add Proposal: Encryption key must be unique in the tree
/// ValSem104:
/// Add Proposal: Init key and encryption key must be different
#[openmls_test::openmls_test]
fn test_valsem103_valsem104(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    for alice_and_bob_share_keys in [
        KeyUniqueness::NegativeSameKey,
        KeyUniqueness::PositiveDifferentKey,
    ] {
        // 0. Initialize Alice and Bob
        let (alice_credential_with_key, _) =
            generate_credential_with_key_and_key_package("Alice".into(), ciphersuite, provider);
        let (bob_credential_with_key, bob_key_package) =
            generate_credential_with_key_and_key_package("Bob".into(), ciphersuite, provider);

        let bob_key_package = match alice_and_bob_share_keys {
            KeyUniqueness::NegativeSameKey => {
                // Create a new key package for bob using the encryption key as init key.
                let mut franken_key_package = FrankenKeyPackage::from(bob_key_package);
                franken_key_package.init_key = franken_key_package.leaf_node.encryption_key.clone();
                franken_key_package.resign(&bob_credential_with_key.signer);
                KeyPackage::from(franken_key_package)
            }
            KeyUniqueness::PositiveDifferentKey => {
                // don't need to do anything since all keys are already
                // different.
                bob_key_package.key_package().clone()
            }
            KeyUniqueness::PositiveSameKeyWithRemove => unreachable!(),
        };

        // 1. Alice creates a group and tries to add Bob to it
        let res = create_group_with_members(
            ciphersuite,
            &alice_credential_with_key,
            &[bob_key_package],
            provider,
        );

        match alice_and_bob_share_keys {
            KeyUniqueness::NegativeSameKey => {
                let err =
                    res.expect_err("was able to add user with colliding init and encryption keys!");
                assert!(matches!(
                    err,
                    AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
                        ProposalValidationError::InitEncryptionKeyCollision
                    ))
                ));
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
        alice_credential_with_key_and_signer,
        mut bob_group,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // We now have alice create a commit. Then we artificially add an Add
    // proposal with a leaf that has the same encryption key as an existing leaf.

    // Create the Commit.
    let serialized_update = alice_group
        .self_update(
            provider,
            &alice_credential_with_key_and_signer.signer,
            LeafNodeParameters::default(),
        )
        .expect("Error creating self-update")
        .into_contents()
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    // Keep the original plaintext for positive test later.
    let original_plaintext = plaintext.clone();

    // We now pull bob's public key from his leaf.
    let bob_encryption_key = bob_group
        .own_leaf_node()
        .expect("No own leaf")
        .encryption_key()
        .clone();

    // Generate fresh key material for Dave.
    let (dave_credential_with_key, dave_key_package) =
        generate_credential_with_key_and_key_package("Dave".into(), ciphersuite, provider);

    // Insert Bob's public key into Dave's KPB and resign.
    let mut franken_key_package = FrankenKeyPackage::from(dave_key_package);
    franken_key_package.leaf_node.encryption_key = bob_encryption_key.as_slice().to_owned().into();
    franken_key_package.resign(&dave_credential_with_key.signer);
    let dave_key_package = KeyPackage::from(franken_key_package);

    // Use the resulting KP to create an Add proposal.
    let add_proposal = Proposal::Add(AddProposal {
        key_package: dave_key_package,
    });

    // Artificially add a proposal trying to add someone with an existing
    // encryption key.
    let verifiable_plaintext = insert_proposal_and_resign(
        provider,
        ciphersuite,
        vec![ProposalOrRef::Proposal(add_proposal)],
        plaintext,
        &original_plaintext,
        &alice_group,
        &alice_credential_with_key_and_signer.signer,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(provider, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::DuplicateEncryptionKey
        ))
    ));

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(
            provider,
            original_update_plaintext
                .try_into_protocol_message()
                .unwrap(),
        )
        .expect("Unexpected error.");
}

#[derive(Debug)]
enum KeyPackageTestVersion {
    // Wrong ciphersuite in the KeyPackage
    WrongCiphersuite,
    // Wrong version in the KeyPackage
    WrongVersion,
    // Unsupported ciphersuite in the KeyPackage's capabilities
    UnsupportedVersion,
    // Unsupported ciphersuite in the KeyPackage's capabilities
    UnsupportedCiphersuite,
    // Positive case
    ValidTestCase,
}

enum ProposalInclusion {
    ByValue,
    ByReference,
}

/// ValSem105:
/// Add Proposal:
/// Ciphersuite & protocol version must match the group
#[openmls_test::openmls_test]
fn test_valsem105() {
    let _ = pretty_env_logger::try_init();

    // Ciphersuite & protocol version validation includes checking the
    // ciphersuite and the version of the KeyPackage in the add proposal to make
    // sure they match the ones from the group.

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
        KeyPackageTestVersion::WrongVersion,
        KeyPackageTestVersion::UnsupportedVersion,
        KeyPackageTestVersion::UnsupportedCiphersuite,
        KeyPackageTestVersion::ValidTestCase,
    ] {
        println!("# running test {key_package_version:?}");

        // Let's set up a group with Alice and Bob as members.
        let ProposalValidationTestSetup {
            mut alice_group,
            alice_credential_with_key_and_signer,
            mut bob_group,
            ..
        } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

        let (charlie_credential_with_key, charlie_key_package) =
            generate_credential_with_key_and_key_package("Charlie".into(), ciphersuite, provider);

        let mut franken_key_package = FrankenKeyPackage::from(charlie_key_package.clone());

        let kpi = KeyPackageIn::from(charlie_key_package.clone());
        kpi.validate(provider.crypto(), ProtocolVersion::Mls10)
            .unwrap();

        // Let's just pick a ciphersuite that's not the one we're testing right now.
        let wrong_ciphersuite = match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            }
            _ => Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        } as u16;
        match key_package_version {
            KeyPackageTestVersion::WrongCiphersuite => {
                franken_key_package.ciphersuite = wrong_ciphersuite;
            }
            KeyPackageTestVersion::WrongVersion => {
                franken_key_package.protocol_version = 999;
            }
            KeyPackageTestVersion::UnsupportedVersion => {
                franken_key_package.leaf_node.capabilities.versions = vec![999];
            }
            KeyPackageTestVersion::UnsupportedCiphersuite => {
                franken_key_package.leaf_node.capabilities.ciphersuites =
                    vec![Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448.into()];
            }
            KeyPackageTestVersion::ValidTestCase => (),
        };

        franken_key_package.resign(&charlie_credential_with_key.signer);
        let test_kp = KeyPackage::from(franken_key_package);

        let test_kp_2 = {
            let (charlie_credential_with_key, charlie_key_package) =
                generate_credential_with_key_and_key_package(
                    "Charlie".into(),
                    ciphersuite,
                    provider,
                );

            let mut franken_key_package = FrankenKeyPackage::from(charlie_key_package.clone());

            // Let's just pick a ciphersuite that's not the one we're testing right now.
            let wrong_ciphersuite = match ciphersuite {
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
                }
                _ => Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            } as u16;
            match key_package_version {
                KeyPackageTestVersion::WrongCiphersuite => {
                    franken_key_package.ciphersuite = wrong_ciphersuite;
                }
                KeyPackageTestVersion::WrongVersion => {
                    franken_key_package.protocol_version = 999;
                }
                KeyPackageTestVersion::UnsupportedVersion => {
                    franken_key_package.leaf_node.capabilities.versions = vec![999];
                }
                KeyPackageTestVersion::UnsupportedCiphersuite => {
                    franken_key_package.leaf_node.capabilities.ciphersuites =
                        vec![Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448.into()];
                }
                KeyPackageTestVersion::ValidTestCase => (),
            };

            franken_key_package.resign(&charlie_credential_with_key.signer);
            KeyPackage::from(franken_key_package)
        };

        // Try to have Alice commit an Add with the test KeyPackage.
        for proposal_inclusion in [ProposalInclusion::ByReference, ProposalInclusion::ByValue] {
            match proposal_inclusion {
                ProposalInclusion::ByReference => {
                    let _proposal = alice_group
                        .propose_add_member(
                            provider,
                            &alice_credential_with_key_and_signer.signer,
                            &test_kp,
                        )
                        .unwrap();

                    let result = alice_group.commit_to_pending_proposals(
                        provider,
                        &alice_credential_with_key_and_signer.signer,
                    );

                    // The error types differ, so we have to check the error inside the `match`.
                    match key_package_version {
                        KeyPackageTestVersion::ValidTestCase => {
                            result.unwrap();
                        }
                        _ => {
                            matches!(
                                result.unwrap_err(),
                                CommitToPendingProposalsError::CreateCommitError(_)
                            );
                        }
                    }
                }
                ProposalInclusion::ByValue => {
                    let result = alice_group.add_members(
                        provider,
                        &alice_credential_with_key_and_signer.signer,
                        &[test_kp_2.clone()],
                    );

                    match key_package_version {
                        KeyPackageTestVersion::ValidTestCase => {
                            result.unwrap();
                        }
                        _ => {
                            matches!(result.unwrap_err(), AddMembersError::CreateCommitError(_));
                        }
                    }
                }
            };
            // Reset alice's group state for the next test case.
            alice_group
                .clear_pending_commit(provider.storage())
                .unwrap();
        }
        // Now we create a valid commit and add the proposal afterwards. Once by value, once by reference.
        alice_group
            .clear_pending_proposals(provider.storage())
            .unwrap();

        // Create the Commit.
        let serialized_update = alice_group
            .self_update(
                provider,
                &alice_credential_with_key_and_signer.signer,
                LeafNodeParameters::default(),
            )
            .unwrap()
            .into_messages()
            .tls_serialize_detached()
            .unwrap();

        let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .unwrap()
            .into_plaintext()
            .unwrap();

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
                    ProposalRef::from_raw_proposal(ciphersuite, provider.crypto(), &add_proposal)
                        .unwrap(),
                ),
            };
            // Artificially add the proposal.
            let verifiable_plaintext = insert_proposal_and_resign(
                provider,
                ciphersuite,
                vec![proposal_or_ref],
                plaintext.clone(),
                &original_plaintext,
                &alice_group,
                &alice_credential_with_key_and_signer.signer,
            );

            let update_message_in = ProtocolMessage::from(verifiable_plaintext);

            // If we're including by reference, we have to sneak the proposal
            // into Bob's queue.
            if matches!(proposal_inclusion, ProposalInclusion::ByReference) {
                bob_group
                    .store_pending_proposal(
                        provider.storage(),
                        QueuedProposal::from_proposal_and_sender(
                            ciphersuite,
                            provider.crypto(),
                            add_proposal.clone(),
                            &Sender::build_member(alice_group.own_leaf_index()),
                        )
                        .unwrap(),
                    )
                    .unwrap()
            }

            // Have bob process the resulting plaintext
            let err = bob_group
                .process_message(provider, update_message_in)
                .expect_err("Could process message despite injected add proposal.");

            match key_package_version {
                // We get an error even if the key package is valid. This is
                // because Bob would expect the encrypted path in the commit to
                // be longer due to the included Add proposal. Since we added
                // the Add artificially, we thus have a path length mismatch.
                KeyPackageTestVersion::ValidTestCase => {
                    assert!(matches!(
                        err,
                        ProcessMessageError::InvalidCommit(StageCommitError::UpdatePathError(
                            ApplyUpdatePathError::PathLengthMismatch,
                        ),)
                    ));
                }
                KeyPackageTestVersion::WrongCiphersuite => {
                    // In this case we need to differentiate, since we
                    // manipulated the ciphersuite. The signature algorithm can
                    // also have a mismatch and therefore invalidate the
                    // signature, and/or the ciphersuite doesn't match.

                    assert!(
                        matches!(
                            err,
                            ProcessMessageError::InvalidCommit(
                                StageCommitError::ProposalValidationError(
                                    ProposalValidationError::InvalidAddProposalCiphersuiteOrVersion,
                                ),
                            )
                        ) || matches!(
                            err,
                            ProcessMessageError::ValidationError(
                                ValidationError::KeyPackageVerifyError(
                                    KeyPackageVerifyError::InvalidLeafNodeSignature,
                                ),
                            )
                        ) || matches!(
                            err,
                            ProcessMessageError::ValidationError(
                                ValidationError::InvalidAddProposalCiphersuite,
                            )
                        )
                    );
                }
                KeyPackageTestVersion::WrongVersion => {
                    // We need to distinguish between the two cases where the
                    // version is wrong, depending on whether it's a proposal by
                    // value or by reference.
                    assert!(
                        matches!(
                            err,
                            ProcessMessageError::InvalidCommit(
                                StageCommitError::ProposalValidationError(
                                    ProposalValidationError::InvalidAddProposalCiphersuiteOrVersion,
                                ),
                            )
                        ) || matches!(
                            err,
                            ProcessMessageError::ValidationError(
                                ValidationError::KeyPackageVerifyError(
                                    KeyPackageVerifyError::InvalidProtocolVersion,
                                ),
                            )
                        )
                    );
                }
                KeyPackageTestVersion::UnsupportedVersion => {
                    assert!(
                        matches!(
                            err,
                            ProcessMessageError::ValidationError(
                                ValidationError::KeyPackageVerifyError(
                                    KeyPackageVerifyError::InvalidProtocolVersion,
                                ),
                            )
                        ) || matches!(
                            err,
                            ProcessMessageError::InvalidCommit(
                                StageCommitError::ProposalValidationError(
                                    ProposalValidationError::LeafNodeValidation(
                                        LeafNodeValidationError::CiphersuiteNotInCapabilities
                                    ),
                                ),
                            )
                        ),
                        "unexpected error: {err:?}"
                    );
                }
                KeyPackageTestVersion::UnsupportedCiphersuite => {
                    assert!(
                        matches!(
                            err,
                            ProcessMessageError::InvalidCommit(
                                StageCommitError::ProposalValidationError(
                                    ProposalValidationError::LeafNodeValidation(
                                        LeafNodeValidationError::CiphersuiteNotInCapabilities
                                    ),
                                ),
                            )
                        ),
                        "unexpected error: {err:?}"
                    );
                }
            };

            let original_update_plaintext =
                MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
                    .expect("Could not deserialize message.");

            // Positive case
            bob_group
                .process_message(
                    provider,
                    original_update_plaintext
                        .try_into_protocol_message()
                        .unwrap(),
                )
                .unwrap();
        }

        alice_group
            .clear_pending_commit(provider.storage())
            .unwrap();
    }
}

/// ValSem107:
/// Remove Proposal:
/// Removed member must be unique among proposals
#[openmls_test::openmls_test]
fn test_valsem107() {
    // Helper function to unwrap a commit with a single proposal from an mls message.
    fn unwrap_specific_commit(commit_ref_remove: MlsMessageOut) -> Commit {
        let serialized_message = commit_ref_remove.tls_serialize_detached().unwrap();

        let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
            .unwrap()
            .into_plaintext()
            .unwrap();

        let commit_content = if let FramedContentBody::Commit(commit) = plaintext.content() {
            commit.clone()
        } else {
            panic!("Unexpected content type.");
        };

        // The commit should contain only one proposal.
        assert_eq!(commit_content.proposals.len(), 1);
        commit_content
    }

    // Before we can test creation of (invalid) proposals, we set up a new group
    // with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        alice_credential_with_key_and_signer,
        bob_group,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // We first try to make Alice create a commit with two remove proposals for
    // Bob.

    // There are two ways in which we could use the MlsGroup API to commit to
    // remove proposals: Create the proposals and then commit them manually or
    // use the `remove_members` endpoint with two times the same KeyPackageRef
    // as input. We first create both commits and then make sure they look as
    // expected.
    let bob_leaf_index = bob_group.own_leaf_index();

    let ref_propose = {
        // We first go the manual route
        let (ref_propose1, _) = alice_group
            .propose_remove_member(
                provider,
                &alice_credential_with_key_and_signer.signer,
                bob_leaf_index,
            )
            .unwrap();

        let (ref_propose2, _) = alice_group
            .propose_remove_member(
                provider,
                &alice_credential_with_key_and_signer.signer,
                bob_leaf_index,
            )
            .unwrap();

        assert_eq!(ref_propose1, ref_propose2);

        ref_propose1
    };

    // While this shouldn't fail, it should produce a valid commit, i.e. one
    // that contains only one remove proposal.
    let (commit_ref_remove, _welcome, _group_info) = alice_group
        .commit_to_pending_proposals(provider, &alice_credential_with_key_and_signer.signer)
        .expect("error while trying to commit to colliding remove proposals");

    // Clear commit to try another way of committing two identical removes.
    alice_group
        .clear_pending_commit(provider.storage())
        .unwrap();

    // Now let's verify that both commits only contain one proposal.
    let (commit_inline_remove, _welcome, _group_info) = alice_group
        .remove_members(
            provider,
            &alice_credential_with_key_and_signer.signer,
            &[bob_leaf_index, bob_leaf_index],
        )
        .expect("error while trying to remove the same member twice");

    // Check commit with referenced remove proposals.
    {
        let commit_content = unwrap_specific_commit(commit_ref_remove);

        // And it should be the proposal to remove bob.
        let expected = {
            let mls_message_in = MlsMessageIn::from(ref_propose);

            let authenticated_content = match mls_message_in.body {
                MlsMessageBodyIn::PublicMessage(ref public) => AuthenticatedContent::new(
                    mls_message_in.wire_format(),
                    FramedContent::from(public.content.clone()),
                    public.auth.clone(),
                ),
                _ => panic!(),
            };

            ProposalOrRef::Reference(
                ProposalRef::from_authenticated_content_by_ref(
                    provider.crypto(),
                    ciphersuite,
                    &authenticated_content,
                )
                .unwrap(),
            )
        };

        let got = commit_content
            .proposals
            .as_slice()
            .last()
            .expect("expected remove proposal");

        assert_eq!(expected, *got);
    }

    // Check commit with inline remove proposals.
    {
        let commit_content = unwrap_specific_commit(commit_inline_remove);

        // And it should be the proposal to remove bob.
        let expected = ProposalOrRef::Proposal(Proposal::Remove(RemoveProposal {
            removed: bob_leaf_index,
        }));

        let got = commit_content
            .proposals
            .as_slice()
            .last()
            .expect("expected remove proposal");

        assert_eq!(expected, *got);
    }

    // TODO(#1335)
    // It remains to verify this behaviour on the receiver side. However, this
    // is not really possible, since the `ProposalQueue` logic on the receiver
    // side automatically de-duplicates proposals with the same Proposal
    // reference. This is the case for Bob's proposal, both in the case of
    // inline and reference proposal.
}

/// ValSem108
/// Remove Proposal:
/// Removed member must be an existing group member
#[openmls_test::openmls_test]
fn test_valsem108() {
    // Before we can test creation or reception of (invalid) proposals, we set
    // up a new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        alice_credential_with_key_and_signer,
        mut bob_group,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // We first try to make Alice create a commit with a proposal targeting a
    // non-existing group member.

    // There are two ways in which we could use the MlsGroup API to commit to
    // remove proposals: Create the proposals and then commit them manually or
    // use the `remove_members` endpoint.
    let fake_leaf_index = LeafNodeIndex::new(9238754);

    // We first go the manual route
    let _remove_proposal1 = alice_group
        .propose_remove_member(
            provider,
            &alice_credential_with_key_and_signer.signer,
            fake_leaf_index,
        )
        .expect_err("Successfully created remove proposal for leaf not in the tree");
    let _ = alice_group
        .commit_to_pending_proposals(provider, &alice_credential_with_key_and_signer.signer)
        .expect("No error while committing empty proposals");
    // FIXME: #1098 This shouldn't be necessary. Something is broken in the state logic.
    alice_group
        .clear_pending_commit(provider.storage())
        .unwrap();

    // Creating the proposal should fail already because the member is not known.
    let err = alice_group
        .propose_remove_member(
            provider,
            &alice_credential_with_key_and_signer.signer,
            fake_leaf_index,
        )
        .expect_err("Successfully created remove proposal for unknown member");

    assert!(matches!(err, ProposeRemoveMemberError::UnknownMember));

    // Clear commit to try another way of committing a remove of a non-member.
    alice_group
        .clear_pending_commit(provider.storage())
        .unwrap();
    alice_group
        .clear_pending_proposals(provider.storage())
        .unwrap();

    let err = alice_group
        .remove_members(
            provider,
            &alice_credential_with_key_and_signer.signer,
            &[fake_leaf_index],
        )
        .expect_err("no error while trying to remove non-group-member");

    assert!(matches!(
        err,
        RemoveMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
            ProposalValidationError::UnknownMemberRemoval
        ))
    ));

    // We now have alice create a commit. Then we artificially add an invalid
    // remove proposal targeting a member that is not part of the group.

    // Create the Commit.
    let serialized_update = alice_group
        .self_update(
            provider,
            &alice_credential_with_key_and_signer.signer,
            LeafNodeParameters::default(),
        )
        .expect("Error creating self-update")
        .into_messages()
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
        provider,
        ciphersuite,
        vec![ProposalOrRef::Proposal(remove_proposal)],
        plaintext,
        &original_plaintext,
        &alice_group,
        &alice_credential_with_key_and_signer.signer,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(provider, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::UnknownMemberRemoval
        ))
    ));

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(
            provider,
            original_update_plaintext
                .try_into_protocol_message()
                .unwrap(),
        )
        .expect("Unexpected error.");
}

/// ValSem110
/// Update Proposal:
/// Encryption key must be unique among existing members
#[openmls_test::openmls_test]
fn test_valsem110() {
    // Before we can test creation or reception of (invalid) proposals, we set
    // up a new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        alice_credential_with_key_and_signer,
        mut bob_group,
        bob_credential_with_key_and_signer,
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // We can't test this by having Alice propose an update herself, so we have
    // to have Bob propose the update. This is due to the commit logic filtering
    // out own proposals and just including a path instead.

    // We first try to make Alice create a commit, where she commits an update
    // proposal by bob that contains alice's existing encryption key.

    // We begin by creating a leaf node with a colliding encryption key.
    let bob_leaf_node = bob_group
        .own_leaf_node()
        .expect("error getting own leaf node")
        .clone();

    let alice_encryption_key = alice_group
        .own_leaf_node()
        .unwrap()
        .encryption_key()
        .clone();

    // We first go the manual route
    let update_proposal: MlsMessageIn = bob_group
        .propose_self_update(
            provider,
            &bob_credential_with_key_and_signer.signer,
            LeafNodeParameters::default(),
        )
        .map(|(out, _)| MlsMessageIn::from(out))
        .expect("error while creating remove proposal");

    // Prepare the modified update proposal:

    let mut franken_leaf_node = FrankenLeafNode::from(bob_leaf_node.clone());
    franken_leaf_node.encryption_key = alice_encryption_key.key().clone();
    franken_leaf_node.leaf_node_source = FrankenLeafNodeSource::Update;
    franken_leaf_node.resign(
        Some(bob_group.own_tree_position().into()),
        &bob_credential_with_key_and_signer.signer,
    );

    let franken_message_in = FrankenMlsMessage::from(MlsMessageOut::from(update_proposal.clone()));

    // Access the content that's inside the message.
    let mut content =
        if let FrankenMlsMessageBody::PublicMessage(public_message) = franken_message_in.body {
            public_message.content
        } else {
            panic!("Unexpected message type");
        };

    // Replace the proposal inside the public message
    match content.body {
        FrankenFramedContentBody::Proposal(FrankenProposal::Update(ref mut update)) => {
            let update_proposal = FrankenUpdateProposal {
                leaf_node: franken_leaf_node.clone(),
            };
            *update = update_proposal;
        }
        _ => {
            panic!("Unexpected content type");
        }
    }

    // Rebuild the PublicMessage with the new content
    let group_context = bob_group.export_group_context().clone();
    let membership_key = bob_group.message_secrets().membership_key().as_slice();

    let new_public_message = FrankenPublicMessage::auth(
        provider,
        ciphersuite,
        &bob_credential_with_key_and_signer.signer,
        content,
        Some(&group_context.into()),
        Some(membership_key),
        None,
    );

    // And turn it into a protocol message
    let protocol_message = ProtocolMessage::from(PublicMessage::from(new_public_message));

    // Have Alice process this proposal.
    if let ProcessedMessageContent::ProposalMessage(proposal) = alice_group
        .process_message(provider, protocol_message)
        .expect("error processing proposal")
        .into_content()
    {
        alice_group
            .store_pending_proposal(provider.storage(), *proposal)
            .unwrap()
    } else {
        panic!("Unexpected message type");
    };

    // This should fail, since the hpke keys collide.
    let err = alice_group
        .commit_to_pending_proposals(provider, &alice_credential_with_key_and_signer.signer)
        .expect_err("no error while trying to commit to update proposal with differing identity");

    assert!(matches!(
        err,
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::ProposalValidationError(
                ProposalValidationError::DuplicateEncryptionKey
            )
        )
    ));

    // Clear commit to see if Bob will process a commit containing two colliding
    // keys.
    alice_group
        .clear_pending_commit(provider.storage())
        .unwrap();
    alice_group
        .clear_pending_proposals(provider.storage())
        .unwrap();

    // We now have Alice create a commit. Then we artificially add an
    // update proposal with a colliding encryption key.

    // Create the Commit.
    let serialized_update = alice_group
        .self_update(
            provider,
            &alice_credential_with_key_and_signer.signer,
            LeafNodeParameters::default(),
        )
        .expect("Error creating self-update")
        .into_contents()
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let plaintext = MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
        .expect("Could not deserialize message.")
        .into_plaintext()
        .expect("Message was not a plaintext.");

    let original_plaintext = plaintext.clone();

    let update_proposal = Proposal::Update(UpdateProposal {
        leaf_node: franken_leaf_node.into(),
    });

    // Artificially add the proposal.
    let verifiable_plaintext = insert_proposal_and_resign(
        provider,
        ciphersuite,
        vec![ProposalOrRef::Proposal(update_proposal)],
        plaintext,
        &original_plaintext,
        &alice_group,
        &alice_credential_with_key_and_signer.signer,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // We have to store the keypair with the proper label s.t. Bob can actually
    // process the commit.
    let leaf_keypair = alice_group
        .read_epoch_keypairs(provider.storage())
        .unwrap()
        .into_iter()
        .find(|keypair| keypair.public_key() == &alice_encryption_key)
        .unwrap();
    leaf_keypair.write(provider.storage()).unwrap();

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(provider, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::CommitterIncludedOwnUpdate)
    ));
}

/// ValSem111
/// Update Proposal:
/// The sender of a full Commit must not include own update proposals
#[openmls_test::openmls_test]
fn test_valsem111() {
    // Before we can test creation or reception of (invalid) proposals, we set
    // up a new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        alice_credential_with_key_and_signer,
        mut bob_group,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // We can't test this by having Alice propose an update herself. This is due
    // to the commit logic filtering out own proposals and just including a path
    // instead.

    // However, we can test the receiving side by crafting such a commit
    // manually. We have to test two scenarios: One, where the proposal is
    // inline and one, where it's committed by reference.

    // We begin by creating an update proposal for alice.
    let update_kp = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        provider,
        alice_credential_with_key_and_signer.clone(),
    );

    let update_proposal = Proposal::Update(UpdateProposal {
        leaf_node: update_kp.key_package().leaf_node().clone(),
    });

    // We now have Alice create a commit. That commit should not contain any
    // proposals, just a path.
    let commit_bundle = alice_group
        .self_update(
            provider,
            &alice_credential_with_key_and_signer.signer,
            LeafNodeParameters::default(),
        )
        .expect("Error creating self-update");

    // Check that there's no proposal in it.
    let serialized_message = commit_bundle
        .contents()
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

    let serialized_update = commit_bundle
        .contents()
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
        provider,
        ciphersuite,
        vec![ProposalOrRef::Proposal(update_proposal.clone())],
        plaintext,
        &original_plaintext,
        &alice_group,
        &alice_credential_with_key_and_signer.signer,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(provider, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::CommitterIncludedOwnUpdate)
    ));

    // Now we insert the proposal into Bob's proposal store so we can include it
    // in the commit by reference.
    bob_group
        .store_pending_proposal(
            provider.storage(),
            QueuedProposal::from_proposal_and_sender(
                ciphersuite,
                provider.crypto(),
                update_proposal.clone(),
                &Sender::build_member(alice_group.own_leaf_index()),
            )
            .expect("error creating queued proposal"),
        )
        .expect("error writing to storage");

    // Now we can have Alice create a new commit and insert the proposal by
    // reference.

    // Wipe any pending commit first.
    alice_group
        .clear_pending_commit(provider.storage())
        .unwrap();

    let commit = alice_group
        .self_update(
            provider,
            &alice_credential_with_key_and_signer.signer,
            LeafNodeParameters::default(),
        )
        .expect("Error creating self-update");

    let serialized_update = commit
        .into_contents()
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
        provider,
        ciphersuite,
        vec![ProposalOrRef::Reference(
            ProposalRef::from_raw_proposal(ciphersuite, provider.crypto(), &update_proposal)
                .expect("error creating hash reference"),
        )],
        plaintext,
        &original_plaintext,
        &alice_group,
        &alice_credential_with_key_and_signer.signer,
    );

    let update_message_in = ProtocolMessage::from(verifiable_plaintext);

    // Have bob process the resulting plaintext
    let err = bob_group
        .process_message(provider, update_message_in)
        .expect_err("Could process message despite modified public key in path.");

    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::CommitterIncludedOwnUpdate
        ))
    ));

    let original_update_plaintext =
        MlsMessageIn::tls_deserialize(&mut serialized_update.as_slice())
            .expect("Could not deserialize message.");

    // Positive case
    bob_group
        .process_message(
            provider,
            original_update_plaintext
                .try_into_protocol_message()
                .unwrap(),
        )
        .expect("Unexpected error.");
}

/// ValSem112
/// Update Proposal:
/// The sender of a standalone update proposal must be of type member
#[openmls_test::openmls_test]
fn test_valsem112() {
    // Before we can test creation or reception of (invalid) proposals, we set
    // up a new group with Alice and Bob.
    let ProposalValidationTestSetup {
        mut alice_group,
        alice_credential_with_key_and_signer,
        mut bob_group,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    // This can really only be tested by the receiver, as there is no way to
    // make a client create a proposal with a different sender type than
    // `member`.

    // However, we can test the receiving side by crafting such a proposal
    // manually.
    let commit = alice_group
        .propose_self_update(
            provider,
            &alice_credential_with_key_and_signer.signer,
            LeafNodeParameters::default(),
        )
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
        .process_message(provider, update_message_in)
        .expect_err("Could parse message despite modified public key in path.");

    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::NotACommit)
    ));

    // We can't test with sender type External, since that currently panics
    // with `unimplemented`.
    // TODO This test should thus be extended when fixing #106.

    // Positive case
    bob_group
        .process_message(provider, ProtocolMessage::from(original_plaintext))
        .expect("Unexpected error.");
}

/// ValSem113
/// All Proposals: The proposal type must be supported by all members of the
/// group
#[openmls_test::openmls_test]
fn valsem113() {
    #[derive(Debug)]
    enum TestMode {
        Unsupported,
        Supported,
    }

    let custom_proposal_type = 0xFFFF;
    let custom_proposal_payload = vec![0, 1, 2, 3];
    let custom_proposal =
        CustomProposal::new(custom_proposal_type, custom_proposal_payload.clone());

    let capabilities_with_support = Capabilities::new(
        None,
        None,
        None,
        Some(&[ProposalType::Custom(custom_proposal_type)]),
        None,
    );

    let mls_group_config = MlsGroupJoinConfig::default();

    // Generate credentials with keys
    let alice_credential_with_keys =
        generate_credential_with_key(b"alice".into(), ciphersuite.signature_algorithm(), provider);

    let bob_credential_with_keys =
        generate_credential_with_key(b"bob".into(), ciphersuite.signature_algorithm(), provider);

    for test_mode in [TestMode::Unsupported, TestMode::Supported] {
        // Before we can test creation or reception of a commit with an
        // (unsupported) custom proposal, we set up a new group with Alice and Bob.

        // Generate Bob's KeyPackage depending on the test mode
        let bob_key_package = if matches!(test_mode, TestMode::Unsupported) {
            KeyPackageBuilder::new()
        } else {
            KeyPackageBuilder::new().leaf_node_capabilities(capabilities_with_support.clone())
        }
        .build(
            ciphersuite,
            provider,
            &bob_credential_with_keys.signer,
            bob_credential_with_keys.credential_with_key.clone(),
        )
        .unwrap();

        // Create a group with the defined capabilities
        let mut alice_group = if matches!(test_mode, TestMode::Unsupported) {
            MlsGroup::builder()
        } else {
            MlsGroup::builder().with_capabilities(capabilities_with_support.clone())
        }
        .ciphersuite(ciphersuite)
        .build(
            provider,
            &alice_credential_with_keys.signer,
            alice_credential_with_keys.credential_with_key.clone(),
        )
        .unwrap();

        // Add Bob
        let (_mls_message, welcome, _group_info) = alice_group
            .add_members(
                provider,
                &alice_credential_with_keys.signer,
                &[bob_key_package.key_package().clone()],
            )
            .unwrap();

        alice_group.merge_pending_commit(provider).unwrap();

        let staged_welcome = StagedWelcome::new_from_welcome(
            provider,
            &mls_group_config,
            welcome.into_welcome().unwrap(),
            Some(alice_group.export_ratchet_tree().into()),
        )
        .unwrap();

        let mut bob_group = staged_welcome.into_group(provider).unwrap();

        // Have alice create a commit with a custom proposal.
        let (custom_proposal_message, _proposal_ref) = alice_group
            .propose_custom_proposal_by_reference(
                provider,
                &alice_credential_with_keys.signer,
                custom_proposal.clone(),
            )
            .unwrap();

        let result =
            alice_group.commit_to_pending_proposals(provider, &alice_credential_with_keys.signer);

        // If the proposal is unsupported, we expect an error here.
        let (commit, _, _) = if matches!(test_mode, TestMode::Unsupported) {
            assert!(matches!(
                result,
                Err(CommitToPendingProposalsError::CreateCommitError(
                    CreateCommitError::ProposalValidationError(
                        ProposalValidationError::UnsupportedProposalType
                    )
                ))
            ));
            continue;
        } else {
            result.expect("Error creating commit")
        };

        // Have bob process the custom proposal first.
        let processed_message = bob_group
            .process_message(
                provider,
                custom_proposal_message.into_protocol_message().unwrap(),
            )
            .unwrap();

        if let ProcessedMessageContent::ProposalMessage(proposal) = processed_message.into_content()
        {
            bob_group
                .store_pending_proposal(provider.storage(), *proposal)
                .unwrap();
        } else {
            panic!("Unexpected message type");
        }

        let result = bob_group.process_message(provider, commit.into_protocol_message().unwrap());

        // If the proposal is unsupported, we expect an error here.
        let _processed_message = if matches!(test_mode, TestMode::Unsupported) {
            assert!(matches!(
                result,
                Err(ProcessMessageError::InvalidCommit(
                    StageCommitError::ProposalValidationError(
                        ProposalValidationError::UnsupportedProposalType
                    )
                ))
            ));
            continue;
        } else {
            // If the proposal is supported, we expect no error.
            result.expect("Error processing commit")
        };
    }
}

// --- PreSharedKey Proposals ---

#[openmls_test::openmls_test]
fn test_valsem401_valsem402() {
    let ProposalValidationTestSetup {
        mut alice_group,
        alice_credential_with_key_and_signer,
        mut bob_group,
        ..
    } = validation_test_setup(PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ciphersuite, provider);

    let alice_provider = Provider::default();
    let bob_provider = Provider::default();

    // TODO(#1354): This is currently not tested because we can't easily create invalid commits.
    let bad_psks: [(Vec<PreSharedKeyId>, ProcessMessageError); 0] = [
        // // ValSem401
        // (
        //     vec![PreSharedKeyId::external(
        //         b"irrelevant".to_vec(),
        //         zero(ciphersuite.hash_length() + 1),
        //     )],
        //     ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
        //         ProposalValidationError::Psk(PskError::NonceLengthMismatch {
        //             expected: ciphersuite.hash_length(),
        //             got: ciphersuite.hash_length() + 1,
        //         }),
        //     )),
        // ),
        // // ValSem401
        // (
        //     vec![PreSharedKeyId::external(
        //         b"irrelevant".to_vec(),
        //         zero(ciphersuite.hash_length() - 1),
        //     )],
        //     ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
        //         ProposalValidationError::Psk(PskError::NonceLengthMismatch {
        //             expected: ciphersuite.hash_length(),
        //             got: ciphersuite.hash_length() - 1,
        //         }),
        //     )),
        // ),
        // // ValSem402
        // (
        //     vec![PreSharedKeyId::resumption(
        //         ResumptionPskUsage::Reinit,
        //         alice_group.group_id().clone(),
        //         alice_group.epoch(),
        //         zero(ciphersuite.hash_length()),
        //     )],
        //     ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
        //         ProposalValidationError::Psk(PskError::UsageMismatch {
        //             allowed: vec![ResumptionPskUsage::Application],
        //             got: ResumptionPskUsage::Reinit,
        //         }),
        //     )),
        // ),
        // // ValSem402
        // (
        //     vec![PreSharedKeyId::resumption(
        //         ResumptionPskUsage::Branch,
        //         alice_group.group_id().clone(),
        //         alice_group.epoch(),
        //         zero(ciphersuite.hash_length()),
        //     )],
        //     ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
        //         ProposalValidationError::Psk(PskError::UsageMismatch {
        //             allowed: vec![ResumptionPskUsage::Application],
        //             got: ResumptionPskUsage::Branch,
        //         }),
        //     )),
        // ),
        // TODO(#1335): We could remove this test after #1335 is closed because it would cover it.
        // ValSem403
        // (
        //     vec![
        //         PreSharedKeyId::external(b"irrelevant".to_vec(), zero(ciphersuite.hash_length())),
        //         PreSharedKeyId::external(b"irrelevant".to_vec(), zero(ciphersuite.hash_length())),
        //     ],
        //     ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
        //         ProposalValidationError::Psk(PskError::Duplicate {
        //             first: PreSharedKeyId::external(
        //                 b"irrelevant".to_vec(),
        //                 zero(ciphersuite.hash_length()),
        //             ),
        //         }),
        //     )),
        // ),
    ];

    for (psk_ids, expected_error) in bad_psks.into_iter() {
        let mut proposals = Vec::new();

        for psk_id in psk_ids {
            psk_id.store(&alice_provider, b"irrelevant").unwrap();
            psk_id.store(&bob_provider, b"irrelevant").unwrap();

            let (psk_proposal, _) = alice_group
                .propose_external_psk(
                    &alice_provider,
                    &alice_credential_with_key_and_signer.signer,
                    psk_id,
                )
                .unwrap();

            proposals.push(psk_proposal);
        }

        let (commit, _, _) = alice_group
            .commit_to_pending_proposals(
                &alice_provider,
                &alice_credential_with_key_and_signer.signer,
            )
            .unwrap();

        alice_group
            .clear_pending_proposals(provider.storage())
            .unwrap();
        alice_group
            .clear_pending_commit(provider.storage())
            .unwrap();

        for psk_proposal in proposals.into_iter() {
            let processed_message = bob_group
                .process_message(&bob_provider, psk_proposal.into_protocol_message().unwrap())
                .unwrap();

            match processed_message.into_content() {
                ProcessedMessageContent::ProposalMessage(queued_proposal) => {
                    bob_group
                        .store_pending_proposal(provider.storage(), *queued_proposal)
                        .unwrap();
                }
                _ => unreachable!(),
            }
        }

        assert_eq!(
            expected_error,
            bob_group
                .process_message(&bob_provider, commit.into_protocol_message().unwrap())
                .unwrap_err(),
        );

        bob_group
            .clear_pending_proposals(provider.storage())
            .unwrap();
        bob_group.clear_pending_commit(provider.storage()).unwrap();
    }
}
