//! Tests for passing a `LeafNodeLifetimePolicy` per call.

use std::time::{SystemTime, UNIX_EPOCH};

use openmls::{
    messages::group_info::VerifiableGroupInfo,
    prelude::{test_utils::new_credential, *},
    treesync::errors::{LeafNodeValidationError, LifetimeError},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Member<Provider> {
    provider: Provider,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

fn create_config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        // Public messages, so that a public group can follow the group.
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build()
}

fn key_package<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
    name: &[u8],
    not_before: u64,
    not_after: u64,
) -> (KeyPackage, SignatureKeyPair) {
    let (credential, signer) = new_credential(provider, name, ciphersuite.signature_algorithm());
    let bundle = KeyPackage::builder()
        .key_package_lifetime(Lifetime::init(not_before, not_after))
        .build(ciphersuite, provider, &signer, credential)
        .unwrap();
    (bundle.key_package().clone(), signer)
}

/// Alice creates a group and adds Charlie with a key package that is valid
/// now.
fn alice_and_charlie<Provider: OpenMlsProvider + Default>(
    ciphersuite: Ciphersuite,
) -> (Member<Provider>, Member<Provider>) {
    let config = create_config(ciphersuite);

    let alice_provider = Provider::default();
    let (alice_credential, alice_signer) =
        new_credential(&alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let mut alice_group =
        MlsGroup::new(&alice_provider, &alice_signer, &config, alice_credential).unwrap();

    let charlie_provider = Provider::default();
    let (charlie_key_package, charlie_signer) = key_package(
        ciphersuite,
        &charlie_provider,
        b"Charlie",
        now() - 60,
        now() + 3600,
    );
    let (_, welcome, _) = alice_group
        .add_members(&alice_provider, &alice_signer, &[charlie_key_package])
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();
    let welcome = match MlsMessageIn::from(welcome).extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("expected a Welcome"),
    };
    let charlie_group =
        StagedWelcome::new_from_welcome(&charlie_provider, config.join_config(), welcome, None)
            .unwrap()
            .into_group(&charlie_provider)
            .unwrap();

    (
        Member {
            provider: alice_provider,
            signer: alice_signer,
            group: alice_group,
        },
        Member {
            provider: charlie_provider,
            signer: charlie_signer,
            group: charlie_group,
        },
    )
}

/// The commit message and the Welcome of a commit that adds `key_package`.
struct AddCommit {
    commit: MlsMessageOut,
    welcome: Option<MlsMessageOut>,
}

/// `committer` builds a commit that adds `key_package`, checking its lifetime
/// under `policy`, and merges it if building succeeds.
fn commit_add<Provider: OpenMlsProvider>(
    committer: &mut Member<Provider>,
    key_package: KeyPackage,
    policy: LeafNodeLifetimePolicy,
) -> Result<AddCommit, CreateCommitError> {
    let bundle = committer
        .group
        .commit_builder()
        .propose_adds([key_package])
        .leaf_node_lifetime_policy(policy)
        .load_psks(committer.provider.storage())
        .unwrap()
        .build(
            committer.provider.rand(),
            committer.provider.crypto(),
            &committer.signer,
            |_| true,
        )?
        .stage_commit(&committer.provider)
        .unwrap();
    committer
        .group
        .merge_pending_commit(&committer.provider)
        .unwrap();
    let (commit, welcome, _) = bundle.into_messages();
    Ok(AddCommit { commit, welcome })
}

fn verifiable_group_info<Provider: OpenMlsProvider>(
    member: &Member<Provider>,
) -> VerifiableGroupInfo {
    member
        .group
        .export_group_info(member.provider.crypto(), &member.signer, true)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap()
}

/// The lifetime error of a key package that made the message fail
/// verification, if any.
fn lifetime_error<StorageError>(err: &ProcessMessageError<StorageError>) -> Option<&LifetimeError> {
    match err {
        ProcessMessageError::ValidationError(ValidationError::KeyPackageVerifyError(
            KeyPackageVerifyError::LifetimeError(err),
        )) => Some(err),
        _ => None,
    }
}

fn protocol_message(message: &MlsMessageOut) -> ProtocolMessage {
    MlsMessageIn::from(message.clone())
        .try_into_protocol_message()
        .unwrap()
}

fn process_and_merge<Provider: OpenMlsProvider>(
    member: &mut Member<Provider>,
    commit: &MlsMessageOut,
    policy: LeafNodeLifetimePolicy,
) {
    let processed = member
        .group
        .process_message_with_lifetime_policy(&member.provider, protocol_message(commit), policy)
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("expected a commit");
    };
    member
        .group
        .merge_staged_commit(&member.provider, *staged)
        .unwrap();
}

/// The application passes its own time. Bob's key package is not valid yet
/// by the system clock, but it is at that time. With `VerifyAt`, building the
/// commit, processing it, joining from the Welcome and joining with an
/// external commit succeed.
#[openmls_test]
fn a_given_time_replaces_the_system_clock() {
    let (mut alice, mut charlie) = alice_and_charlie::<Provider>(ciphersuite);
    let later = now() + 1500;

    let bob_provider = Provider::default();
    let (bob_key_package, _) = key_package(
        ciphersuite,
        &bob_provider,
        b"Bob",
        now() + 1000,
        now() + 2000,
    );

    let err = commit_add(
        &mut alice,
        bob_key_package.clone(),
        LeafNodeLifetimePolicy::Verify,
    )
    .err()
    .expect("the key package is not valid yet");
    assert!(matches!(
        err,
        CreateCommitError::ProposalValidationError(ProposalValidationError::LeafNodeValidation(
            LeafNodeValidationError::Lifetime(LifetimeError::NotValidYet { .. })
        ))
    ));

    let add = commit_add(
        &mut alice,
        bob_key_package,
        LeafNodeLifetimePolicy::VerifyAt(later),
    )
    .unwrap();

    let err = charlie
        .group
        .process_message(&charlie.provider, protocol_message(&add.commit))
        .expect_err("the key package is not valid yet");
    assert!(matches!(
        lifetime_error(&err),
        Some(LifetimeError::NotValidYet { .. })
    ));
    process_and_merge(
        &mut charlie,
        &add.commit,
        LeafNodeLifetimePolicy::VerifyAt(later),
    );

    let welcome = match MlsMessageIn::from(add.welcome.unwrap()).extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("expected a Welcome"),
    };
    let join_config = create_config(ciphersuite).join_config().clone();
    // The ratchet tree holds Bob's leaf node, which is not valid yet by the
    // system clock.
    let bob_group = StagedWelcome::build_from_welcome(&bob_provider, &join_config, welcome)
        .unwrap()
        .leaf_node_lifetime_policy(LeafNodeLifetimePolicy::VerifyAt(later))
        .build()
        .unwrap()
        .into_group(&bob_provider)
        .unwrap();

    assert_eq!(alice.group.epoch(), charlie.group.epoch());
    assert_eq!(alice.group.epoch(), bob_group.epoch());

    // Erin joins with an external commit.
    let erin_provider = Provider::default();
    let (erin_credential, erin_signer) =
        new_credential(&erin_provider, b"Erin", ciphersuite.signature_algorithm());
    let err = MlsGroup::external_commit_builder()
        .build_group(
            &erin_provider,
            verifiable_group_info(&alice),
            erin_credential.clone(),
        )
        .expect_err("Bob's leaf node is not valid yet");
    assert!(matches!(
        err,
        ExternalCommitBuilderError::PublicGroupError(
            CreationFromExternalError::LeafNodeValidation(LeafNodeValidationError::Lifetime(
                LifetimeError::NotValidYet { .. }
            ))
        )
    ));
    MlsGroup::external_commit_builder()
        .leaf_node_lifetime_policy(LeafNodeLifetimePolicy::VerifyAt(later))
        .build_group(
            &erin_provider,
            verifiable_group_info(&alice),
            erin_credential,
        )
        .unwrap()
        .load_psks(erin_provider.storage())
        .unwrap()
        .build(
            erin_provider.rand(),
            erin_provider.crypto(),
            &erin_signer,
            |_| true,
        )
        .unwrap()
        .finalize(&erin_provider)
        .unwrap();
}

/// Branching into a sub-group builds a commit that adds the new members, so
/// `BranchGroupBuilder` takes the policy too.
#[openmls_test]
fn a_branch_takes_the_policy() {
    let alice_provider = Provider::default();
    let (alice_credential, alice_signer) =
        new_credential(&alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .number_of_resumption_psks(5)
        .build();
    let alice_group = MlsGroup::new(
        &alice_provider,
        &alice_signer,
        &config,
        alice_credential.clone(),
    )
    .unwrap();

    let bob_provider = Provider::default();
    let (bob_key_package, _) = key_package(
        ciphersuite,
        &bob_provider,
        b"Bob",
        now() + 1000,
        now() + 2000,
    );
    let branch = || {
        MlsGroup::builder()
            .number_of_resumption_psks(5)
            .branch(alice_group.branch_info())
    };

    let err = branch()
        .build_branch(
            &alice_provider,
            &alice_signer,
            alice_credential.clone(),
            vec![bob_key_package.clone()],
        )
        .expect_err("Bob's key package is not valid yet");
    assert!(matches!(
        err,
        BranchError::CreateCommit(CreateCommitError::ProposalValidationError(
            ProposalValidationError::LeafNodeValidation(LeafNodeValidationError::Lifetime(
                LifetimeError::NotValidYet { .. }
            ))
        ))
    ));
    branch()
        .leaf_node_lifetime_policy(LeafNodeLifetimePolicy::VerifyAt(now() + 1500))
        .build_branch(
            &alice_provider,
            &alice_signer,
            alice_credential,
            vec![bob_key_package],
        )
        .unwrap();
}

/// Charlie processes a commit after the key package it adds has expired. With
/// `Skip` the commit goes through. The policy is not stored, so the next
/// commit with an expired key package fails again with the default.
#[openmls_test]
fn catching_up_after_a_key_package_expired() {
    let (mut alice, mut charlie) = alice_and_charlie::<Provider>(ciphersuite);
    let then = now() - 1500;

    let bob_provider = Provider::default();
    let (bob_key_package, _) = key_package(
        ciphersuite,
        &bob_provider,
        b"Bob",
        now() - 2000,
        now() - 1000,
    );
    // The commit is built at a time the key package was valid.
    let add_bob = commit_add(
        &mut alice,
        bob_key_package,
        LeafNodeLifetimePolicy::VerifyAt(then),
    )
    .unwrap();

    let err = charlie
        .group
        .process_message(&charlie.provider, protocol_message(&add_bob.commit))
        .expect_err("the key package has expired");
    assert!(matches!(
        lifetime_error(&err),
        Some(LifetimeError::Expired { .. })
    ));
    process_and_merge(&mut charlie, &add_bob.commit, LeafNodeLifetimePolicy::Skip);

    let dave_provider = Provider::default();
    let (dave_key_package, _) = key_package(
        ciphersuite,
        &dave_provider,
        b"Dave",
        now() - 2000,
        now() - 1000,
    );
    let add_dave = commit_add(
        &mut alice,
        dave_key_package,
        LeafNodeLifetimePolicy::VerifyAt(then),
    )
    .unwrap();
    let err = charlie
        .group
        .process_message(&charlie.provider, protocol_message(&add_dave.commit))
        .expect_err("the policy of the previous call must not carry over");
    assert!(matches!(
        lifetime_error(&err),
        Some(LifetimeError::Expired { .. })
    ));
    process_and_merge(
        &mut charlie,
        &add_dave.commit,
        LeafNodeLifetimePolicy::VerifyAt(then),
    );
    assert_eq!(alice.group.epoch(), charlie.group.epoch());
}

/// An Add proposal sent on its own and committed by reference is checked when
/// the proposal is processed and again when the commit is processed. Each
/// call takes its own policy.
#[openmls_test]
fn an_add_by_reference_is_checked_on_both_calls() {
    let (mut alice, mut charlie) = alice_and_charlie::<Provider>(ciphersuite);
    let then = now() - 1500;

    let bob_provider = Provider::default();
    let (bob_key_package, _) = key_package(
        ciphersuite,
        &bob_provider,
        b"Bob",
        now() - 2000,
        now() - 1000,
    );
    let (proposal, _) = alice
        .group
        .propose_add_member(&alice.provider, &alice.signer, &bob_key_package)
        .unwrap();
    let (commit, _, _) = alice
        .group
        .commit_builder()
        .leaf_node_lifetime_policy(LeafNodeLifetimePolicy::VerifyAt(then))
        .load_psks(alice.provider.storage())
        .unwrap()
        .build(
            alice.provider.rand(),
            alice.provider.crypto(),
            &alice.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(&alice.provider)
        .unwrap()
        .into_messages();
    alice.group.merge_pending_commit(&alice.provider).unwrap();

    let err = charlie
        .group
        .process_message(&charlie.provider, protocol_message(&proposal))
        .expect_err("the key package has expired");
    assert!(matches!(
        lifetime_error(&err),
        Some(LifetimeError::Expired { .. })
    ));
    let processed = charlie
        .group
        .process_message_with_lifetime_policy(
            &charlie.provider,
            protocol_message(&proposal),
            LeafNodeLifetimePolicy::Skip,
        )
        .unwrap();
    let ProcessedMessageContent::ProposalMessage(queued_proposal) = processed.into_content() else {
        panic!("expected a proposal");
    };
    charlie
        .group
        .store_pending_proposal(charlie.provider.storage(), *queued_proposal)
        .unwrap();

    // The commit carries only a reference, so the key package is checked when
    // the commit is staged.
    let err = charlie
        .group
        .process_message(&charlie.provider, protocol_message(&commit))
        .expect_err("the key package has expired");
    assert!(matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
            ProposalValidationError::LeafNodeValidation(LeafNodeValidationError::Lifetime(
                LifetimeError::Expired { .. }
            ))
        ))
    ));
    process_and_merge(&mut charlie, &commit, LeafNodeLifetimePolicy::Skip);
    assert_eq!(alice.group.epoch(), charlie.group.epoch());
}

/// A delivery service follows the group with a `PublicGroup`. The ratchet tree
/// holds Bob's leaf node, whose lifetime has expired, and the next commit adds
/// Dave with an expired key package. Both fail with the default and succeed
/// with `Skip`.
#[openmls_test]
fn a_public_group_with_expired_leaf_nodes() {
    let (mut alice, _charlie) = alice_and_charlie::<Provider>(ciphersuite);
    let then = now() - 1500;

    let bob_provider = Provider::default();
    let (bob_key_package, _) = key_package(
        ciphersuite,
        &bob_provider,
        b"Bob",
        now() - 2000,
        now() - 1000,
    );
    commit_add(
        &mut alice,
        bob_key_package,
        LeafNodeLifetimePolicy::VerifyAt(then),
    )
    .unwrap();

    let group_info = verifiable_group_info(&alice);
    let ds_provider = Provider::default();
    let err = PublicGroup::from_external(
        ds_provider.crypto(),
        ds_provider.storage(),
        alice.group.export_ratchet_tree().into(),
        group_info.clone(),
        ProposalStore::new(),
    )
    .expect_err("Bob's leaf node has expired");
    assert!(matches!(
        err,
        CreationFromExternalError::LeafNodeValidation(LeafNodeValidationError::Lifetime(
            LifetimeError::Expired { .. }
        ))
    ));
    let (ds, _) = PublicGroup::from_external_with_lifetime_policy(
        ds_provider.crypto(),
        ds_provider.storage(),
        alice.group.export_ratchet_tree().into(),
        group_info,
        ProposalStore::new(),
        LeafNodeLifetimePolicy::Skip,
    )
    .unwrap();

    let dave_provider = Provider::default();
    let (dave_key_package, _) = key_package(
        ciphersuite,
        &dave_provider,
        b"Dave",
        now() - 2000,
        now() - 1000,
    );
    let add_dave = commit_add(
        &mut alice,
        dave_key_package,
        LeafNodeLifetimePolicy::VerifyAt(then),
    )
    .unwrap();
    let err = ds
        .process_message(ds_provider.crypto(), protocol_message(&add_dave.commit))
        .expect_err("Dave's key package has expired");
    assert!(matches!(
        err,
        PublicProcessMessageError::ValidationError(ValidationError::KeyPackageVerifyError(
            KeyPackageVerifyError::LifetimeError(LifetimeError::Expired { .. })
        ))
    ));
    let processed = ds
        .process_message_with_lifetime_policy(
            ds_provider.crypto(),
            protocol_message(&add_dave.commit),
            LeafNodeLifetimePolicy::Skip,
        )
        .unwrap();
    assert!(matches!(
        processed.into_content(),
        ProcessedMessageContent::StagedCommitMessage(_)
    ));
}

/// A key package validated on its own, at a given time and with `Skip`.
#[openmls_test]
fn a_key_package_validated_at_a_given_time() {
    let provider = Provider::default();
    let (key_package, _) = key_package(ciphersuite, &provider, b"Bob", now() + 1000, now() + 2000);
    let key_package_in = KeyPackageIn::from(key_package);

    let err = key_package_in
        .clone()
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .expect_err("the key package is not valid yet");
    assert!(matches!(
        err,
        KeyPackageVerifyError::LifetimeError(LifetimeError::NotValidYet { .. })
    ));
    key_package_in
        .clone()
        .validate_with_lifetime_policy(
            provider.crypto(),
            ProtocolVersion::Mls10,
            LeafNodeLifetimePolicy::VerifyAt(now() + 1500),
        )
        .unwrap();
    // A time that `SystemTime` cannot represent.
    let err = key_package_in
        .clone()
        .validate_with_lifetime_policy(
            provider.crypto(),
            ProtocolVersion::Mls10,
            LeafNodeLifetimePolicy::VerifyAt(u64::MAX),
        )
        .expect_err("the key package has expired");
    assert!(matches!(
        err,
        KeyPackageVerifyError::LifetimeError(LifetimeError::Expired { .. })
    ));
    key_package_in
        .validate_with_lifetime_policy(
            provider.crypto(),
            ProtocolVersion::Mls10,
            LeafNodeLifetimePolicy::Skip,
        )
        .unwrap();
}
