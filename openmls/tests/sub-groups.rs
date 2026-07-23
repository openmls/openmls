//! Tests for sub-groups of MLS groups.
//!
//! A new group can be formed from a subset of an existing group's members,
//! using the same parameters as the old group.
//! <https://www.rfc-editor.org/rfc/rfc9420.html#name-subgroup-branching>

use openmls::{prelude::*, test_utils::single_group_test_framework::generate_credential};
use openmls_test::openmls_test;
use openmls_traits::signatures::Signer;

/// Set up a group with Alice, Bob and Charlie, where Bob joins via the regular
/// welcome path. Returns the three providers/credentials/signers and the two
/// groups (Alice's and Bob's view).
#[allow(clippy::type_complexity)]
fn setup_group(
    ciphersuite: Ciphersuite,
    create_config: &MlsGroupCreateConfig,
    alice_provider: &impl OpenMlsProvider,
    bob_provider: &impl OpenMlsProvider,
    charlie_provider: &impl OpenMlsProvider,
) -> (
    (CredentialWithKey, impl Signer),
    (CredentialWithKey, impl Signer),
    MlsGroup,
    MlsGroup,
) {
    let (alice_credential, alice_signer) = generate_credential(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let (bob_credential, bob_signer) = generate_credential(
        b"Bob".to_vec(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );
    let (charlie_credential, charlie_signer) = generate_credential(
        b"Charlie".to_vec(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );

    let bob_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            bob_provider,
            &bob_signer,
            bob_credential.clone(),
        )
        .unwrap();
    let charlie_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            charlie_provider,
            &charlie_signer,
            charlie_credential,
        )
        .unwrap();

    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        create_config,
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");

    let welcome = match alice_group.add_members(
        alice_provider,
        &alice_signer,
        &[
            bob_key_package.key_package().clone(),
            charlie_key_package.key_package().clone(),
        ],
    ) {
        Ok((_, welcome, _)) => welcome,
        Err(e) => panic!("Could not add member to group: {e:?}"),
    };
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating StagedWelcome from Welcome")
    .into_group(bob_provider)
    .expect("Error creating group from StagedWelcome");

    (
        (alice_credential, alice_signer),
        (bob_credential, bob_signer),
        alice_group,
        bob_group,
    )
}

/// Happy path: Alice branches an Alice+Bob subgroup from the original group and
/// Bob joins it with [`StagedWelcome::build_from_branch`].
#[openmls_test]
fn subgroup_branching() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .build();

    let ((alice_credential, alice_signer), (bob_credential, bob_signer), alice_group, bob_group) =
        setup_group(
            ciphersuite,
            &mls_group_create_config,
            alice_provider,
            bob_provider,
            charlie_provider,
        );

    // === Alice creates a subgroup with Alice and Bob ===
    let bob_new_key_package = KeyPackage::builder()
        .build(ciphersuite, bob_provider, &bob_signer, bob_credential)
        .unwrap();

    // Creating the sub-group and its branch commit is a single builder
    // operation. The sub-group uses the parent's ciphersuite automatically.
    let (mut alice_bob_sub_group, commit_message_bundle) = MlsGroup::builder()
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .branch(alice_group.branch_info())
        .build_branch(
            alice_provider,
            &alice_signer,
            alice_credential,
            vec![bob_new_key_package.key_package().clone()],
        )
        .unwrap();
    // The commit is merged only once the delivery service confirms it.
    alice_bob_sub_group
        .merge_pending_commit(alice_provider)
        .unwrap();

    let branching_welcome = MlsMessageOut::from_welcome(
        commit_message_bundle.welcome().unwrap().clone(),
        ProtocolVersion::Mls10,
    );
    let welcome: MlsMessageIn = branching_welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    // === Bob joins the subgroup ===
    let bob_alice_sub_group = StagedWelcome::build_from_branch(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        bob_group.branch_info(),
    )
    .expect("Bob could not process the branch welcome")
    .build()
    .expect("Bob could not join the subgroup")
    .into_group(bob_provider)
    .expect("Error creating group from StagedWelcome");

    assert_eq!(
        alice_bob_sub_group.confirmation_tag(),
        bob_alice_sub_group.confirmation_tag()
    );
}

/// A joiner must reject a subgroup whose members do not all match members of the
/// parent group (RFC 9420 §11.3 receiver check c).
#[openmls_test]
fn subgroup_branch_rejects_non_matching_leaf() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let dave_provider = &Provider::default();

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .build();

    let ((alice_credential, alice_signer), (bob_credential, bob_signer), alice_group, bob_group) =
        setup_group(
            ciphersuite,
            &mls_group_create_config,
            alice_provider,
            bob_provider,
            charlie_provider,
        );

    // Dave is NOT a member of the original (parent) group.
    let (dave_credential, dave_signer) = generate_credential(
        b"Dave".to_vec(),
        ciphersuite.signature_algorithm(),
        dave_provider,
    );
    let dave_key_package = KeyPackage::builder()
        .build(ciphersuite, dave_provider, &dave_signer, dave_credential)
        .unwrap();

    let bob_new_key_package = KeyPackage::builder()
        .build(ciphersuite, bob_provider, &bob_signer, bob_credential)
        .unwrap();

    // Alice branches a subgroup that (incorrectly) also adds Dave.
    let (mut sub_group, commit_message_bundle) = MlsGroup::builder()
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .branch(alice_group.branch_info())
        .build_branch(
            alice_provider,
            &alice_signer,
            alice_credential,
            vec![
                bob_new_key_package.key_package().clone(),
                dave_key_package.key_package().clone(),
            ],
        )
        .unwrap();
    sub_group.merge_pending_commit(alice_provider).unwrap();

    let welcome = MlsMessageOut::from_welcome(
        commit_message_bundle.welcome().unwrap().clone(),
        ProtocolVersion::Mls10,
    );
    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome.into_welcome().unwrap();

    // Bob checks the subgroup against his view of the parent group and must
    // reject it because Dave has no matching leaf there.
    let result = StagedWelcome::build_from_branch(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        bob_group.branch_info(),
    )
    .expect("Bob could not process the branch welcome")
    .build();

    assert!(
        matches!(result, Err(WelcomeError::SubgroupLeafMismatch)),
        "expected a subgroup with a non-parent member to be rejected, got {result:?}"
    );
}

/// A joiner must reject a branch whose branch PSK references a different parent
/// epoch than the `BranchInfo` the joiner supplies (RFC 9420 §11.3). This happens
/// when the joiner's view of the parent group has advanced (an unrelated commit
/// arrived) between when the branch was created and when its `Welcome` is joined.
#[openmls_test]
fn subgroup_branch_rejects_parent_epoch_mismatch() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .build();

    let (
        (alice_credential, alice_signer),
        (bob_credential, bob_signer),
        alice_group,
        mut bob_group,
    ) = setup_group(
        ciphersuite,
        &mls_group_create_config,
        alice_provider,
        bob_provider,
        charlie_provider,
    );

    // Alice branches a subgroup from the parent's current epoch.
    let bob_new_key_package = KeyPackage::builder()
        .build(ciphersuite, bob_provider, &bob_signer, bob_credential)
        .unwrap();

    let (mut sub_group, commit_message_bundle) = MlsGroup::builder()
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .branch(alice_group.branch_info())
        .build_branch(
            alice_provider,
            &alice_signer,
            alice_credential,
            vec![bob_new_key_package.key_package().clone()],
        )
        .unwrap();
    sub_group.merge_pending_commit(alice_provider).unwrap();

    let welcome = MlsMessageOut::from_welcome(
        commit_message_bundle.welcome().unwrap().clone(),
        ProtocolVersion::Mls10,
    );
    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome.into_welcome().unwrap();

    // Bob's view of the parent group advances one epoch before he joins the
    // branch, so his `branch_info()` now reports a different parent epoch than the
    // one Alice branched from.
    bob_group
        .self_update(bob_provider, &bob_signer, LeafNodeParameters::default())
        .unwrap();
    bob_group.merge_pending_commit(bob_provider).unwrap();

    // The mismatch is detected while processing the branch welcome, before the
    // wrong-epoch resumption PSK secret is mixed into the key schedule.
    let result = StagedWelcome::build_from_branch(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        bob_group.branch_info(),
    );

    assert!(
        matches!(result, Err(WelcomeError::SubgroupParentMismatch)),
        "expected a branch from a mismatched parent epoch to be rejected, got {:?}",
        result.map(|_| ())
    );
}

/// A plain (non-branch) welcome carries no branch resumption PSK, so joining it
/// via [`StagedWelcome::build_from_branch`] must be rejected rather than silently
/// treated as a branch.
#[openmls_test]
fn build_from_branch_rejects_non_branch_welcome() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();
    let eve_provider = &Provider::default();

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .build();

    let ((_, alice_signer), _, mut alice_group, bob_group) = setup_group(
        ciphersuite,
        &mls_group_create_config,
        alice_provider,
        bob_provider,
        charlie_provider,
    );

    // Alice adds Eve with a regular (non-branch) commit; this yields a plain
    // welcome with no branch PSK.
    let (eve_credential, eve_signer) = generate_credential(
        b"Eve".to_vec(),
        ciphersuite.signature_algorithm(),
        eve_provider,
    );
    let eve_key_package = KeyPackage::builder()
        .build(ciphersuite, eve_provider, &eve_signer, eve_credential)
        .unwrap();

    let (_, welcome, _) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            &[eve_key_package.key_package().clone()],
        )
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome.into_welcome().unwrap();

    // Eve tries to join this plain welcome as if it were a branch. It must be
    // rejected: the welcome references no parent group/epoch via a branch PSK.
    let result = StagedWelcome::build_from_branch(
        eve_provider,
        mls_group_create_config.join_config(),
        welcome,
        bob_group.branch_info(),
    );

    assert!(
        matches!(result, Err(WelcomeError::SubgroupParentMismatch)),
        "expected a non-branch welcome to be rejected by build_from_branch, got {:?}",
        result.map(|_| ())
    );
}

// TODO: To test the following two error cases we'd need to build an invalid
//       commit message.
// - `SubgroupParameterMismatch`
// - `SubgroupEpochInvalid`
