//! Tests for sub-groups of MLS groups.
//!
//! A new group can be formed from a subset of an existing group's members,
//! using the same parameters as the old group.
//! <https://www.rfc-editor.org/rfc/rfc9420.html#name-subgroup-branching>

use openmls::{
    prelude::*, schedule::errors::PskError,
    test_utils::single_group_test_framework::generate_credential,
};
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
/// Bob joins it with [`StagedWelcome::new_from_branch`].
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

    let mut alice_bob_sub_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        alice_credential,
    )
    .expect("An unexpected error occurred.");

    let commit_message_bundle = alice_bob_sub_group
        .commit_builder()
        .branch(alice_provider.rand(), &alice_group)
        .unwrap()
        .propose_adds([bob_new_key_package.key_package().clone()])
        .load_psks(alice_provider.storage())
        .unwrap()
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap();
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
    let bob_alice_sub_group = StagedWelcome::new_from_branch(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        None,
        &bob_group,
        true,
    )
    .expect("Bob could not join the subgroup")
    .into_group(bob_provider)
    .expect("Error creating group from StagedWelcome");

    assert_eq!(
        alice_bob_sub_group.confirmation_tag(),
        bob_alice_sub_group.confirmation_tag()
    );
}

/// A resumption PSK of usage `Branch` must only appear in the initial commit of
/// a subgroup (i.e. at epoch 0). Using it in any later commit must be rejected.
#[openmls_test]
fn subgroup_branch_psk_rejected_outside_initial_commit() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .build();

    // `alice_group` is at epoch 1 after adding Bob and Charlie, so a branch PSK
    // in a commit on it must be rejected.
    let ((_alice_credential, alice_signer), _, mut alice_group, _bob_group) = setup_group(
        ciphersuite,
        &mls_group_create_config,
        alice_provider,
        bob_provider,
        charlie_provider,
    );

    // Use a separate group as the (arbitrary) source of the branch PSK secret,
    // so that `load_psks` succeeds and we actually reach the proposal validation.
    let (parent_credential, parent_signer) = generate_credential(
        b"Parent".to_vec(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let parent_group = MlsGroup::new(
        alice_provider,
        &parent_signer,
        &mls_group_create_config,
        parent_credential,
    )
    .unwrap();

    let result = alice_group
        .commit_builder()
        .branch(alice_provider.rand(), &parent_group)
        .unwrap()
        .load_psks(alice_provider.storage())
        .unwrap()
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signer,
            |_| true,
        );

    assert!(
        matches!(
            result,
            Err(CreateCommitError::ProposalValidationError(
                ProposalValidationError::Psk(PskError::NotAllowed)
            ))
        ),
        "expected a branch PSK outside the initial commit to be rejected, got {result:?}"
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
    let mut sub_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        alice_credential,
    )
    .unwrap();

    let commit_message_bundle = sub_group
        .commit_builder()
        .branch(alice_provider.rand(), &alice_group)
        .unwrap()
        .propose_adds([
            bob_new_key_package.key_package().clone(),
            dave_key_package.key_package().clone(),
        ])
        .load_psks(alice_provider.storage())
        .unwrap()
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
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
    let result = StagedWelcome::new_from_branch(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        None,
        &bob_group,
        true,
    );

    assert!(
        matches!(result, Err(WelcomeError::SubgroupLeafMismatch)),
        "expected a subgroup with a non-parent member to be rejected, got {result:?}"
    );
}
