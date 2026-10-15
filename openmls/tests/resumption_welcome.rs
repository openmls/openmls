//! Tests [`Welcome`] handling and resumption checks.
//!
//! These tests exercise various application-side mishandling and happy paths
//! of resuming `Welcome`s, and check that appropriate errors are returned.

use openmls::{prelude::*, test_utils::single_group_test_framework::generate_credential};
use openmls_test::openmls_test;
use openmls_traits::signatures::Signer;

/// Set up a group with Alice and Bob, where Bob joins via the regular welcome
/// path. Returns Alice's and Bob's credentials/signers and their two group
/// views.
#[allow(clippy::type_complexity)]
fn setup_group(
    ciphersuite: Ciphersuite,
    create_config: &MlsGroupCreateConfig,
    alice_provider: &impl OpenMlsProvider,
    bob_provider: &impl OpenMlsProvider,
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

    let bob_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            bob_provider,
            &bob_signer,
            bob_credential.clone(),
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
        &[bob_key_package.key_package().clone()],
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

/// How a new group is created by Alice
#[derive(Clone, Copy)]
enum TestResumptionCreation {
    /// New group is reinit of old group
    ReInit,
    /// New group is branch of old group
    Branch,
    /// New group is independent of the old ones
    Normal,
}

/// How Bob joins the group
#[derive(Clone, Copy)]
enum TestResumptionUsage {
    /// Joins from ReInit
    ReInit,
    /// Joins from ReInit of wrong group
    ReInitOther,
    /// Joins from Branch
    Branch,
    /// Joins from Branch of wrong group
    BranchOther,
    /// Joins without resumption info using `new_from_welcome`
    Normal,
    /// Joins without resumption info using `PendingResumingWelcome`
    NormalIndirect,
}

/// Commits a ReInit proposal by value in `alice_group`, lets Bob process it, and
/// returns the proposal. Afterwards both groups are suspended.
fn suspend_via_reinit<Provider: OpenMlsProvider>(
    alice_provider: &Provider,
    bob_provider: &Provider,
    alice_signer: &impl Signer,
    ciphersuite: Ciphersuite,
    new_group_id: &[u8],
    alice_group: &mut MlsGroup,
    bob_group: &mut MlsGroup,
) -> ReInitProposal {
    let reinit_proposal = ReInitProposal::new(
        GroupId::from_slice(new_group_id),
        ProtocolVersion::Mls10,
        ciphersuite,
        Extensions::empty(),
    );

    let bundle = alice_group
        .commit_builder()
        .add_proposal(Proposal::re_init(reinit_proposal.clone()))
        .load_psks(alice_provider.storage())
        .unwrap()
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            alice_signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap();
    let commit_message = bundle.into_commit();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let processed = bob_group
        .process_message(
            bob_provider,
            commit_message.into_protocol_message().unwrap(),
        )
        .unwrap();
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            bob_group
                .merge_staged_commit(bob_provider, *staged)
                .unwrap();
        }
        other => panic!("expected a staged commit message, got {other:?}"),
    }
    assert!(
        !alice_group.is_active(),
        "Alice's old group must be suspended"
    );
    assert!(!bob_group.is_active(), "Bob's old group must be suspended");

    reinit_proposal
}

/// Steps:
/// * Alice creates two groups X1 and X2, each containing Bob
/// * Alice creates a new group Y from X1 according to `sender` and invites Bob. She commits Reinits as needed.
/// * Bob processes the Welcome according to `receiver`.
///   * If `expect` is `Ok(())`, assert that Y's epoch authenticators match between Alice and Bob
///   * If `expect` is `Err(e)`, assert that Bob trying to join returns this error.
fn run_resumption_constellation_test<Provider: openmls::storage::OpenMlsProvider + Default>(
    ciphersuite: Ciphersuite,
    sender: TestResumptionCreation,
    receiver: TestResumptionUsage,
    expect: Result<(), WelcomeError<Provider::StorageError>>,
) where
    Provider::StorageError: PartialEq + std::fmt::Debug,
{
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .build();

    // === Alice creates X1 and X2, each containing Bob ===
    let ((alice_credential, alice_signer), (bob_credential, bob_signer), mut alice_x1, mut bob_x1) =
        setup_group(ciphersuite, &create_config, alice_provider, bob_provider);
    let (
        (_alice_credential_x2, alice_signer_x2),
        (_bob_credential_x2, _bob_signer_x2),
        mut alice_x2,
        mut bob_x2,
    ) = setup_group(ciphersuite, &create_config, alice_provider, bob_provider);

    // Suspend the groups whose ReInit info is needed
    let x1_reinit_proposal = (matches!(sender, TestResumptionCreation::ReInit)
        || matches!(receiver, TestResumptionUsage::ReInit))
    .then(|| {
        suspend_via_reinit(
            alice_provider,
            bob_provider,
            &alice_signer,
            ciphersuite,
            b"Y",
            &mut alice_x1,
            &mut bob_x1,
        )
    });
    let x2_reinit_proposal = matches!(receiver, TestResumptionUsage::ReInitOther).then(|| {
        suspend_via_reinit(
            alice_provider,
            bob_provider,
            &alice_signer_x2,
            ciphersuite,
            b"Z",
            &mut alice_x2,
            &mut bob_x2,
        )
    });

    // === Alice creates Y according to `sender` and invites Bob ===
    let bob_y_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            bob_provider,
            &bob_signer,
            bob_credential.clone(),
        )
        .unwrap();

    let (mut alice_y, welcome) = match sender {
        TestResumptionCreation::ReInit => {
            let proposal = x1_reinit_proposal.clone().unwrap();
            let reinit_info = alice_x1.reinit_info(proposal.clone()).unwrap();

            let (alice_y, bundle) = MlsGroup::builder()
                .use_ratchet_tree_extension(true)
                .number_of_resumption_psks(5)
                .reinit(reinit_info)
                .build_reinit(
                    alice_provider,
                    &alice_signer,
                    alice_credential,
                    [bob_y_key_package.key_package().clone()],
                )
                .expect("failed to build successor group");
            (alice_y, bundle.into_welcome().expect("no welcome"))
        }
        TestResumptionCreation::Branch => {
            let (alice_y, bundle) = MlsGroup::builder()
                .use_ratchet_tree_extension(true)
                .number_of_resumption_psks(5)
                .branch(alice_x1.branch_info())
                .build_branch(
                    alice_provider,
                    &alice_signer,
                    alice_credential,
                    vec![bob_y_key_package.key_package().clone()],
                )
                .unwrap();
            (alice_y, bundle.into_welcome().expect("no welcome"))
        }
        TestResumptionCreation::Normal => {
            let mut alice_y = MlsGroup::new(
                alice_provider,
                &alice_signer,
                &create_config,
                alice_credential,
            )
            .unwrap();
            let (_, welcome, _) = alice_y
                .add_members(
                    alice_provider,
                    &alice_signer,
                    &[bob_y_key_package.key_package().clone()],
                )
                .unwrap();
            let welcome = MlsMessageIn::from(welcome)
                .into_welcome()
                .expect("expected the message to be a welcome message");
            (alice_y, welcome)
        }
    };
    alice_y.merge_pending_commit(alice_provider).unwrap();
    let ratchet_tree = alice_y.export_ratchet_tree();
    let join_config = create_config.join_config();

    // === Bob processes the Welcome according to `receiver` ===
    let bob_y: Result<MlsGroup, WelcomeError<Provider::StorageError>> = (|| match receiver {
        TestResumptionUsage::ReInit | TestResumptionUsage::ReInitOther => {
            let (bob_group, proposal) = if let TestResumptionUsage::ReInit = receiver {
                let proposal = x1_reinit_proposal.unwrap();
                (&bob_x1, proposal)
            } else {
                (&bob_x2, x2_reinit_proposal.unwrap())
            };
            let reinit_info = bob_group.reinit_info(proposal).unwrap();
            StagedWelcome::build_from_reinit(bob_provider, join_config, welcome, reinit_info)?
                .with_ratchet_tree(ratchet_tree.into())
                .build()?
                .into_group(bob_provider)
        }
        TestResumptionUsage::Branch | TestResumptionUsage::BranchOther => {
            let branch_info = if let TestResumptionUsage::Branch = receiver {
                bob_x1.branch_info()
            } else {
                bob_x2.branch_info()
            };
            StagedWelcome::build_from_branch(bob_provider, join_config, welcome, branch_info)?
                .with_ratchet_tree(ratchet_tree.into())
                .build()?
                .into_group(bob_provider)
        }
        TestResumptionUsage::Normal => StagedWelcome::new_from_welcome(
            bob_provider,
            join_config,
            welcome,
            Some(ratchet_tree.into()),
        )?
        .into_group(bob_provider),
        TestResumptionUsage::NormalIndirect => {
            StagedWelcome::process_resuming_welcome(bob_provider, join_config, welcome)?
                .build(bob_provider)?
                .into_staged_welcome(bob_provider, Some(ratchet_tree.into()))?
                .into_group(bob_provider)
        }
    })();

    match expect {
        Ok(()) => {
            let bob_y = bob_y.expect("Bob could not join Y");
            assert_eq!(
                alice_y.epoch_authenticator(),
                bob_y.epoch_authenticator(),
                "epoch authenticators must match"
            );
        }
        Err(expected) => {
            let err = bob_y
                .map(|_| ())
                .expect_err("Bob must not be able to join Y");
            assert_eq!(err, expected);
        }
    }
}

#[openmls_test]
fn resumption_reinit_with_reinit_info() {
    run_resumption_constellation_test::<Provider>(
        ciphersuite,
        TestResumptionCreation::ReInit,
        TestResumptionUsage::ReInit,
        Ok(()),
    );
}

#[openmls_test]
fn resumption_reinit_with_other_reinit_info() {
    run_resumption_constellation_test::<Provider>(
        ciphersuite,
        TestResumptionCreation::ReInit,
        TestResumptionUsage::ReInitOther,
        Err(WelcomeError::ReInitPredecessorMismatch),
    );
}

#[openmls_test]
fn resumption_reinit_without_info() {
    for receiver in [
        TestResumptionUsage::Normal,
        TestResumptionUsage::NormalIndirect,
        TestResumptionUsage::Branch,
    ] {
        run_resumption_constellation_test::<Provider>(
            ciphersuite,
            TestResumptionCreation::ReInit,
            receiver,
            Err(WelcomeError::MissingReInitInfo),
        );
    }
}

#[openmls_test]
fn resumption_branch_with_branch_info() {
    run_resumption_constellation_test::<Provider>(
        ciphersuite,
        TestResumptionCreation::Branch,
        TestResumptionUsage::Branch,
        Ok(()),
    );
}

#[openmls_test]
fn resumption_branch_with_other_branch_info() {
    run_resumption_constellation_test::<Provider>(
        ciphersuite,
        TestResumptionCreation::Branch,
        TestResumptionUsage::BranchOther,
        Err(WelcomeError::SubgroupParentMismatch),
    );
}

#[openmls_test]
fn resumption_branch_without_info() {
    for receiver in [
        TestResumptionUsage::Normal,
        TestResumptionUsage::NormalIndirect,
        TestResumptionUsage::ReInit,
    ] {
        run_resumption_constellation_test::<Provider>(
            ciphersuite,
            TestResumptionCreation::Branch,
            receiver,
            Err(WelcomeError::MissingBranchInfo),
        );
    }
}

#[openmls_test]
fn resumption_normal_welcome() {
    for receiver in [
        TestResumptionUsage::Normal,
        TestResumptionUsage::NormalIndirect,
    ] {
        run_resumption_constellation_test::<Provider>(
            ciphersuite,
            TestResumptionCreation::Normal,
            receiver,
            Ok(()),
        );
    }
}

#[openmls_test]
fn resumption_normal_welcome_with_extra_reinit() {
    run_resumption_constellation_test::<Provider>(
        ciphersuite,
        TestResumptionCreation::Normal,
        TestResumptionUsage::ReInit,
        Err(WelcomeError::NotAReInit),
    );
}

#[openmls_test]
fn resumption_normal_welcome_with_extra_branch() {
    run_resumption_constellation_test::<Provider>(
        ciphersuite,
        TestResumptionCreation::Normal,
        TestResumptionUsage::Branch,
        Err(WelcomeError::NotABranch),
    );
}
