//! Tests for group reinitialization (ReInit).
//!
//! A group can be reinitialized into a brand-new successor group with new
//! parameters (group id, protocol version, ciphersuite, extensions). Committing
//! a ReInit proposal suspends the old group; the successor group is then seeded
//! with a resumption PSK from the old group's final epoch.
//! <https://www.rfc-editor.org/rfc/rfc9420.html#name-reinitialization>

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

/// Pick a ciphersuite different from `ciphersuite` but with the same signature
/// scheme (so the same credentials can be reused) that the provider supports.
/// Falls back to `ciphersuite` if no such alternative is available.
fn alternate_ciphersuite(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) -> Ciphersuite {
    const CANDIDATES: &[Ciphersuite] = &[
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
        Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
    ];
    CANDIDATES
        .iter()
        .copied()
        .find(|cs| {
            *cs != ciphersuite
                && cs.signature_algorithm() == ciphersuite.signature_algorithm()
                && provider.crypto().supports(*cs).is_ok()
        })
        .unwrap_or(ciphersuite)
}

/// Runs the full reinit flow (old group Alice+Bob -> successor group Alice+Bob)
/// and asserts the old groups are suspended and the successor is consistent.
///
/// `by_value` selects whether the ReInit is committed by value (inline in the
/// commit) or by reference (a standalone proposal committed afterwards).
fn run_reinit_flow<Provider: OpenMlsProvider + Default>(
    ciphersuite: Ciphersuite,
    new_ciphersuite: Ciphersuite,
    by_value: bool,
) {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let old_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .build();

    let (
        (alice_credential, alice_signer),
        (bob_credential, bob_signer),
        mut alice_group,
        mut bob_group,
    ) = setup_group(
        ciphersuite,
        &old_create_config,
        alice_provider,
        bob_provider,
    );

    // === Alice proposes and commits a ReInit ===
    let new_group_id = GroupId::from_slice(b"successor group id");
    let reinit_proposal = ReInitProposal::new(
        new_group_id.clone(),
        ProtocolVersion::Mls10,
        new_ciphersuite,
        Extensions::empty(),
    );

    let commit_message = if by_value {
        // Commit the ReInit inline (by value).
        let bundle = alice_group
            .commit_builder()
            .add_proposal(Proposal::re_init(reinit_proposal.clone()))
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
        bundle.into_commit()
    } else {
        // Propose the ReInit (by reference), let Bob store it, then commit the
        // pending proposal store.
        let (proposal_message, _proposal_ref) = alice_group
            .propose_reinit(alice_provider, reinit_proposal.clone(), &alice_signer)
            .unwrap();

        let processed = bob_group
            .process_message(
                bob_provider,
                proposal_message.into_protocol_message().unwrap(),
            )
            .unwrap();
        match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(queued) => bob_group
                .store_pending_proposal(bob_provider.storage(), *queued)
                .unwrap(),
            other => panic!("expected a proposal message, got {other:?}"),
        }

        let bundle = alice_group
            .commit_builder()
            .consume_proposal_store(true)
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
        bundle.into_commit()
    };

    // Alice merges the ReInit commit: her group is now suspended (inactive).
    alice_group.merge_pending_commit(alice_provider).unwrap();
    assert!(
        !alice_group.is_active(),
        "old group must be suspended (inactive)"
    );

    // Bob processes the ReInit commit and merges it: his group is suspended too.
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
    assert!(!bob_group.is_active(), "Bob's old group must be suspended");
    assert_eq!(
        alice_group.epoch_authenticator(),
        bob_group.epoch_authenticator(),
        "reinit epoch authenticators must match"
    );

    // === Alice creates the successor group and welcomes Bob ===
    let bob_new_key_package = KeyPackage::builder()
        .build(new_ciphersuite, bob_provider, &bob_signer, bob_credential)
        .unwrap();

    let successor_join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .build();

    let mut alice_successor = MlsGroup::builder()
        .with_group_id(new_group_id.clone())
        .ciphersuite(new_ciphersuite)
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .build(alice_provider, &alice_signer, alice_credential)
        .expect("failed to build successor group");

    let bundle = alice_successor
        .commit_builder()
        .reinit(alice_provider.rand(), &alice_group)
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
    let successor_welcome = bundle
        .into_welcome()
        .expect("successor produced no welcome");
    alice_successor
        .merge_pending_commit(alice_provider)
        .unwrap();

    // === Bob joins the successor group from the reinit welcome ===
    let bob_successor = StagedWelcome::new_from_reinit(
        bob_provider,
        &successor_join_config,
        successor_welcome,
        Some(alice_successor.export_ratchet_tree().into()),
        &bob_group,
        &reinit_proposal,
        true,
    )
    .expect("Bob could not join the successor group")
    .into_group(bob_provider)
    .expect("Error creating successor group from StagedWelcome");

    assert_eq!(alice_successor.ciphersuite(), new_ciphersuite);
    assert_eq!(alice_successor.group_id(), &new_group_id);
    assert_eq!(
        alice_successor.confirmation_tag(),
        bob_successor.confirmation_tag(),
        "successor confirmation tags must match"
    );
}

/// Happy path: reinit committed by reference, same ciphersuite.
#[openmls_test]
fn reinit_by_reference_same_ciphersuite() {
    run_reinit_flow::<Provider>(ciphersuite, ciphersuite, false);
}

/// Happy path: reinit committed by value, same ciphersuite.
#[openmls_test]
fn reinit_by_value_same_ciphersuite() {
    run_reinit_flow::<Provider>(ciphersuite, ciphersuite, true);
}

/// Happy path: reinit into a different ciphersuite (by reference), when an
/// alternative ciphersuite with the same signature scheme is available.
#[openmls_test]
fn reinit_cross_ciphersuite() {
    let provider = Provider::default();
    let new_ciphersuite = alternate_ciphersuite(ciphersuite, &provider);
    run_reinit_flow::<Provider>(ciphersuite, new_ciphersuite, false);
}
