//! Tests for sub-groups of MLS groups.
//!
//! A new group can be formed from a subset of an existing group's members,
//! using the same parameters as the old group.
//! <https://www.rfc-editor.org/rfc/rfc9420.html#name-subgroup-branching>

use openmls::{
    prelude::*,
    schedule::{psk::ResumptionPskUsage, PreSharedKeyId},
    test_utils::single_group_test_framework::generate_credential,
};
use openmls_test::openmls_test;

#[openmls_test]
fn subgroup_branching() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .build();

    // Generate credentials with keys
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

    // Generate KeyPackages
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

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob and Charlie ===
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
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating StagedWelcome from Welcome")
    .into_group(bob_provider)
    .expect("Error creating group from StagedWelcome");

    // === Alice creates a subgroup with Alice and Bob ===
    let bob_new_key_package = KeyPackage::builder()
        .build(ciphersuite, bob_provider, &bob_signer, bob_credential)
        .unwrap();
    // Get the resumption branch PSK
    let alice_branching_psk_id = PreSharedKeyId::resumption(
        ResumptionPskUsage::Branch,
        alice_group.group_id().clone(),
        GroupEpoch::from(alice_group.epoch()),
        "P".repeat(alice_group.ciphersuite().hash_length())
            .into_bytes(),
    );
    let alice_branch_psk_secret = alice_group.resumption_psk_secret().clone();

    let mut alice_bob_sub_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");

    eprintln!(" --- Alice creates sub group ...");
    let bob_resumption_psk_secret = bob_group.resumption_psk_secret().clone();
    debug_assert_eq!(
        bob_resumption_psk_secret.as_slice(),
        alice_branch_psk_secret.as_slice()
    );

    let commit_message_bundle = alice_bob_sub_group
        .commit_builder()
        .branch(alice_branching_psk_id, alice_branch_psk_secret)
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
    let welcome: MlsMessageIn = branching_welcome.clone().into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    eprintln!(" --- Bob joins sub group ...");
    let bob_alice_sub_group = GroupBuilder::new(mls_group_create_config.join_config(), welcome)
        .with_resumption_psk(bob_resumption_psk_secret)
        .read_key_package(bob_provider)
        .unwrap()
        .decrypt_group_secrets(bob_provider)
        .unwrap()
        .read_psks(bob_provider.storage())
        .unwrap()
        .key_schedule(bob_provider)
        .unwrap()
        .into_staged_welcome(bob_provider, None)
        .unwrap()
        .into_group(bob_provider)
        .unwrap();

    assert_eq!(
        alice_bob_sub_group.confirmation_tag(),
        bob_alice_sub_group.confirmation_tag()
    );
}
