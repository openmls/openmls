use std::slice::from_ref;

use crate::{
    framing::ProcessedMessageContent,
    group::{
        mls_group::tests_and_kats::utils::setup_client, GroupId, MlsGroup, MlsGroupCreateConfig,
        StagedCommit, StagedWelcome,
    },
};

/// In this test we:
/// 1. create a fresh group with two parties alice and bob
/// 2. make alice create a new staged commit
/// 3. have bob merge it
/// 4. have alice encode it, clear the pending commit, decode it, then merge it
///
/// we then verify that the key state is the same: we export secrets before and after merging and
/// we send an application message to verify the other party can decrypt it.
#[openmls_test::openmls_test]
fn repro() {
    // 1. create a fresh group with two parties alice and bob
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let group_id = GroupId::from_slice(b"Test Group");

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_pk) =
        setup_client("Alice", ciphersuite, alice_provider);
    let (_bob_credential_with_key, bob_kpb, bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, bob_provider);

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        group_id.clone(),
        alice_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    // Test persistence after Alice adds Bob
    alice_group
        .ensure_persistence(alice_provider.storage())
        .unwrap();

    let commit_res = alice_group
        .commit_builder()
        .propose_adds(from_ref(bob_kpb.key_package()).iter().cloned())
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

    alice_group.merge_pending_commit(alice_provider).unwrap();

    let welcome = commit_res.welcome().unwrap().clone();

    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(bob_provider)
    .expect("Error creating group from staged join");

    // 2. Make Alice create a new staged commit
    // For this, we have Alice add another party Charlie

    let charlie_provider = &Provider::default();
    let (_charlie_credential_with_key, charlie_kpb, _charlie_signer, _charlie_pk) =
        setup_client("charlie", ciphersuite, charlie_provider);

    let commit_res = alice_group
        .commit_builder()
        .propose_adds(from_ref(charlie_kpb.key_package()).iter().cloned())
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

    // encode and clear staged commit
    let staged_commit = alice_group.pending_commit().unwrap();
    let staged_commit_json = serde_json::to_string(&staged_commit).unwrap();
    alice_group
        .clear_pending_commit(alice_provider.storage())
        .unwrap();

    // make bob process the message and merge it. print exported secrets to show agreement
    let bob_commit_in = commit_res.commit().clone().into_protocol_message();
    let bob_processed_message = bob_group
        .process_message(bob_provider, bob_commit_in.unwrap())
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.content()
    else {
        unreachable!()
    };

    let bob_secret_before = bob_group
        .export_secret(bob_provider.crypto(), "test", b"", 16)
        .unwrap();

    bob_group
        .merge_staged_commit(bob_provider, (**staged_commit).clone())
        .unwrap();

    let bob_secret_after = bob_group
        .export_secret(bob_provider.crypto(), "test", b"", 16)
        .unwrap();

    // make alice load the staged commit from json and merge it. Also generate
    let staged_commit: StagedCommit = serde_json::from_str(&staged_commit_json).unwrap();
    let alice_secret_before = alice_group
        .export_secret(alice_provider.crypto(), "test", b"", 16)
        .unwrap();
    alice_group
        .merge_staged_commit(alice_provider, staged_commit)
        .unwrap();
    let alice_secret_after = alice_group
        .export_secret(alice_provider.crypto(), "test", b"", 16)
        .unwrap();

    // ensure the exported secrets match
    assert_eq!(bob_secret_before, alice_secret_before);
    assert_eq!(bob_secret_after, alice_secret_after);

    // make both send a message to ensure it is decryptable
    let bob_appmsg = bob_group
        .create_message(bob_provider, &bob_signer, b"hi alice")
        .unwrap();
    let alice_appmsg = alice_group
        .create_message(alice_provider, &alice_signer, b"oh hey bob")
        .unwrap();

    let alice_processed_msg = alice_group
        .process_message(alice_provider, bob_appmsg.into_protocol_message().unwrap())
        .unwrap();
    let bob_processed_msg = bob_group
        .process_message(bob_provider, alice_appmsg.into_protocol_message().unwrap())
        .unwrap();
    println!("{alice_processed_msg:?}\n{bob_processed_msg:?}");
}
