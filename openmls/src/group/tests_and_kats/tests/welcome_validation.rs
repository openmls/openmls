use crate::{
    group::{
        mls_group::tests_and_kats::utils::{setup_alice_group, setup_client},
        StagedWelcome,
    },
    test_utils::frankenstein::*,
};

/// Valn1405:
/// Welcome:
/// The tree hash of the ratchet tree must match the tree_hash field in GroupInfo.
#[openmls_test::openmls_test]
fn test_valn1405_inline_tree_valid() {
    // ceate Welcome message and GroupInfo

    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (mut alice_group, _alice_credential, alice_signer, _alice_pk) =
        setup_alice_group(ciphersuite, alice_provider);

    let (_bob_credential, bob_kpb, _bob_signer, _bob_pk) =
        setup_client("Bob", ciphersuite, bob_provider);
    let message_bundle = alice_group
        .commit_builder()
        .propose_adds([bob_kpb.key_package.clone()])
        .load_psks(alice_provider.storage())
        .unwrap()
        .use_ratchet_tree_extension(true)
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signer,
            |_proposal| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap();

    let welcome: FrankenWelcome = message_bundle.welcome().unwrap().clone().into();

    // validate Welcome message
    let staged_welcome = StagedWelcome::new_from_welcome(
        bob_provider,
        alice_group.configuration(),
        welcome.into(),
        None,
    )
    .expect("expected valid join from unmodified welcome");

    let _bob_group = staged_welcome
        .into_group(bob_provider)
        .expect("expected valid group from join");
}

// TODO: Test: With changed tree_hash in the encrypted group_info, staging the welcome should return an error.
// TODO: Repeat tests without the ratchet tree extensiion.
