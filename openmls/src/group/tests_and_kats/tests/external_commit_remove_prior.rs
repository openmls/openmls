//! External-commit remove-prior ("resync") that truncates the tree.

use openmls_test::openmls_test;

use crate::{
    extensions::Extensions,
    framing::ProcessedMessageContent,
    group::{
        tests_and_kats::utils::{generate_credential_with_key, generate_key_package},
        MlsGroup, MlsGroupJoinConfig,
    },
    prelude::LeafNodeIndex,
    treesync::LeafNodeParameters,
};

/// A remove-prior that truncates the tree must not resurrect the removed leaf
/// when the joiner's leaf grows the tree again.
///
/// Alice, Bob, Carol and Dave occupy leaves 0 to 3. Carol is removed, so leaf 2
/// is blank. Dave then rejoins via an external commit. Removing his prior leaf
/// 3 truncates the tree to two leaves, and adding his new leaf grows it back to
/// four leaves with Dave at leaf 2. Leaf 3 must stay blank.
#[openmls_test]
fn external_commit_remove_prior_after_truncation() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let carol_provider = &Provider::default();
    let dave_provider = &Provider::default();
    // Dave rejoins as a fresh client instance, but reuses his signing key.
    let dave2_provider = &Provider::default();

    let alice = generate_credential_with_key(
        b"alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let bob = generate_credential_with_key(
        b"bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );
    let carol = generate_credential_with_key(
        b"carol".into(),
        ciphersuite.signature_algorithm(),
        carol_provider,
    );
    let dave = generate_credential_with_key(
        b"dave".into(),
        ciphersuite.signature_algorithm(),
        dave_provider,
    );

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build(
            alice_provider,
            &alice.signer,
            alice.credential_with_key.clone(),
        )
        .unwrap();

    let key_packages = [
        generate_key_package(ciphersuite, Extensions::empty(), bob_provider, bob),
        generate_key_package(ciphersuite, Extensions::empty(), carol_provider, carol),
        generate_key_package(
            ciphersuite,
            Extensions::empty(),
            dave_provider,
            dave.clone(),
        ),
    ]
    .map(|bundle| bundle.key_package().clone());
    alice_group
        .add_members(alice_provider, &alice.signer, &key_packages)
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    alice_group
        .remove_members(alice_provider, &alice.signer, &[LeafNodeIndex::new(2)])
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();
    assert_eq!(alice_group.members().count(), 3);

    // Dave rejoins with remove-prior.
    let vgi = alice_group
        .export_group_info(alice_provider.crypto(), &alice.signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let tree = alice_group.export_ratchet_tree();
    let (dave_group, bundle) = MlsGroup::external_commit_builder()
        .with_ratchet_tree(tree.into())
        .with_config(
            MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build(),
        )
        .build_group(dave2_provider, vgi, dave.credential_with_key.clone())
        .unwrap()
        .leaf_node_parameters(LeafNodeParameters::builder().build())
        .load_psks(dave2_provider.storage())
        .unwrap()
        .build(
            dave2_provider.rand(),
            dave2_provider.crypto(),
            &dave.signer,
            |_| true,
        )
        .unwrap()
        .finalize(dave2_provider)
        .unwrap();

    let plaintext = bundle.into_commit().into_protocol_message().unwrap();
    let processed = alice_group
        .process_message(alice_provider, plaintext)
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("expected a staged commit");
    };
    alice_group
        .merge_staged_commit(alice_provider, *staged)
        .unwrap();

    // Both sides see Alice, Bob and Dave's new leaf only.
    for group in [&alice_group, &dave_group] {
        let members: Vec<u32> = group.members().map(|member| member.index.u32()).collect();
        assert_eq!(members, [0, 1, 2], "the removed prior leaf must stay blank");
    }
    assert_eq!(dave_group.own_leaf_index(), LeafNodeIndex::new(2));
    assert_eq!(
        alice_group.epoch_authenticator().as_slice(),
        dave_group.epoch_authenticator().as_slice(),
    );
}
