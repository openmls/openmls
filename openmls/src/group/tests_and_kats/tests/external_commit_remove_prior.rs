//! External-commit remove-prior ("resync") received by a group member.
//!
//! When a member rejoins the group via an external commit reusing its prior
//! signature key, OpenMLS's `ExternalCommitBuilder` auto-adds an inline Remove
//! of the joiner's previous leaf. A *receiving* member must apply that inline
//! Remove: its tree must replace the prior leaf rather than grow, and its epoch
//! authenticator must agree with the committer's.

use openmls_test::openmls_test;

use crate::{
    framing::ProcessedMessageContent,
    group::{
        tests_and_kats::utils::{generate_credential_with_key, CredentialWithKeyAndSigner},
        MlsGroup, MlsGroupJoinConfig, WireFormatPolicy, MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY,
        MIXED_PLAINTEXT_WIRE_FORMAT_POLICY, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
};

#[openmls_test]
fn external_commit_remove_prior_applied_by_member() {
    for policy in [
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
        MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY,
    ] {
        run_case::<Provider>(ciphersuite, policy);
    }
}

fn run_case<Provider: crate::storage::OpenMlsProvider + Default>(
    ciphersuite: crate::prelude::Ciphersuite,
    policy: WireFormatPolicy,
) {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    // Bob "rejoins" as a fresh client instance, but reuses his signing key.
    let bob2_provider = &Provider::default();

    let CredentialWithKeyAndSigner {
        credential_with_key: alice_credential_with_key,
        signer: alice_signer,
    } = generate_credential_with_key(
        b"alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let CredentialWithKeyAndSigner {
        credential_with_key: bob_credential_with_key,
        signer: bob_signer,
    } = generate_credential_with_key(
        b"bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    // === Alice creates a group ===
    // Match the interop client's group configuration knobs.
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(policy)
        .max_past_epochs(32)
        .number_of_resumption_psks(32)
        .use_ratchet_tree_extension(true)
        .build(alice_provider, &alice_signer, alice_credential_with_key)
        .unwrap();

    let join_group_config = MlsGroupJoinConfig::builder()
        .max_past_epochs(32)
        .number_of_resumption_psks(32)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(policy)
        .build();

    // === Bob joins externally ===
    let vgi = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let tree = alice_group.export_ratchet_tree();

    let (_bob_group, bundle) = MlsGroup::external_commit_builder()
        .with_ratchet_tree(tree.into())
        .with_config(join_group_config.clone())
        .build_group(bob_provider, vgi, bob_credential_with_key.clone())
        .unwrap()
        .load_psks(bob_provider.storage())
        .unwrap()
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_signer,
            |_| true,
        )
        .unwrap()
        .finalize(bob_provider)
        .unwrap();

    // Alice processes Bob's external join.
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
    assert_eq!(alice_group.members().count(), 2);

    // === Bob rejoins externally with remove-prior (reusing his signing key) ===
    let vgi = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let tree = alice_group.export_ratchet_tree();

    let (bob_group2, bundle) = MlsGroup::external_commit_builder()
        .with_ratchet_tree(tree.into())
        .with_config(join_group_config.clone())
        .build_group(bob2_provider, vgi, bob_credential_with_key.clone())
        .unwrap()
        .load_psks(bob2_provider.storage())
        .unwrap()
        .build(
            bob2_provider.rand(),
            bob2_provider.crypto(),
            &bob_signer,
            |_| true,
        )
        .unwrap()
        .finalize(bob2_provider)
        .unwrap();

    // The committer's own tree replaced the prior leaf (still 2 members).
    assert_eq!(
        bob_group2.members().count(),
        2,
        "committer should have removed its prior leaf"
    );

    // Alice processes Bob's remove-prior external commit.
    let plaintext = bundle.into_commit().into_protocol_message().unwrap();
    let processed = alice_group
        .process_message(alice_provider, plaintext)
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("expected a staged commit");
    };
    assert_eq!(
        staged.remove_proposals().count(),
        1,
        "the received external commit must carry the inline remove-prior"
    );
    alice_group
        .merge_staged_commit(alice_provider, *staged)
        .unwrap();

    // The receiving member's tree must have replaced the prior leaf, not grown.
    assert_eq!(
        alice_group.members().count(),
        2,
        "receiving member must apply the inline remove-prior"
    );

    // And both sides must agree on the epoch authenticator.
    assert_eq!(
        alice_group.epoch_authenticator().as_slice(),
        bob_group2.epoch_authenticator().as_slice(),
        "receiver and committer must agree on the epoch authenticator"
    );
}
