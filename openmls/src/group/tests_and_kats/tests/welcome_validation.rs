use crate::{
    group::{
        mls_group::tests_and_kats::utils::{setup_alice_group, setup_client},
        public_group::errors::CreationFromExternalError,
        StagedWelcome,
    },
    test_utils::frankenstein::*,
};

/// Valn1405:
/// Welcome:
/// The tree hash of the ratchet tree must match the tree_hash field in GroupInfo.
///
/// This module tests the happy and error paths, each with and without RatchedTree extension in Welcome
mod test_valn1405 {
    use crate::group::WelcomeError;

    use super::*;

    #[openmls_test::openmls_test]
    fn test_inline_tree_valid() {
        // create Welcome message and GroupInfo
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

        // No-op for consistency with other tests
        let welcome: FrankenWelcome = message_bundle.welcome().unwrap().clone().into();
        let updated_welcome = welcome.with_sealed_update(
            &alice_signer,
            alice_provider,
            &bob_kpb.key_package,
            bob_provider,
            |_ciphersuite, _group_secrets, _group_info| {},
        );

        // validate Welcome message
        let staged_welcome = StagedWelcome::new_from_welcome(
            bob_provider,
            alice_group.configuration(),
            updated_welcome.into(),
            None,
        )
        .expect("expected valid join from unmodified welcome");

        let _bob_group = staged_welcome
            .into_group(bob_provider)
            .expect("expected valid group from join");
    }

    #[openmls_test::openmls_test]
    fn test_inline_tree_invalid() {
        // create Welcome message and GroupInfo
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
        let updated_welcome = welcome.with_sealed_update(
            &alice_signer,
            alice_provider,
            &bob_kpb.key_package,
            bob_provider,
            |_ciphersuite, _group_secrets, group_info| {
                // Flip bit of tree hash
                let last_byte = group_info
                    .group_context
                    .tree_hash
                    .pop()
                    .expect("empty tree_hash in group_context");
                group_info.group_context.tree_hash.push(last_byte ^ 1);
            },
        );

        // validate Welcome message
        let welcome_err = StagedWelcome::new_from_welcome(
            bob_provider,
            alice_group.configuration(),
            updated_welcome.into(),
            None,
        )
        .expect_err("Welcome should fail due to invalid tree_hash in GroupInfo");
        assert_eq!(
            welcome_err,
            WelcomeError::PublicGroupError(CreationFromExternalError::TreeHashMismatch)
        )
    }

    #[openmls_test::openmls_test]
    fn test_external_tree_valid() {
        // create Welcome message and GroupInfo
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
            .use_ratchet_tree_extension(false)
            .build(
                alice_provider.rand(),
                alice_provider.crypto(),
                &alice_signer,
                |_proposal| true,
            )
            .unwrap()
            .stage_commit(alice_provider)
            .unwrap();

        // No-op for consistency with other tests
        let welcome: FrankenWelcome = message_bundle.welcome().unwrap().clone().into();
        let updated_welcome = welcome.with_sealed_update(
            &alice_signer,
            alice_provider,
            &bob_kpb.key_package,
            bob_provider,
            |_ciphersuite, _group_secrets, _group_info| {},
        );

        // Alice needs to merge the commit so she can export the new tree
        alice_group
            .merge_pending_commit(alice_provider)
            .expect("error merging pending commit");

        // validate Welcome message
        let staged_welcome = StagedWelcome::new_from_welcome(
            bob_provider,
            alice_group.configuration(),
            updated_welcome.into(),
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("expected valid join from unmodified welcome");

        let _bob_group = staged_welcome
            .into_group(bob_provider)
            .expect("expected valid group from join");
    }

    #[openmls_test::openmls_test]
    fn test_external_tree_invalid() {
        // create Welcome message and GroupInfo
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
            .use_ratchet_tree_extension(false)
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
        let updated_welcome = welcome.with_sealed_update(
            &alice_signer,
            alice_provider,
            &bob_kpb.key_package,
            bob_provider,
            |_ciphersuite, _group_secrets, group_info| {
                // Flip bit of tree hash
                let last_byte = group_info
                    .group_context
                    .tree_hash
                    .pop()
                    .expect("empty tree_hash in group_context");
                group_info.group_context.tree_hash.push(last_byte ^ 1);
            },
        );

        // validate Welcome message
        let welcome_err = StagedWelcome::new_from_welcome(
            bob_provider,
            alice_group.configuration(),
            updated_welcome.into(),
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect_err("Welcome should fail due to invalid tree_hash in GroupInfo");
        assert_eq!(
            welcome_err,
            WelcomeError::PublicGroupError(CreationFromExternalError::TreeHashMismatch)
        )
    }
}
