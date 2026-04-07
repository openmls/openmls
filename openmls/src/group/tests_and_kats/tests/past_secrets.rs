//! This module contains tests regarding the use of [`MessageSecretsStore`] in [`MlsGroup`]

use crate::framing::SecretTreeError;
use crate::group::tests_and_kats::utils::{generate_credential_with_key, generate_key_package};
use crate::{
    framing::{MessageDecryptionError, MlsMessageIn, ProcessedMessageContent},
    group::*,
    treesync::LeafNodeParameters,
};

#[openmls_test::openmls_test]
async fn test_past_secrets_in_group<Provider: crate::storage::OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
) {
    let alice_provider = &mut Provider::default();
    let bob_provider = &mut Provider::default();

    // Test this for different parameters
    for max_epochs in (0..10usize).step_by(2) {
        let group_id = GroupId::random(alice_provider.rand());

        // Generate credentials
        let alice_credential_with_keys = generate_credential_with_key(
            b"Alice".to_vec(),
            ciphersuite.signature_algorithm(),
            alice_provider,
        )
        .await;
        let bob_credential_with_keys = generate_credential_with_key(
            b"Bob".to_vec(),
            ciphersuite.signature_algorithm(),
            bob_provider,
        )
        .await;

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            bob_provider,
            bob_credential_with_keys,
        )
        .await;

        // Define the MlsGroup configuration

        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .max_past_epochs(max_epochs / 2)
            .ciphersuite(ciphersuite)
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            alice_provider,
            &alice_credential_with_keys.signer,
            &mls_group_create_config,
            group_id.clone(),
            alice_credential_with_keys.credential_with_key.clone(),
        )
        .await
        .expect("An unexpected error occurred.");

        // Alice adds Bob
        let (_message, welcome, _group_info) = alice_group
            .add_members(
                alice_provider,
                &alice_credential_with_keys.signer,
                core::slice::from_ref(bob_key_package.key_package()),
            )
            .await
            .expect("An unexpected error occurred.");

        alice_group
            .merge_pending_commit(alice_provider)
            .await
            .expect("error merging pending commit");

        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome
            .into_welcome()
            .expect("expected message to be a welcome");

        let mut bob_group = StagedWelcome::new_from_welcome(
            bob_provider,
            mls_group_create_config.join_config(),
            welcome,
            Some(alice_group.export_ratchet_tree().into()),
        )
        .await
        .expect("Error creating staged join from Welcome")
        .into_group(bob_provider)
        .await
        .expect("Error creating group from staged join");

        // Generate application message for different epochs

        let mut application_messages = Vec::new();
        let mut update_commits = Vec::new();

        for _ in 0..max_epochs {
            let application_message = alice_group
                .create_message(
                    alice_provider,
                    &alice_credential_with_keys.signer,
                    &[1, 2, 3],
                )
                .await
                .expect("An unexpected error occurred.");

            application_messages.push(application_message.into_protocol_message().unwrap());

            let (message, _welcome, _group_info) = alice_group
                .self_update(
                    alice_provider,
                    &alice_credential_with_keys.signer,
                    LeafNodeParameters::default(),
                )
                .await
                .expect("An unexpected error occurred.")
                .into_contents();

            update_commits.push(message.clone());

            alice_group
                .merge_pending_commit(alice_provider)
                .await
                .expect("error merging pending commit");
        }

        // Bob processes all update commits

        for update_commit in update_commits {
            let bob_processed_message = bob_group
                .process_message(bob_provider, update_commit.into_protocol_message().unwrap())
                .await
                .expect("An unexpected error occurred.");

            if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                bob_processed_message.into_content()
            {
                bob_group
                    .merge_staged_commit(bob_provider, *staged_commit)
                    .await
                    .expect("Error merging commit.");
            } else {
                unreachable!("Expected a StagedCommit.");
            }
        }

        // === Test application messages from older epochs ===

        let mut bob_group = MlsGroup::load(bob_provider.storage(), &group_id)
            .await
            .expect("error re-loading bob's group")
            .expect("no such group");

        // The first messages should fail
        for application_message in application_messages.iter().take(max_epochs / 2) {
            let err = bob_group
                .process_message(bob_provider, application_message.clone())
                .await
                .expect_err("An unexpected error occurred.");
            assert!(matches!(
                err,
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast)
                ),)
            ));
        }

        // The last messages should not fail
        for application_message in application_messages.iter().skip(max_epochs / 2) {
            let bob_processed_message = bob_group
                .process_message(bob_provider, application_message.clone())
                .await
                .expect("An unexpected error occurred.");

            if let ProcessedMessageContent::ApplicationMessage(application_message) =
                bob_processed_message.into_content()
            {
                assert_eq!(application_message.into_bytes(), &[1, 2, 3]);
            } else {
                unreachable!("Expected an ApplicationMessage.");
            }
        }
    }
}
