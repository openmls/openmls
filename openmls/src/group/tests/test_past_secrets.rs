//! This module contains tests regarding the use of [`MessageSecretsStore`] in [`MlsGroup`]

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::Ciphersuite, OpenMlsCryptoProvider};
use tls_codec::Serialize;

use rstest::*;
use rstest_reuse::{self, *};

use crate::{
    credentials::{CredentialBundle, CredentialType},
    framing::{MessageDecryptionError, ProcessedMessage},
    group::{errors::*, *},
    key_packages::KeyPackageBundle,
};

#[apply(ciphersuites_and_backends)]
fn test_past_secrets_in_group(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test this for different parameters
    for max_epochs in (0..10usize).step_by(2) {
        let group_id = GroupId::from_slice(b"Test Group");

        // Generate credential bundles

        let alice_credential_bundle = CredentialBundle::new(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("An unexpected error occurred.");
        let alice_credential = alice_credential_bundle.credential().clone();
        backend
            .key_store()
            .store(
                &alice_credential
                    .signature_key()
                    .tls_serialize_detached()
                    .expect("Error serializing signature key."),
                &alice_credential_bundle,
            )
            .expect("An unexpected error occurred.");

        let bob_credential_bundle = CredentialBundle::new(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("An unexpected error occurred.");
        let bob_credential = bob_credential_bundle.credential().clone();
        backend
            .key_store()
            .store(
                &bob_credential
                    .signature_key()
                    .tls_serialize_detached()
                    .expect("Error serializing signature key."),
                &bob_credential_bundle,
            )
            .expect("An unexpected error occurred.");

        // Generate KeyPackages

        let alice_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &alice_credential_bundle, backend, vec![])
                .expect("An unexpected error occurred.");
        let alice_key_package = alice_key_package_bundle.key_package().clone();
        backend
            .key_store()
            .store(
                alice_key_package
                    .hash_ref(backend.crypto())
                    .expect("Could not hash KeyPackage.")
                    .value(),
                &alice_key_package_bundle,
            )
            .expect("An unexpected error occurred.");

        let bob_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &bob_credential_bundle, backend, vec![])
                .expect("An unexpected error occurred.");
        let bob_key_package = bob_key_package_bundle.key_package().clone();
        backend
            .key_store()
            .store(
                bob_key_package
                    .hash_ref(backend.crypto())
                    .expect("Could not hash KeyPackage.")
                    .value(),
                &bob_key_package_bundle,
            )
            .expect("An unexpected error occurred.");

        // Define the MlsGroup configuration

        let mls_group_config = MlsGroupConfig::builder()
            .max_past_epochs(max_epochs / 2)
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new(
            backend,
            &mls_group_config,
            group_id,
            alice_key_package
                .hash_ref(backend.crypto())
                .expect("Could not hash KeyPackage.")
                .as_slice(),
        )
        .expect("An unexpected error occurred.");

        // Alice adds Bob
        let (_message, welcome) = alice_group
            .add_members(backend, &[bob_key_package])
            .expect("An unexpected error occurred.");

        alice_group
            .merge_pending_commit()
            .expect("error merging pending commit");

        let mut bob_group = MlsGroup::new_from_welcome(
            backend,
            &mls_group_config,
            welcome,
            Some(alice_group.export_ratchet_tree()),
        )
        .expect("Error creating group from Welcome");

        // Generate application message for different epochs

        let mut application_messages = Vec::new();
        let mut update_commits = Vec::new();

        for _ in 0..max_epochs {
            let application_message = alice_group
                .create_message(backend, &[1, 2, 3])
                .expect("An unexpected error occurred.");

            application_messages.push(application_message);

            let (message, _welcome) = alice_group
                .self_update(backend, None)
                .expect("An unexpected error occurred.");

            update_commits.push(message.clone());

            alice_group
                .merge_pending_commit()
                .expect("error merging pending commit");
        }

        // Bob processes all update commits

        for update_commit in update_commits {
            let unverified_message = bob_group
                .parse_message(update_commit.into(), backend)
                .expect("An unexpected error occurred.");

            let bob_processed_message = bob_group
                .process_unverified_message(unverified_message, None, backend)
                .expect("An unexpected error occurred.");

            if let ProcessedMessage::StagedCommitMessage(staged_commit) = bob_processed_message {
                bob_group
                    .merge_staged_commit(*staged_commit)
                    .expect("Could not merge StagedCommit");
            } else {
                unreachable!("Expected a StagedCommit.");
            }
        }

        // === Test application messages from older epochs ===

        // The first messages should fail
        for application_message in application_messages.iter().take(max_epochs / 2) {
            let err = bob_group
                .parse_message(application_message.clone().into(), backend)
                .expect_err("An unexpected error occurred.");
            assert_eq!(
                err,
                ParseMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::AeadError
                ),)
            );
        }

        // The last messages should not fail
        for application_message in application_messages.iter().skip(max_epochs / 2) {
            let unverified_message = bob_group
                .parse_message(application_message.clone().into(), backend)
                .expect("An unexpected error occurred.");

            let bob_processed_message = bob_group
                .process_unverified_message(unverified_message, None, backend)
                .expect("An unexpected error occurred.");

            if let ProcessedMessage::ApplicationMessage(application_message) = bob_processed_message
            {
                assert_eq!(application_message.into_bytes(), &[1, 2, 3]);
            } else {
                unreachable!("Expected an ApplicationMessage.");
            }
        }
    }
}
