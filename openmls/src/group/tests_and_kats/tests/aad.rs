// Import necessary modules and dependencies
use crate::{
    binary_tree::LeafNodeIndex,
    framing::*,
    group::{
        tests_and_kats::utils::{generate_credential_with_key, generate_key_package},
        *,
    },
};

// Tests the different variants of the RemoveOperation enum.
#[openmls_test::openmls_test]
fn test_add_member_with_aad(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Test over both wire format policies
    for wire_format_policy in [
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    ] {
        let group_id = GroupId::from_slice(b"Test Group");

        // Generate credentials with keys
        let alice_credential_with_key_and_signer = generate_credential_with_key(
            "Alice".into(),
            ciphersuite.signature_algorithm(),
            provider,
        );

        let bob_credential_with_key_and_signer =
            generate_credential_with_key("Bob".into(), ciphersuite.signature_algorithm(), provider);

        let charlie_credential_with_key_and_signer = generate_credential_with_key(
            "Charlie".into(),
            ciphersuite.signature_algorithm(),
            provider,
        );

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            bob_credential_with_key_and_signer.clone(),
        );
        let charlie_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            provider,
            charlie_credential_with_key_and_signer,
        );

        // Define the MlsGroup configuration
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .wire_format_policy(wire_format_policy)
            .build();

        // === Alice creates a group ===

        let mut alice_group = MlsGroup::new_with_group_id(
            provider,
            &alice_credential_with_key_and_signer.signer,
            &mls_group_create_config,
            group_id,
            alice_credential_with_key_and_signer
                .credential_with_key
                .clone(),
        )
        .expect("An unexpected error occurred.");

        let aad = b"Test AAD".to_vec();

        alice_group.set_aad(aad.clone());

        // Test the AAD was set correctly
        assert_eq!(alice_group.aad(), &aad);

        // === Alice adds Bob ===

        let (_message, welcome, _group_info) = alice_group
            .add_members(
                provider,
                &alice_credential_with_key_and_signer.signer,
                &[bob_key_package.key_package().clone()],
            )
            .expect("An unexpected error occurred.");
        alice_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome
            .into_welcome()
            .expect("expected message to be a welcome");

        let mut bob_group = StagedWelcome::new_from_welcome(
            provider,
            mls_group_create_config.join_config(),
            welcome.clone(),
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("Error creating staged join from Welcome")
        .into_group(provider)
        .expect("Error creating group from staged join");

        // === Alice sends a message to Bob ===

        let message = b"Hello, World!".to_vec();
        alice_group.set_aad(aad.clone());
        let alice_message: MlsMessageIn = alice_group
            .create_message(
                provider,
                &alice_credential_with_key_and_signer.signer,
                &message,
            )
            .expect("Error creating message")
            .into();

        // Test the AAD was reset
        assert_eq!(alice_group.aad().len(), 0);

        let bob_message = bob_group
            .process_message(
                provider,
                alice_message.clone().into_protocol_message().unwrap(),
            )
            .expect("Error handling message");

        // Test the AAD was set correctly
        assert_eq!(bob_message.aad(), &aad);

        // === Alice adds Charlie ===

        alice_group.set_aad(aad.clone());
        let (commit, _welcome, _group_info) = alice_group
            .add_members(
                provider,
                &alice_credential_with_key_and_signer.signer,
                &[charlie_key_package.key_package().clone()],
            )
            .expect("An unexpected error occurred.");
        alice_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        // Test the AAD was reset
        assert_eq!(alice_group.aad().len(), 0);

        let bob_processed_message = bob_group
            .process_message(provider, commit.clone().into_protocol_message().unwrap())
            .expect("Error handling message");

        match bob_processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(bob_staged_commit) => {
                bob_group
                    .merge_staged_commit(provider, *bob_staged_commit)
                    .unwrap();
            }
            _ => panic!("Expected a StagedCommitMessage"),
        }

        // Test the AAD was set correctly
        assert_eq!(bob_message.aad(), &aad);

        // === Alice removes Charlie ===

        alice_group.set_aad(aad.clone());
        let (commit, _welcome, _group_info) = alice_group
            .remove_members(
                provider,
                &alice_credential_with_key_and_signer.signer,
                &[LeafNodeIndex::new(2)],
            )
            .expect("An unexpected error occurred.");
        alice_group
            .merge_pending_commit(provider)
            .expect("error merging pending commit");

        // Test the AAD was reset
        assert_eq!(alice_group.aad().len(), 0);

        let bob_processed_message = bob_group
            .process_message(provider, commit.clone().into_protocol_message().unwrap())
            .expect("Error handling message");

        // Test the AAD was set correctly
        assert_eq!(bob_processed_message.aad(), &aad);
    }
}
