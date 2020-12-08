use crate::framing::*;

/// This tests serializing/deserializing MLSPlaintext
#[test]
fn codec() {
    use crate::ciphersuite::*;
    use crate::config::*;

    for ciphersuite in Config::supported_ciphersuites() {
        let credential_bundle =
            CredentialBundle::new(vec![7, 8, 9], CredentialType::Basic, ciphersuite.name())
                .unwrap();
        let sender = Sender {
            sender_type: SenderType::Member,
            sender: LeafIndex::from(2u32),
        };
        let mut orig = MLSPlaintext {
            group_id: GroupId::random(),
            epoch: GroupEpoch(1u64),
            sender,
            authenticated_data: vec![1, 2, 3],
            content_type: ContentType::Application,
            content: MLSPlaintextContentType::Application(vec![4, 5, 6]),
            signature: Signature::new_empty(),
        };
        let context = GroupContext {
            group_id: GroupId::random(),
            epoch: GroupEpoch(1u64),
            tree_hash: vec![],
            confirmed_transcript_hash: vec![],
        };
        let serialized_context = context.encode_detached().unwrap();
        let signature_input = MLSPlaintextTBS::new_from(&orig, Some(serialized_context));
        orig.signature = signature_input.sign(&credential_bundle);

        let enc = orig.encode_detached().unwrap();
        let copy = MLSPlaintext::from_bytes(&enc).unwrap();
        assert_eq!(orig, copy);
        assert!(!orig.is_handshake_message());
    }
}

/// This tests the presence of the group context in MLSPlaintextTBS
#[test]
fn context_presence() {
    use crate::ciphersuite::*;
    use crate::config::*;

    for ciphersuite in Config::supported_ciphersuites() {
        let credential_bundle = CredentialBundle::new(
            "Random identity".into(),
            CredentialType::Basic,
            ciphersuite.name(),
        )
        .unwrap();
        let sender = Sender {
            sender_type: SenderType::Member,
            sender: LeafIndex::from(2u32),
        };
        let mut orig = MLSPlaintext {
            group_id: GroupId::random(),
            epoch: GroupEpoch(1u64),
            sender,
            authenticated_data: vec![1, 2, 3],
            content_type: ContentType::Application,
            content: MLSPlaintextContentType::Application(vec![4, 5, 6]),
            signature: Signature::new_empty(),
        };
        let context = GroupContext {
            group_id: GroupId::random(),
            epoch: GroupEpoch(1u64),
            tree_hash: vec![],
            confirmed_transcript_hash: vec![],
        };
        let serialized_context = context.encode_detached().unwrap();
        let signature_input = MLSPlaintextTBS::new_from(&orig, Some(serialized_context.clone()));
        orig.signature = signature_input.sign(&credential_bundle);
        assert!(orig.verify(
            Some(serialized_context.clone()),
            credential_bundle.credential()
        ));
        assert!(!orig.verify(None, credential_bundle.credential()));

        let signature_input = MLSPlaintextTBS::new_from(&orig, None);
        orig.signature = signature_input.sign(&credential_bundle);
        assert!(!orig.verify(Some(serialized_context), credential_bundle.credential()));
        assert!(orig.verify(None, credential_bundle.credential()));
        assert!(!orig.is_handshake_message());
    }
}

#[test]
fn unknown_sender() {
    use crate::config::*;
    use crate::creds::*;
    use crate::key_packages::*;
    use crate::utils::*;

    for ciphersuite in Config::supported_ciphersuites() {
        let group_aad = b"Alice's test group";

        // Define credential bundles
        let alice_credential_bundle =
            CredentialBundle::new("Alice".into(), CredentialType::Basic, ciphersuite.name())
                .unwrap();
        let bob_credential_bundle =
            CredentialBundle::new("Bob".into(), CredentialType::Basic, ciphersuite.name()).unwrap();
        let charlie_credential_bundle =
            CredentialBundle::new("Charlie".into(), CredentialType::Basic, ciphersuite.name())
                .unwrap();

        // Generate KeyPackages
        let bob_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, Vec::new())
                .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();

        let charlie_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &charlie_credential_bundle,
            Vec::new(),
        )
        .unwrap();
        let charlie_key_package = charlie_key_package_bundle.key_package();

        let alice_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, Vec::new())
                .unwrap();

        // Alice creates a group
        let group_id = [1, 2, 3, 4];
        let mut group_alice = MlsGroup::new(
            &group_id,
            ciphersuite.name(),
            alice_key_package_bundle,
            GroupConfig::default(),
        )
        .unwrap();

        // Alice adds Bob
        let bob_add_proposal = group_alice.create_add_proposal(
            group_aad,
            &alice_credential_bundle,
            bob_key_package.clone(),
        );

        let (commit, _welcome_option, _kpb_option) = group_alice
            .create_commit(
                group_aad,
                &alice_credential_bundle,
                &[&bob_add_proposal],
                false,
            )
            .expect("Error creating Commit");

        group_alice
            .apply_commit(commit, vec![bob_add_proposal], &[])
            .expect("Could not apply Commit");

        // Alice adds Charlie

        let charlie_add_proposal = group_alice.create_add_proposal(
            group_aad,
            &alice_credential_bundle,
            charlie_key_package.clone(),
        );

        let (commit, welcome_option, _kpb_option) = group_alice
            .create_commit(
                group_aad,
                &alice_credential_bundle,
                &[&charlie_add_proposal],
                false,
            )
            .expect("Error creating Commit");

        group_alice
            .apply_commit(commit, vec![charlie_add_proposal], &[])
            .expect("Could not apply Commit");

        let mut group_charlie = MlsGroup::new_from_welcome(
            welcome_option.unwrap(),
            Some(group_alice.tree().public_key_tree_copy()),
            charlie_key_package_bundle,
        )
        .expect("Charlie: Error creating group from Welcome");

        // Alice removes Bob
        let bob_remove_proposal = group_alice.create_remove_proposal(
            group_aad,
            &alice_credential_bundle,
            LeafIndex::from(1usize),
        );
        let (commit, _welcome_option, kpb_option) = group_alice
            .create_commit(
                group_aad,
                &alice_credential_bundle,
                &[&bob_remove_proposal],
                false,
            )
            .expect("Error creating Commit");

        _print_tree(&group_alice.tree(), "Alice tree");
        _print_tree(&group_charlie.tree(), "Charlie tree");

        group_charlie
            .apply_commit(commit.clone(), vec![bob_remove_proposal.clone()], &[])
            .expect("Charlie: Could not apply Commit");
        group_alice
            .apply_commit(
                commit.clone(),
                vec![bob_remove_proposal.clone()],
                &[kpb_option.unwrap()],
            )
            .expect("Alice: Could not apply Commit");

        // Alice sends a message with a sender that points to a blank leaf
        // Expected result: MLSCiphertextError::UnknownSender

        let content = MLSPlaintextContentType::Application(vec![1, 2, 3]);
        let bogus_sender = LeafIndex::from(1usize);
        let bogus_sender_message = MLSPlaintext::new(
            bogus_sender,
            &[],
            content.clone(),
            &alice_credential_bundle,
            &group_alice.context(),
        );

        let (generation, (ratchet_key, ratchet_nonce)) = group_alice
            .secret_tree_mut()
            .secret_for_encryption(ciphersuite, bogus_sender, SecretType::ApplicationSecret);
        let enc_message = MLSCiphertext::new_from_plaintext(
            &bogus_sender_message,
            &group_alice,
            generation,
            ratchet_key,
            ratchet_nonce,
        );

        let received_message = group_charlie.decrypt(&enc_message);
        assert_eq!(
            received_message.unwrap_err(),
            MLSCiphertextError::UnknownSender
        );

        // Alice sends a message with a sender that is outside of the group
        // Expected result: MLSCiphertextError::GenerationOutOfBound
        let bogus_sender = LeafIndex::from(100usize);
        let bogus_sender_message = MLSPlaintext::new(
            bogus_sender,
            &[],
            content,
            &alice_credential_bundle,
            &group_alice.context(),
        );

        let (generation, (ratchet_key, ratchet_nonce)) =
            group_alice.secret_tree_mut().secret_for_encryption(
                ciphersuite,
                LeafIndex::from(0usize),
                SecretType::ApplicationSecret,
            );
        let enc_message = MLSCiphertext::new_from_plaintext(
            &bogus_sender_message,
            &group_alice,
            generation,
            ratchet_key,
            ratchet_nonce,
        );

        let received_message = group_charlie.decrypt(&enc_message);
        assert_eq!(
            received_message.unwrap_err(),
            MLSCiphertextError::GenerationOutOfBound
        );
    }
}
