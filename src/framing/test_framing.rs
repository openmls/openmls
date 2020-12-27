use crate::config::*;
use crate::framing::*;

/// This tests serializing/deserializing MLSPlaintext
#[test]
fn codec() {
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
            confirmation_tag: None,
            membership_tag: None,
        };
        let group_context =
            GroupContext::new(GroupId::random(), GroupEpoch(1), vec![], vec![]).unwrap();
        let serialized_context = group_context.serialized();
        let signature_input = MLSPlaintextTBS::new_from(&orig, Some(serialized_context.to_vec()));
        orig.signature = signature_input.sign(&credential_bundle);

        let enc = orig.encode_detached().unwrap();
        let copy = MLSPlaintext::decode(&mut Cursor::new(&enc)).unwrap();
        assert_eq!(orig, copy);
        assert!(!orig.is_handshake_message());
    }
}

#[test]
fn membership_tag() {
    for ciphersuite in Config::supported_ciphersuites() {
        let credential_bundle =
            CredentialBundle::new(vec![7, 8, 9], CredentialType::Basic, ciphersuite.name())
                .unwrap();
        let sender = Sender {
            sender_type: SenderType::Member,
            sender: LeafIndex::from(2u32),
        };
        let mut mls_plaintext = MLSPlaintext {
            group_id: GroupId::random(),
            epoch: GroupEpoch(1u64),
            sender,
            authenticated_data: vec![1, 2, 3],
            content_type: ContentType::Application,
            content: MLSPlaintextContentType::Application(vec![4, 5, 6]),
            signature: Signature::new_empty(),
            confirmation_tag: None,
            membership_tag: None,
        };
        let group_context =
            GroupContext::new(GroupId::random(), GroupEpoch(1), vec![], vec![]).unwrap();
        let serialized_context = group_context.serialized();
        let membership_key = Secret::random(ciphersuite.hash_length());
        mls_plaintext.sign_and_mac(
            ciphersuite,
            &credential_bundle,
            serialized_context.to_vec(),
            &membership_key,
        );

        // Verify signature
        assert!(mls_plaintext.verify_signature(
            Some(serialized_context.to_vec()),
            &credential_bundle.credential()
        ));

        // Verify membership tag
        assert!(mls_plaintext.verify_membership_tag(
            ciphersuite,
            serialized_context.to_vec(),
            &membership_key
        ));

        // Construct a membership tag from a random memberhip key
        let mls_plaintext_tbs_payload = MLSPlaintextTBSPayload::new_from_mls_plaintext(
            &mls_plaintext,
            Some(serialized_context.to_vec()),
        );
        let mls_plaintext_tbm_payload =
            MLSPlaintextTBMPayload::new(mls_plaintext_tbs_payload, &mls_plaintext);
        mls_plaintext.membership_tag = Some(MembershipTag::new(
            ciphersuite,
            &Secret::random(ciphersuite.hash_length()),
            mls_plaintext_tbm_payload,
        ));
        // Expect the membership tag verification to fail
        assert!(!mls_plaintext.verify_membership_tag(
            ciphersuite,
            serialized_context.to_vec(),
            &membership_key
        ))
    }
}

/// This tests the presence of the group context in MLSPlaintextTBS
#[test]
fn context_presence() {
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
            confirmation_tag: None,
            membership_tag: None,
        };
        let group_context =
            GroupContext::new(GroupId::random(), GroupEpoch(1), vec![], vec![]).unwrap();
        let serialized_context = group_context.serialized();
        let signature_input = MLSPlaintextTBS::new_from(&orig, Some(serialized_context.to_vec()));
        orig.signature = signature_input.sign(&credential_bundle);
        assert!(orig.verify_signature(
            Some(serialized_context.to_vec()),
            credential_bundle.credential()
        ));
        assert!(!orig.verify_signature(None, credential_bundle.credential()));

        let signature_input = MLSPlaintextTBS::new_from(&orig, None);
        orig.signature = signature_input.sign(&credential_bundle);
        assert!(!orig.verify_signature(
            Some(serialized_context.to_vec()),
            credential_bundle.credential()
        ));
        assert!(orig.verify_signature(None, credential_bundle.credential()));
        assert!(!orig.is_handshake_message());
    }
}

#[test]
fn unknown_sender() {
    use crate::config::*;
    use crate::credentials::*;
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
                &[],
                false,
            )
            .expect("Error creating Commit");

        group_alice
            .apply_commit(&commit, &[&bob_add_proposal], &[])
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
                &[],
                false,
            )
            .expect("Error creating Commit");

        group_alice
            .apply_commit(&commit, &[&charlie_add_proposal], &[])
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
                &[],
                false,
            )
            .expect("Error creating Commit");

        _print_tree(&group_alice.tree(), "Alice tree");
        _print_tree(&group_charlie.tree(), "Charlie tree");

        group_charlie
            .apply_commit(&commit, &[&bob_remove_proposal], &[])
            .expect("Charlie: Could not apply Commit");
        group_alice
            .apply_commit(&commit, &[&bob_remove_proposal], &[kpb_option.unwrap()])
            .expect("Alice: Could not apply Commit");

        _print_tree(&group_alice.tree(), "Alice tree");
        _print_tree(&group_charlie.tree(), "Charlie tree");

        // Alice sends a message with a sender that points to a blank leaf
        // Expected result: MLSCiphertextError::UnknownSender

        let bogus_sender = LeafIndex::from(1usize);
        let bogus_sender_message = MLSPlaintext::new_from_application(
            ciphersuite,
            bogus_sender,
            &[],
            vec![1, 2, 3],
            &alice_credential_bundle,
            &group_alice.context(),
            &Secret::default(),
        );

        let enc_message = MLSCiphertext::try_from_plaintext(
            &bogus_sender_message,
            ciphersuite,
            group_alice.context(),
            LeafIndex::from(1usize),
            group_alice.epoch_secrets(),
            &mut group_alice.secret_tree_mut(),
            0,
        )
        .expect("Encryption error");

        let received_message = group_charlie.decrypt(&enc_message);
        assert_eq!(
            received_message.unwrap_err(),
            MLSCiphertextError::PlaintextError(MLSPlaintextError::UnknownSender)
        );

        // Alice sends a message with a sender that is outside of the group
        // Expected result: MLSCiphertextError::GenerationOutOfBound
        let bogus_sender = LeafIndex::from(100usize);
        let bogus_sender_message = MLSPlaintext::new_from_application(
            ciphersuite,
            bogus_sender,
            &[],
            vec![1, 2, 3],
            &alice_credential_bundle,
            &group_alice.context(),
            &Secret::default(),
        );

        let mut secret_tree = SecretTree::new(
            EncryptionSecret::from_random(ciphersuite.hash_length()),
            LeafIndex::from(100usize),
        );

        let enc_message = MLSCiphertext::try_from_plaintext(
            &bogus_sender_message,
            ciphersuite,
            group_alice.context(),
            LeafIndex::from(99usize),
            group_alice.epoch_secrets(),
            &mut secret_tree,
            0,
        )
        .expect("Encryption error");

        let received_message = group_charlie.decrypt(&enc_message);
        assert_eq!(
            received_message.unwrap_err(),
            MLSCiphertextError::GenerationOutOfBound
        );
    }
}
