use crate::config::*;
use crate::framing::*;

/// This tests serializing/deserializing MLSPlaintext
#[test]
fn codec() {
    for ciphersuite in Config::supported_ciphersuites() {
        let credential_bundle = CredentialBundle::new(
            vec![7, 8, 9],
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
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
            GroupContext::new(GroupId::random(), GroupEpoch(1), vec![], vec![], &[]).unwrap();
        let serialized_context = group_context.serialized();
        let signature_input = MLSPlaintextTBS::new_from(&orig, Some(serialized_context));
        orig.signature = signature_input
            .sign(&credential_bundle)
            .expect("Signing failed.");

        let enc = orig.encode_detached().unwrap();
        let copy = MLSPlaintext::decode(&mut Cursor::new(&enc)).unwrap();
        assert_eq!(orig, copy);
        assert!(!orig.is_handshake_message());
    }
}

#[test]
fn membership_tag() {
    for ciphersuite in Config::supported_ciphersuites() {
        let credential_bundle = CredentialBundle::new(
            vec![7, 8, 9],
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
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
            GroupContext::new(GroupId::random(), GroupEpoch(1), vec![], vec![], &[]).unwrap();
        let serialized_context = group_context.serialized();
        let membership_key =
            MembershipKey::from_secret(Secret::random(ciphersuite, None /* MLS version */));
        mls_plaintext
            .sign_from_member(&credential_bundle, serialized_context)
            .expect("Could not sign plaintext.");
        mls_plaintext
            .add_membership_tag(serialized_context, &membership_key)
            .expect("Could not mac plaintext.");

        println!(
            "Membership tag error: {:?}",
            mls_plaintext.verify_from_member(
                serialized_context,
                &credential_bundle.credential(),
                &membership_key,
            )
        );

        // Verify signature & membership tag
        assert!(mls_plaintext
            .verify_from_member(
                serialized_context,
                &credential_bundle.credential(),
                &membership_key,
            )
            .is_ok());

        // Change the content of the plaintext message
        mls_plaintext.content = MLSPlaintextContentType::Application(vec![7, 8, 9]);

        // Expect the signature & membership tag verification to fail
        assert!(mls_plaintext
            .verify_from_member(
                serialized_context,
                &credential_bundle.credential(),
                &membership_key,
            )
            .is_err());
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
        let alice_credential_bundle = CredentialBundle::new(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();
        let bob_credential_bundle = CredentialBundle::new(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();
        let charlie_credential_bundle = CredentialBundle::new(
            "Charlie".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
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
            None, /* Initial PSK */
            None, /* MLS version */
        )
        .unwrap();

        // Alice adds Bob
        let bob_add_proposal = group_alice
            .create_add_proposal(group_aad, &alice_credential_bundle, bob_key_package.clone())
            .expect("Could not create proposal.");

        let (commit, _welcome_option, _kpb_option) = group_alice
            .create_commit(
                group_aad,
                &alice_credential_bundle,
                &[&bob_add_proposal],
                &[],
                false,
                None,
            )
            .expect("Error creating Commit");

        group_alice
            .apply_commit(&commit, &[&bob_add_proposal], &[], None)
            .expect("Could not apply Commit");

        // Alice adds Charlie

        let charlie_add_proposal = group_alice
            .create_add_proposal(
                group_aad,
                &alice_credential_bundle,
                charlie_key_package.clone(),
            )
            .expect("Could not create proposal.");

        let (commit, welcome_option, _kpb_option) = group_alice
            .create_commit(
                group_aad,
                &alice_credential_bundle,
                &[&charlie_add_proposal],
                &[],
                false,
                None,
            )
            .expect("Error creating Commit");

        group_alice
            .apply_commit(&commit, &[&charlie_add_proposal], &[], None)
            .expect("Could not apply Commit");

        let mut group_charlie = MlsGroup::new_from_welcome(
            welcome_option.unwrap(),
            Some(group_alice.tree().public_key_tree_copy()),
            charlie_key_package_bundle,
            None,
        )
        .expect("Charlie: Error creating group from Welcome");

        // Alice removes Bob
        let bob_remove_proposal = group_alice
            .create_remove_proposal(group_aad, &alice_credential_bundle, LeafIndex::from(1usize))
            .expect("Could not create proposal.");
        let (commit, _welcome_option, kpb_option) = group_alice
            .create_commit(
                group_aad,
                &alice_credential_bundle,
                &[&bob_remove_proposal],
                &[],
                false,
                None,
            )
            .expect("Error creating Commit");

        _print_tree(&group_alice.tree(), "Alice tree");
        _print_tree(&group_charlie.tree(), "Charlie tree");

        group_charlie
            .apply_commit(&commit, &[&bob_remove_proposal], &[], None)
            .expect("Charlie: Could not apply Commit");
        group_alice
            .apply_commit(
                &commit,
                &[&bob_remove_proposal],
                &[kpb_option.unwrap()],
                None,
            )
            .expect("Alice: Could not apply Commit");

        _print_tree(&group_alice.tree(), "Alice tree");
        _print_tree(&group_charlie.tree(), "Charlie tree");

        // Alice sends a message with a sender that points to a blank leaf
        // Expected result: MLSCiphertextError::UnknownSender

        let bogus_sender = LeafIndex::from(1usize);
        let bogus_sender_message = MLSPlaintext::new_from_application(
            bogus_sender,
            &[],
            &[1, 2, 3],
            &alice_credential_bundle,
            &group_alice.context(),
            &MembershipKey::from_secret(Secret::random(ciphersuite, None)),
        )
        .expect("Could not create new MLSPlaintext.");

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
            bogus_sender,
            &[],
            &[1, 2, 3],
            &alice_credential_bundle,
            &group_alice.context(),
            &MembershipKey::from_secret(Secret::random(ciphersuite, None)),
        )
        .expect("Could not create new MLSPlaintext.");

        let mut secret_tree = SecretTree::new(
            EncryptionSecret::random(ciphersuite),
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
