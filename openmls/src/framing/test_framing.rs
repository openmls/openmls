use crate::ciphersuite::signable::Signable;
use crate::ciphersuite::signable::Verifiable;
use crate::config::*;
use crate::framing::*;
use crate::prelude::KeyPackageBundle;
use crate::prelude::_print_tree;

/// This tests serializing/deserializing MlsPlaintext
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
        let group_context =
            GroupContext::new(GroupId::random(), GroupEpoch(1), vec![], vec![], &[]).unwrap();

        let serialized_context = group_context.serialized();
        let signature_input = MlsPlaintextTbs::new(
            serialized_context,
            GroupId::random(),
            GroupEpoch(1u64),
            sender,
            vec![1, 2, 3],
            ContentType::Application,
            MlsPlaintextContentType::Application(vec![4, 5, 6]),
        );
        let orig: MlsPlaintext = signature_input
            .sign(&credential_bundle)
            .expect("Signing failed.")
            .into();

        let enc = orig.encode_detached().unwrap();
        let copy = VerifiableMlsPlaintext::decode(&mut Cursor::new(&enc)).unwrap();
        let copy = copy
            .set_context(serialized_context)
            .verify(credential_bundle.credential())
            .unwrap();
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
        let group_context =
            GroupContext::new(GroupId::random(), GroupEpoch(1), vec![], vec![], &[]).unwrap();
        let membership_key =
            MembershipKey::from_secret(Secret::random(ciphersuite, None /* MLS version */));
        let mut mls_plaintext = MlsPlaintext::new_application(
            LeafIndex::from(2u32),
            &[1, 2, 3],
            &[4, 5, 6],
            &&credential_bundle,
            &group_context,
            &membership_key,
        )
        .unwrap();

        let serialized_context = group_context.serialized();

        println!(
            "Membership tag error: {:?}",
            mls_plaintext.verify_membership(serialized_context, &membership_key)
        );

        // Verify signature & membership tag
        assert!(mls_plaintext
            .verify_membership(serialized_context, &membership_key)
            .is_ok());

        // Change the content of the plaintext message
        mls_plaintext.set_content(MlsPlaintextContentType::Application(vec![7, 8, 9]));

        // Expect the signature & membership tag verification to fail
        assert!(mls_plaintext
            .verify_membership(serialized_context, &membership_key)
            .is_err());
    }
}

#[test]
fn unknown_sender() {
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
            MlsGroupConfig::default(),
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
        // Expected result: MlsCiphertextError::UnknownSender

        let bogus_sender = LeafIndex::from(1usize);
        let bogus_sender_message = MlsPlaintext::new_application(
            bogus_sender,
            &[],
            &[1, 2, 3],
            &alice_credential_bundle,
            &group_alice.context(),
            &MembershipKey::from_secret(Secret::random(ciphersuite, None)),
        )
        .expect("Could not create new MlsPlaintext.");

        let enc_message = MlsCiphertext::try_from_plaintext(
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
            MlsGroupError::MlsPlaintextError(MlsPlaintextError::UnknownSender)
        );

        // Alice sends a message with a sender that is outside of the group
        // Expected result: MlsCiphertextError::GenerationOutOfBound
        let bogus_sender = LeafIndex::from(100usize);
        let bogus_sender_message = MlsPlaintext::new_application(
            bogus_sender,
            &[],
            &[1, 2, 3],
            &alice_credential_bundle,
            &group_alice.context(),
            &MembershipKey::from_secret(Secret::random(ciphersuite, None)),
        )
        .expect("Could not create new MlsPlaintext.");

        let mut secret_tree = SecretTree::new(
            EncryptionSecret::random(ciphersuite),
            LeafIndex::from(100usize),
        );

        let enc_message = MlsCiphertext::try_from_plaintext(
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
            MlsGroupError::MlsCiphertextError(MlsCiphertextError::GenerationOutOfBound)
        );
    }
}

#[test]
fn confirmation_tag_presence() {
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

        // Generate KeyPackages
        let bob_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, Vec::new())
                .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();

        let alice_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, Vec::new())
                .unwrap();

        // Alice creates a group
        let group_id = [1, 2, 3, 4];
        let mut group_alice = MlsGroup::new(
            &group_id,
            ciphersuite.name(),
            alice_key_package_bundle,
            MlsGroupConfig::default(),
            None, /* Initial PSK */
            None, /* MLS version */
        )
        .unwrap();

        // Alice adds Bob
        let bob_add_proposal = group_alice
            .create_add_proposal(group_aad, &alice_credential_bundle, bob_key_package.clone())
            .expect("Could not create proposal.");

        let (mut commit, _welcome_option, _kpb_option) = group_alice
            .create_commit(
                group_aad,
                &alice_credential_bundle,
                &[&bob_add_proposal],
                &[],
                false,
                None,
            )
            .expect("Error creating Commit");

        commit.unset_confirmation_tag();

        let err = group_alice
            .apply_commit(&commit, &[&bob_add_proposal], &[], None)
            .expect_err("No error despite missing confirmation tag.");

        assert_eq!(
            err,
            MlsGroupError::ApplyCommitError(ApplyCommitError::ConfirmationTagMissing)
        );
    }
}

ctest_ciphersuites!(invalid_plaintext_signature,test (ciphersuite_name: CiphersuiteName) {
    log::info!("Testing ciphersuite {:?}", ciphersuite_name);
    let ciphersuite = Config::ciphersuite(ciphersuite_name).unwrap();
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

    // Generate KeyPackages
    let bob_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, Vec::new())
            .unwrap();
    let bob_key_package = bob_key_package_bundle.key_package();

    let alice_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, Vec::new())
            .unwrap();

    // Alice creates a group
    let group_id = [1, 2, 3, 4];
    let mut group_alice = MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        alice_key_package_bundle,
        MlsGroupConfig::default(),
        None, /* Initial PSK */
        None, /* MLS version */
    )
    .unwrap();

    // Alice adds Bob
    let bob_add_proposal = group_alice
        .create_add_proposal(group_aad, &alice_credential_bundle, bob_key_package.clone())
        .expect("Could not create proposal.");

    let (mut commit, _welcome, _kpb_option) = group_alice
        .create_commit(
            group_aad,
            &alice_credential_bundle,
            &[&bob_add_proposal],
            &[],
            false,
            None,
        )
        .expect("Error creating Commit");

    let original_encoded_commit = commit.encode_detached().unwrap();
    let input_commit = VerifiableMlsPlaintext::decode_detached(&original_encoded_commit).unwrap();
    let decoded_commit = group_alice.verify(input_commit).expect("Error verifying valid commit message");
    assert_eq!(decoded_commit.encode_detached().unwrap(), original_encoded_commit);

    // Remove membership tag.
    let good_membership_tag = commit.membership_tag().clone();
    commit.unset_membership_tag();
    let membership_error = commit.verify_membership(
        group_alice.context().serialized(),
        group_alice.epoch_secrets().membership_key())
        .err()
        .expect("Membership verification should have returned an error");
    assert_eq!(
        membership_error,
        MlsPlaintextError::VerificationError(VerificationError::MissingMembershipTag));

    // Tamper with membership tag.
    let mut modified_membership_tag = good_membership_tag
        .clone()
        .expect("There should have been a membership tag.");
    modified_membership_tag.0.mac_value[0] ^= 0xFF;
    commit.set_membership_tag_test(modified_membership_tag);
    let membership_error = commit.verify_membership(
        group_alice.context().serialized(),
        group_alice.epoch_secrets().membership_key())
        .err()
        .expect("Membership verification should have returned an error");
    assert_eq!(
        membership_error,
        MlsPlaintextError::VerificationError(VerificationError::InvalidMembershipTag));

    // Tamper with signature.
    let good_signature = commit.signature().clone();
    let mut modified_signature = commit.signature().as_slice().to_vec();
    modified_signature[0] ^= 0xFF;
    commit.signature_mut().modify(&modified_signature);
    let encoded_commit = commit.encode_detached().unwrap();
    let input_commit = VerifiableMlsPlaintext::decode_detached(&encoded_commit).unwrap();
    let decoded_commit = group_alice.verify(input_commit);
    assert_eq!(
        decoded_commit.err().expect("group.verify() should have returned an error"),
        MlsGroupError::MlsPlaintextError(MlsPlaintextError::CredentialError(CredentialError::InvalidSignature)));

    // Fix commit
    commit.set_signature(good_signature);
    commit.set_membership_tag_test(good_membership_tag.unwrap());

    // Remove confirmation tag.
    let good_confirmation_tag = commit.confirmation_tag().cloned();
    commit.unset_confirmation_tag();
    let error = group_alice
        .apply_commit(&commit, &[&bob_add_proposal], &[], None)
        .err()
        .expect("Applying commit should have yielded an error.");
    assert_eq!(
        error,
        MlsGroupError::ApplyCommitError(ApplyCommitError::ConfirmationTagMissing));

    // Tamper with confirmation tag.
    let mut modified_confirmation_tag = good_confirmation_tag
        .clone()
        .expect("There should have been a membership tag.");
    modified_confirmation_tag.0.mac_value[0] ^= 0xFF;
    commit.set_confirmation_tag(modified_confirmation_tag);
    let serialized_group_before = serde_json::to_string(&group_alice).unwrap();
    let error = group_alice
        .apply_commit(&commit, &[&bob_add_proposal], &[], None)
        .err()
        .expect("Applying commit should have yielded an error.");
    assert_eq!(
        error,
        MlsGroupError::ApplyCommitError(ApplyCommitError::ConfirmationTagMismatch));
    let serialized_group_after = serde_json::to_string(&group_alice).unwrap();
    assert_eq!(serialized_group_before, serialized_group_after);

    // Fix commit again and apply it.
    commit.set_confirmation_tag(good_confirmation_tag.unwrap());
    let encoded_commit = commit.encode_detached().unwrap();
    let input_commit = VerifiableMlsPlaintext::decode_detached(&encoded_commit).unwrap();
    let decoded_commit = group_alice.verify(input_commit).expect("Error verifying commit");
    assert_eq!(original_encoded_commit, decoded_commit.encode_detached().unwrap());
    group_alice
        .apply_commit(&decoded_commit, &[&bob_add_proposal], &[], None)
        .expect("Alice: Error applying commit.");
});
