use mls_group::create_commit_params::CreateCommitParams;
use mls_group::proposals::ProposalStore;
use mls_group::proposals::StagedProposal;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

use crate::framing::*;
use crate::prelude::KeyPackageBundle;
use crate::prelude::_print_tree;
use crate::tree::secret_tree::SecretTree;
use crate::{
    ciphersuite::signable::{Signable, Verifiable},
    config::*,
};

/// This tests serializing/deserializing MlsPlaintext
#[test]
fn codec_plaintext() {
    let crypto = OpenMlsRustCrypto::default();

    for ciphersuite in Config::supported_ciphersuites() {
        let credential_bundle = CredentialBundle::new(
            vec![7, 8, 9],
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            &crypto,
        )
        .unwrap();
        let sender = Sender {
            sender_type: SenderType::Member,
            sender: LeafIndex::from(2u32),
        };
        let group_context =
            GroupContext::new(GroupId::random(&crypto), GroupEpoch(1), vec![], vec![], &[])
                .unwrap();

        let serialized_context = group_context.tls_serialize_detached().unwrap();
        let signature_input = MlsPlaintextTbs::new(
            WireFormat::MlsPlaintext,
            GroupId::random(&crypto),
            GroupEpoch(1u64),
            sender,
            vec![1, 2, 3].into(),
            Payload {
                content_type: ContentType::Application,
                payload: MlsPlaintextContentType::Application(vec![4, 5, 6].into()),
            },
        )
        .with_context(serialized_context.clone());
        let orig: MlsPlaintext = signature_input
            .sign(&crypto, &credential_bundle)
            .expect("Signing failed.");

        let enc = orig.tls_serialize_detached().unwrap();
        let mut copy = VerifiableMlsPlaintext::tls_deserialize(&mut enc.as_slice()).unwrap();
        copy.set_context(serialized_context);
        let copy = copy
            .verify(&crypto, credential_bundle.credential())
            .unwrap();
        assert_eq!(orig, copy);
        assert!(!orig.is_handshake_message());
    }
}

/// This tests serializing/deserializing MlsCiphertext
#[test]
fn codec_ciphertext() {
    let crypto = OpenMlsRustCrypto::default();

    for ciphersuite in Config::supported_ciphersuites() {
        let credential_bundle = CredentialBundle::new(
            vec![7, 8, 9],
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            &crypto,
        )
        .unwrap();
        let sender = Sender {
            sender_type: SenderType::Member,
            sender: LeafIndex::from(0u32),
        };
        let group_context = GroupContext::new(
            GroupId::from_slice(&[5, 5, 5]),
            GroupEpoch(1),
            vec![],
            vec![],
            &[],
        )
        .unwrap();

        let serialized_context = group_context.tls_serialize_detached().unwrap();
        let signature_input = MlsPlaintextTbs::new(
            WireFormat::MlsCiphertext,
            GroupId::random(&crypto),
            GroupEpoch(1u64),
            sender,
            vec![1, 2, 3].into(),
            Payload {
                payload: MlsPlaintextContentType::Application(vec![4, 5, 6].into()),
                content_type: ContentType::Application,
            },
        )
        .with_context(serialized_context);
        let plaintext: MlsPlaintext = signature_input
            .sign(&crypto, &credential_bundle)
            .expect("Signing failed.");

        let mut key_schedule = KeySchedule::init(
            ciphersuite,
            &crypto,
            JoinerSecret::random(ciphersuite, &crypto, ProtocolVersion::default()),
            None, // PSK
        )
        .expect("Could not create KeySchedule.");

        let serialized_group_context = group_context
            .tls_serialize_detached()
            .expect("Could not serialize group context.");

        key_schedule
            .add_context(&crypto, &serialized_group_context)
            .expect("Could not add context to key schedule");

        let epoch_secrets = key_schedule
            .epoch_secrets(&crypto, false)
            .expect("Could not generte epoch secrets");

        let mut secret_tree = SecretTree::new(epoch_secrets.encryption_secret(), 1u32.into());

        let orig = MlsCiphertext::try_from_plaintext(
            &plaintext,
            ciphersuite,
            &crypto,
            &group_context,
            sender.to_leaf_index(),
            Secrets {
                epoch_secrets: &epoch_secrets,
                secret_tree: &mut secret_tree,
            },
            0,
        )
        .expect("Could not encrypt MlsPlaintext.");

        let enc = orig.tls_serialize_detached().unwrap();
        let copy = MlsCiphertext::tls_deserialize(&mut enc.as_slice()).unwrap();

        assert_eq!(orig, copy);
        assert!(!orig.is_handshake_message());
    }
}

/// This tests the correctness of wire format checks
#[test]
fn wire_format_checks() {
    let crypto = OpenMlsRustCrypto::default();

    for ciphersuite in Config::supported_ciphersuites() {
        let credential_bundle = CredentialBundle::new(
            vec![7, 8, 9],
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            &crypto,
        )
        .unwrap();
        let sender = Sender {
            sender_type: SenderType::Member,
            sender: LeafIndex::from(0u32),
        };
        let group_context = GroupContext::new(
            GroupId::from_slice(&[5, 5, 5]),
            GroupEpoch(1),
            vec![],
            vec![],
            &[],
        )
        .unwrap();

        let serialized_context = group_context.tls_serialize_detached().unwrap();
        let signature_input = MlsPlaintextTbs::new(
            WireFormat::MlsCiphertext,
            GroupId::random(&crypto),
            GroupEpoch(1u64),
            sender,
            vec![1, 2, 3].into(),
            Payload {
                content_type: ContentType::Application,
                payload: MlsPlaintextContentType::Application(vec![4, 5, 6].into()),
            },
        )
        .with_context(serialized_context);
        let mut plaintext: MlsPlaintext = signature_input
            .sign(&crypto, &credential_bundle)
            .expect("Signing failed.");

        let mut key_schedule = KeySchedule::init(
            ciphersuite,
            &crypto,
            JoinerSecret::random(ciphersuite, &crypto, ProtocolVersion::default()),
            None, // PSK
        )
        .expect("Could not create KeySchedule.");

        let serialized_group_context = group_context
            .tls_serialize_detached()
            .expect("Could not serialize group context.");

        key_schedule
            .add_context(&crypto, &serialized_group_context)
            .expect("Could not add context to key schedule");

        let epoch_secrets = key_schedule
            .epoch_secrets(&crypto, false)
            .expect("Could not generte epoch secrets");

        let mut secret_tree = SecretTree::new(epoch_secrets.encryption_secret(), 1u32.into());

        let mut ciphertext = MlsCiphertext::try_from_plaintext(
            &plaintext,
            ciphersuite,
            &crypto,
            &group_context,
            sender.to_leaf_index(),
            Secrets {
                epoch_secrets: &epoch_secrets,
                secret_tree: &mut secret_tree,
            },
            0,
        )
        .expect("Could not encrypt MlsPlaintext.");

        // Decrypt the ciphertext and expect the correct wire format

        let verifiable_plaintext = ciphertext
            .to_plaintext(ciphersuite, &crypto, &epoch_secrets, &mut secret_tree)
            .expect("Could not decrypt MlsCiphertext.");

        assert_eq!(
            verifiable_plaintext.wire_format(),
            WireFormat::MlsCiphertext
        );

        // Try to decrypt a ciphertext with the wrong wire format

        ciphertext.set_wire_format(WireFormat::MlsPlaintext);

        assert_eq!(
            ciphertext
                .to_plaintext(ciphersuite, &crypto, &epoch_secrets, &mut secret_tree)
                .expect_err("Could decrypt despite wrong wire format."),
            MlsCiphertextError::WrongWireFormat
        );

        // Try to encrypt an MlsPlaintext with the wrong wire format

        plaintext.set_wire_format(WireFormat::MlsPlaintext);

        assert_eq!(
            MlsCiphertext::try_from_plaintext(
                &plaintext,
                ciphersuite,
                &crypto,
                &group_context,
                sender.to_leaf_index(),
                Secrets {
                    epoch_secrets: &epoch_secrets,
                    secret_tree: &mut secret_tree,
                },
                0,
            )
            .expect_err("Could encrypt despite wrong wire format."),
            MlsCiphertextError::WrongWireFormat
        );
    }
}

#[test]
fn membership_tag() {
    let crypto = &OpenMlsRustCrypto::default();

    for ciphersuite in Config::supported_ciphersuites() {
        let credential_bundle = CredentialBundle::new(
            vec![7, 8, 9],
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            crypto,
        )
        .unwrap();
        let group_context =
            GroupContext::new(GroupId::random(crypto), GroupEpoch(1), vec![], vec![], &[]).unwrap();
        let membership_key = MembershipKey::from_secret(
            Secret::random(ciphersuite, crypto, None /* MLS version */)
                .expect("Not enough randomness."),
        );
        let mut mls_plaintext = MlsPlaintext::new_application(
            LeafIndex::from(2u32),
            &[1, 2, 3],
            &[4, 5, 6],
            &credential_bundle,
            &group_context,
            &membership_key,
            crypto,
        )
        .unwrap();
        let serialized_context: Vec<u8> = group_context.tls_serialize_detached().unwrap();

        let verifiable_mls_plaintext = VerifiableMlsPlaintext::from_plaintext(
            mls_plaintext.clone(),
            serialized_context.clone(),
        );

        println!(
            "Membership tag error: {:?}",
            verifiable_mls_plaintext.verify_membership(crypto, &membership_key)
        );

        // Verify signature & membership tag
        assert!(verifiable_mls_plaintext
            .verify_membership(crypto, &membership_key)
            .is_ok());

        // Change the content of the plaintext message
        mls_plaintext.set_content(MlsPlaintextContentType::Application(vec![7, 8, 9].into()));
        let verifiable_mls_plaintext =
            VerifiableMlsPlaintext::from_plaintext(mls_plaintext.clone(), serialized_context);

        // Expect the signature & membership tag verification to fail
        assert!(verifiable_mls_plaintext
            .verify_membership(crypto, &membership_key)
            .is_err());
    }
}

#[test]
fn unknown_sender() {
    let crypto = &OpenMlsRustCrypto::default();

    for ciphersuite in Config::supported_ciphersuites() {
        let group_aad = b"Alice's test group";
        let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

        // Define credential bundles
        let alice_credential_bundle = CredentialBundle::new(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            crypto,
        )
        .unwrap();
        let bob_credential_bundle = CredentialBundle::new(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            crypto,
        )
        .unwrap();
        let charlie_credential_bundle = CredentialBundle::new(
            "Charlie".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            crypto,
        )
        .unwrap();

        // Generate KeyPackages
        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            crypto,
            Vec::new(),
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();

        let charlie_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &charlie_credential_bundle,
            crypto,
            Vec::new(),
        )
        .unwrap();
        let charlie_key_package = charlie_key_package_bundle.key_package();

        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            crypto,
            Vec::new(),
        )
        .unwrap();

        // Alice creates a group
        let mut group_alice = MlsGroup::builder(GroupId::random(crypto), alice_key_package_bundle)
            .build(crypto)
            .expect("Error creating group.");

        // Alice adds Bob
        let bob_add_proposal = group_alice
            .create_add_proposal(
                framing_parameters,
                &alice_credential_bundle,
                bob_key_package.clone(),
                crypto,
            )
            .expect("Could not create proposal.");

        let mut proposal_store = ProposalStore::from_staged_proposal(
            StagedProposal::from_mls_plaintext(ciphersuite, crypto, bob_add_proposal)
                .expect("Could not create StagedProposal."),
        );

        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(&alice_credential_bundle)
            .proposal_store(&proposal_store)
            .force_self_update(false)
            .build();
        let (commit, _welcome_option, _kpb_option) = group_alice
            .create_commit(params, crypto)
            .expect("Error creating Commit");

        let staged_commit = group_alice
            .stage_commit(&commit, &proposal_store, &[], None, crypto)
            .expect("Could not stage Commit");
        group_alice.merge_commit(staged_commit);

        // Alice adds Charlie

        let charlie_add_proposal = group_alice
            .create_add_proposal(
                framing_parameters,
                &alice_credential_bundle,
                charlie_key_package.clone(),
                crypto,
            )
            .expect("Could not create proposal.");

        proposal_store.empty();
        proposal_store.add(
            StagedProposal::from_mls_plaintext(ciphersuite, crypto, charlie_add_proposal)
                .expect("Could not create staged proposal."),
        );

        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(&alice_credential_bundle)
            .proposal_store(&proposal_store)
            .force_self_update(false)
            .build();
        let (commit, welcome_option, _kpb_option) = group_alice
            .create_commit(params, crypto)
            .expect("Error creating Commit");

        let staged_commit = group_alice
            .stage_commit(&commit, &proposal_store, &[], None, crypto)
            .expect("Could not stage Commit");
        group_alice.merge_commit(staged_commit);

        let mut group_charlie = MlsGroup::new_from_welcome(
            welcome_option.unwrap(),
            Some(group_alice.tree().public_key_tree_copy()),
            charlie_key_package_bundle,
            None,
            crypto,
        )
        .expect("Charlie: Error creating group from Welcome");

        // Alice removes Bob
        let bob_remove_proposal = group_alice
            .create_remove_proposal(framing_parameters, &alice_credential_bundle, 1u32, crypto)
            .expect("Could not create proposal.");

        proposal_store.empty();
        proposal_store.add(
            StagedProposal::from_mls_plaintext(ciphersuite, crypto, bob_remove_proposal)
                .expect("Could not create staged proposal."),
        );

        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(&alice_credential_bundle)
            .proposal_store(&proposal_store)
            .force_self_update(false)
            .build();
        let (commit, _welcome_option, kpb_option) = group_alice
            .create_commit(params, crypto)
            .expect("Error creating Commit");

        let staged_commit = group_charlie
            .stage_commit(&commit, &proposal_store, &[], None, crypto)
            .expect("Charlie: Could not stage Commit");
        group_charlie.merge_commit(staged_commit);
        let staged_commit = group_alice
            .stage_commit(
                &commit,
                &proposal_store,
                &[kpb_option.unwrap()],
                None,
                crypto,
            )
            .expect("Alice: Could not stage Commit");
        group_alice.merge_commit(staged_commit);

        _print_tree(&group_alice.tree(), "Alice tree");
        _print_tree(&group_charlie.tree(), "Charlie tree");

        // Alice sends a message with a sender that points to a blank leaf
        // Expected result: MlsCiphertextError::UnknownSender

        let bogus_sender = 1u32;
        let bogus_sender_message = MlsPlaintext::new_application(
            bogus_sender,
            &[],
            &[1, 2, 3],
            &alice_credential_bundle,
            group_alice.context(),
            &MembershipKey::from_secret(
                Secret::random(ciphersuite, crypto, None).expect("Not enough randomness."),
            ),
            crypto,
        )
        .expect("Could not create new MlsPlaintext.");

        let enc_message = MlsCiphertext::try_from_plaintext(
            &bogus_sender_message,
            ciphersuite,
            crypto,
            group_alice.context(),
            1u32,
            Secrets {
                epoch_secrets: group_alice.epoch_secrets(),
                secret_tree: &mut group_alice.secret_tree_mut(),
            },
            0,
        )
        .expect("Encryption error");

        let received_message = group_charlie
            .decrypt(&enc_message, crypto)
            .expect("error decrypting message");
        let received_message = group_charlie.verify(received_message, crypto);
        assert_eq!(
            received_message.unwrap_err(),
            MlsGroupError::MlsPlaintextError(MlsPlaintextError::UnknownSender)
        );

        // Alice sends a message with a sender that is outside of the group
        // Expected result: MlsCiphertextError::GenerationOutOfBound
        let bogus_sender = 100u32;
        let bogus_sender_message = MlsPlaintext::new_application(
            bogus_sender,
            &[],
            &[1, 2, 3],
            &alice_credential_bundle,
            group_alice.context(),
            &MembershipKey::from_secret(
                Secret::random(ciphersuite, crypto, None).expect("Not enough randomness."),
            ),
            crypto,
        )
        .expect("Could not create new MlsPlaintext.");

        let mut secret_tree =
            SecretTree::new(EncryptionSecret::random(ciphersuite, crypto), 100u32.into());

        let enc_message = MlsCiphertext::try_from_plaintext(
            &bogus_sender_message,
            ciphersuite,
            crypto,
            group_alice.context(),
            99u32,
            Secrets {
                epoch_secrets: group_alice.epoch_secrets(),
                secret_tree: &mut secret_tree,
            },
            0,
        )
        .expect("Encryption error");

        let received_message = group_charlie.decrypt(&enc_message, crypto);
        assert_eq!(
            received_message.unwrap_err(),
            MlsGroupError::MlsCiphertextError(MlsCiphertextError::GenerationOutOfBound)
        );
    }
}

#[test]
fn confirmation_tag_presence() {
    let crypto = &OpenMlsRustCrypto::default();

    for ciphersuite in Config::supported_ciphersuites() {
        let group_aad = b"Alice's test group";
        let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

        // Define credential bundles
        let alice_credential_bundle = CredentialBundle::new(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            crypto,
        )
        .unwrap();
        let bob_credential_bundle = CredentialBundle::new(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            crypto,
        )
        .unwrap();

        // Generate KeyPackages
        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            crypto,
            Vec::new(),
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();

        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            crypto,
            Vec::new(),
        )
        .unwrap();

        // Alice creates a group
        let mut group_alice = MlsGroup::builder(GroupId::random(crypto), alice_key_package_bundle)
            .build(crypto)
            .expect("Error creating group.");

        // Alice adds Bob
        let bob_add_proposal = group_alice
            .create_add_proposal(
                framing_parameters,
                &alice_credential_bundle,
                bob_key_package.clone(),
                crypto,
            )
            .expect("Could not create proposal.");

        let proposal_store = ProposalStore::from_staged_proposal(
            StagedProposal::from_mls_plaintext(ciphersuite, crypto, bob_add_proposal)
                .expect("Could not create StagedProposal."),
        );

        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(&alice_credential_bundle)
            .proposal_store(&proposal_store)
            .force_self_update(false)
            .build();
        let (mut commit, _welcome_option, _kpb_option) = group_alice
            .create_commit(params, crypto)
            .expect("Error creating Commit");

        commit.unset_confirmation_tag();

        let err = group_alice
            .stage_commit(&commit, &proposal_store, &[], None, crypto)
            .expect_err("No error despite missing confirmation tag.");

        assert_eq!(
            err,
            MlsGroupError::StageCommitError(StageCommitError::ConfirmationTagMissing)
        );
    }
}

ctest_ciphersuites!(invalid_plaintext_signature,test (ciphersuite_name: CiphersuiteName) {

        let crypto = &OpenMlsRustCrypto::default();

        log::info!("Testing ciphersuite {:?}", ciphersuite_name);
        let ciphersuite = Config::ciphersuite(ciphersuite_name).unwrap();
        let group_aad = b"Alice's test group";
        let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

        // Define credential bundles
        let alice_credential_bundle = CredentialBundle::new(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            crypto,
        )
        .unwrap();
        let bob_credential_bundle = CredentialBundle::new(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            crypto,
        )
        .unwrap();

        // Generate KeyPackages
        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            crypto,
            Vec::new(),
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();

        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            crypto,
            Vec::new(),
        )
        .unwrap();

        // Alice creates a group
        let mut group_alice = MlsGroup::builder(GroupId::random(crypto), alice_key_package_bundle)
            .build(crypto)
            .expect("Error creating group.");

        // Alice adds Bob
        let bob_add_proposal = group_alice
            .create_add_proposal(
                framing_parameters,
                &alice_credential_bundle,
                bob_key_package.clone(),
                crypto,
            )
            .expect("Could not create proposal.");

        let mut proposal_store = ProposalStore::from_staged_proposal(
            StagedProposal::from_mls_plaintext(ciphersuite, crypto, bob_add_proposal.clone())
                .expect("Could not create StagedProposal."),
        );

        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(&alice_credential_bundle)
            .proposal_store(&proposal_store)
            .force_self_update(false)
            .build();
        let (mut commit, _welcome, _kpb_option) = group_alice
            .create_commit(params, crypto)
            .expect("Error creating Commit");

        let original_encoded_commit = commit.tls_serialize_detached().unwrap();
        let mut input_commit =
            VerifiableMlsPlaintext::tls_deserialize(&mut original_encoded_commit.as_slice())
                .unwrap();
        let original_input_commit = input_commit.clone();

        // Remove membership tag.
        let good_membership_tag = input_commit.membership_tag().clone();
        input_commit.unset_membership_tag();
        let membership_error = group_alice
            .verify_membership_tag(crypto, &mut input_commit)
            .err()
            .expect("Membership verification should have returned an error");

        assert_eq!(
            membership_error,
            MlsGroupError::MlsPlaintextError(MlsPlaintextError::VerificationError(
                VerificationError::MissingMembershipTag
            ))
        );

        // Tamper with membership tag.
        let mut modified_membership_tag = good_membership_tag
            .clone()
            .expect("There should have been a membership tag.");
        modified_membership_tag.0.mac_value[0] ^= 0xFF;
        input_commit.set_membership_tag(modified_membership_tag);
        let membership_error = group_alice
            .verify_membership_tag(crypto, &mut input_commit)
            .err()
            .expect("Membership verification should have returned an error");

        assert_eq!(
            membership_error,
            MlsGroupError::MlsPlaintextError(MlsPlaintextError::VerificationError(
                VerificationError::InvalidMembershipTag
            ))
        );

        let decoded_commit = group_alice
            .verify(original_input_commit, crypto)
            .expect("Error verifying valid commit message");
        assert_eq!(
            decoded_commit.tls_serialize_detached().unwrap(),
            original_encoded_commit
        );

        // Tamper with signature.
        let good_signature = commit.signature().clone();
        commit.invalidate_signature();
        let encoded_commit = commit.tls_serialize_detached().unwrap();
        let input_commit =
            VerifiableMlsPlaintext::tls_deserialize(&mut encoded_commit.as_slice()).unwrap();
        let decoded_commit = group_alice.verify(input_commit, crypto);
        assert_eq!(
            decoded_commit
                .err()
                .expect("group.verify() should have returned an error"),
            MlsGroupError::MlsPlaintextError(MlsPlaintextError::CredentialError(
                CredentialError::InvalidSignature
            ))
        );

        // Fix commit
        commit.set_signature(good_signature);
        commit.set_membership_tag_test(good_membership_tag.unwrap());

        // Remove confirmation tag.
        let good_confirmation_tag = commit.confirmation_tag().cloned();
        commit.unset_confirmation_tag();


        let error = group_alice
            .stage_commit(&commit, &proposal_store, &[], None, crypto)
            .expect_err("Staging commit should have yielded an error.");
        assert_eq!(
            error,
            MlsGroupError::StageCommitError(StageCommitError::ConfirmationTagMissing)
        );

        // Tamper with confirmation tag.
        let mut modified_confirmation_tag = good_confirmation_tag
            .clone()
            .expect("There should have been a membership tag.");
        modified_confirmation_tag.0.mac_value[0] ^= 0xFF;
        commit.set_confirmation_tag(modified_confirmation_tag);
        let serialized_group_before = serde_json::to_string(&group_alice).unwrap();

        proposal_store.empty();
        proposal_store.add(
            StagedProposal::from_mls_plaintext(ciphersuite, crypto, bob_add_proposal.clone())
                .expect("Could not create staged proposal."),
        );

        let error = group_alice
            .stage_commit(&commit, &proposal_store, &[], None, crypto)
            .expect_err("Staging commit should have yielded an error.");
        assert_eq!(
            error,
            MlsGroupError::StageCommitError(StageCommitError::ConfirmationTagMismatch)
        );
        let serialized_group_after = serde_json::to_string(&group_alice).unwrap();
        assert_eq!(serialized_group_before, serialized_group_after);

        // Fix commit again and stage it.
        commit.set_confirmation_tag(good_confirmation_tag.unwrap());
        let encoded_commit = commit.tls_serialize_detached().unwrap();
        let input_commit =
            VerifiableMlsPlaintext::tls_deserialize(&mut encoded_commit.as_slice()).unwrap();
        let decoded_commit = group_alice
            .verify(input_commit, crypto)
            .expect("Error verifying commit");
        assert_eq!(
            original_encoded_commit,
            decoded_commit.tls_serialize_detached().unwrap()
        );

        proposal_store.empty();
        proposal_store.add(
            StagedProposal::from_mls_plaintext(ciphersuite, crypto, bob_add_proposal)
                .expect("Could not create staged proposal."),
        );

        group_alice
            .stage_commit(&decoded_commit, &proposal_store, &[], None, crypto)
            .expect("Alice: Error staging commit.");
    }
);
