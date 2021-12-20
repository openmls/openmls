//use crate::test_utils::*;
use openmls_traits::OpenMlsCryptoProvider;

use rstest::*;
use rstest_reuse::{self, *};

use core_group::create_commit_params::CreateCommitParams;
use core_group::proposals::ProposalStore;
use core_group::proposals::StagedProposal;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

use crate::{
    ciphersuite::signable::{Signable, Verifiable},
    config::*,
    framing::*,
    key_packages::KeyPackageBundle,
    utils::print_tree,
};

/// This tests serializing/deserializing MlsPlaintext
#[apply(ciphersuites_and_backends)]
fn codec_plaintext(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let credential_bundle = CredentialBundle::new(
        vec![7, 8, 9],
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let sender = Sender {
        sender_type: SenderType::Member,
        sender: 2u32,
    };
    let group_context =
        GroupContext::new(GroupId::random(backend), GroupEpoch(1), vec![], vec![], &[])
            .expect("An unexpected error occurred.");

    let serialized_context = group_context
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let signature_input = MlsPlaintextTbs::new(
        WireFormat::MlsPlaintext,
        GroupId::random(backend),
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
        .sign(backend, &credential_bundle)
        .expect("Signing failed.");

    let enc = orig
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let mut copy = VerifiableMlsPlaintext::tls_deserialize(&mut enc.as_slice())
        .expect("An unexpected error occurred.");
    copy.set_context(serialized_context);
    let copy = copy
        .verify(backend, credential_bundle.credential())
        .expect("An unexpected error occurred.");
    assert_eq!(orig, copy);
    assert!(!orig.is_handshake_message());
}

/// This tests serializing/deserializing MlsCiphertext
#[apply(ciphersuites_and_backends)]
fn codec_ciphertext(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let credential_bundle = CredentialBundle::new(
        vec![7, 8, 9],
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let sender = Sender {
        sender_type: SenderType::Member,
        sender: 0u32,
    };
    let group_context = GroupContext::new(
        GroupId::from_slice(&[5, 5, 5]),
        GroupEpoch(1),
        vec![],
        vec![],
        &[],
    )
    .expect("An unexpected error occurred.");

    let serialized_context = group_context
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let signature_input = MlsPlaintextTbs::new(
        WireFormat::MlsCiphertext,
        GroupId::random(backend),
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
        .sign(backend, &credential_bundle)
        .expect("Signing failed.");

    let mut key_schedule = KeySchedule::init(
        ciphersuite,
        backend,
        JoinerSecret::random(ciphersuite, backend, ProtocolVersion::default()),
        None, // PSK
    )
    .expect("Could not create KeySchedule.");

    let serialized_group_context = group_context
        .tls_serialize_detached()
        .expect("Could not serialize group context.");

    key_schedule
        .add_context(backend, &serialized_group_context)
        .expect("Could not add context to key schedule");

    let mut message_secrets = MessageSecrets::random(ciphersuite, backend);

    let orig = MlsCiphertext::try_from_plaintext(
        &plaintext,
        ciphersuite,
        backend,
        MlsMessageHeader {
            group_id: group_context.group_id().clone(),
            epoch: group_context.epoch(),
            sender: sender.to_leaf_index(),
        },
        &mut message_secrets,
        0,
    )
    .expect("Could not encrypt MlsPlaintext.");

    let enc = orig
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let copy =
        MlsCiphertext::tls_deserialize(&mut enc.as_slice()).expect("An unexpected error occurred.");

    assert_eq!(orig, copy);
    assert!(!orig.is_handshake_message());
}

/// This tests the correctness of wire format checks
#[apply(ciphersuites_and_backends)]
fn wire_format_checks(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let credential_bundle = CredentialBundle::new(
        vec![7, 8, 9],
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let sender = Sender {
        sender_type: SenderType::Member,
        sender: (0u32),
    };
    let group_context = GroupContext::new(
        GroupId::from_slice(&[5, 5, 5]),
        GroupEpoch(1),
        vec![],
        vec![],
        &[],
    )
    .expect("An unexpected error occurred.");

    let serialized_context = group_context
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let signature_input = MlsPlaintextTbs::new(
        WireFormat::MlsCiphertext,
        GroupId::random(backend),
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
        .sign(backend, &credential_bundle)
        .expect("Signing failed.");

    let mut key_schedule = KeySchedule::init(
        ciphersuite,
        backend,
        JoinerSecret::random(ciphersuite, backend, ProtocolVersion::default()),
        None, // PSK
    )
    .expect("Could not create KeySchedule.");

    let serialized_group_context = group_context
        .tls_serialize_detached()
        .expect("Could not serialize group context.");

    key_schedule
        .add_context(backend, &serialized_group_context)
        .expect("Could not add context to key schedule");

    let mut message_secrets = MessageSecrets::random(ciphersuite, backend);

    let mut ciphertext = MlsCiphertext::try_from_plaintext(
        &plaintext,
        ciphersuite,
        backend,
        MlsMessageHeader {
            group_id: group_context.group_id().clone(),
            epoch: group_context.epoch(),
            sender: sender.to_leaf_index(),
        },
        &mut message_secrets,
        0,
    )
    .expect("Could not encrypt MlsPlaintext.");

    // Decrypt the ciphertext and expect the correct wire format

    let verifiable_plaintext = ciphertext
        .to_plaintext(ciphersuite, backend, &mut message_secrets)
        .expect("Could not decrypt MlsCiphertext.");

    assert_eq!(
        verifiable_plaintext.wire_format(),
        WireFormat::MlsCiphertext
    );

    // Try to decrypt a ciphertext with the wrong wire format

    ciphertext.set_wire_format(WireFormat::MlsPlaintext);

    assert_eq!(
        ciphertext
            .to_plaintext(ciphersuite, backend, &mut message_secrets)
            .expect_err("Could decrypt despite wrong wire format."),
        MlsCiphertextError::WrongWireFormat
    );

    // Try to encrypt an MlsPlaintext with the wrong wire format

    plaintext.set_wire_format(WireFormat::MlsPlaintext);

    assert_eq!(
        MlsCiphertext::try_from_plaintext(
            &plaintext,
            ciphersuite,
            backend,
            MlsMessageHeader {
                group_id: group_context.group_id().clone(),
                epoch: group_context.epoch(),
                sender: sender.to_leaf_index(),
            },
            &mut message_secrets,
            0,
        )
        .expect_err("Could encrypt despite wrong wire format."),
        MlsCiphertextError::WrongWireFormat
    );
}

#[apply(ciphersuites_and_backends)]
fn membership_tag(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let credential_bundle = CredentialBundle::new(
        vec![7, 8, 9],
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let group_context =
        GroupContext::new(GroupId::random(backend), GroupEpoch(1), vec![], vec![], &[])
            .expect("An unexpected error occurred.");
    let membership_key = MembershipKey::from_secret(
        Secret::random(ciphersuite, backend, None /* MLS version */)
            .expect("Not enough randomness."),
    );
    let mut mls_plaintext = MlsPlaintext::new_application(
        2u32,
        &[1, 2, 3],
        &[4, 5, 6],
        &credential_bundle,
        &group_context,
        &membership_key,
        backend,
    )
    .expect("An unexpected error occurred.");
    let serialized_context: Vec<u8> = group_context
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    let verifiable_mls_plaintext =
        VerifiableMlsPlaintext::from_plaintext(mls_plaintext.clone(), serialized_context.clone());

    println!(
        "Membership tag error: {:?}",
        verifiable_mls_plaintext.verify_membership(backend, &membership_key)
    );

    // Verify signature & membership tag
    assert!(verifiable_mls_plaintext
        .verify_membership(backend, &membership_key)
        .is_ok());

    // Change the content of the plaintext message
    mls_plaintext.set_content(MlsPlaintextContentType::Application(vec![7, 8, 9].into()));
    let verifiable_mls_plaintext =
        VerifiableMlsPlaintext::from_plaintext(mls_plaintext.clone(), serialized_context);

    // Expect the signature & membership tag verification to fail
    assert!(verifiable_mls_plaintext
        .verify_membership(backend, &membership_key)
        .is_err());
}

#[apply(ciphersuites_and_backends)]
fn unknown_sender(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let charlie_credential_bundle = CredentialBundle::new(
        "Charlie".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    let charlie_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &charlie_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let charlie_key_package = charlie_key_package_bundle.key_package();

    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    // Alice creates a group
    let mut group_alice = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Error creating group.");

    // Alice adds Bob
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");

    let mut proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create StagedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let (commit, _welcome_option, _kpb_option) = group_alice
        .create_commit(params, backend)
        .expect("Error creating Commit");

    let staged_commit = group_alice
        .stage_commit(&commit, &proposal_store, &[], backend)
        .expect("Could not stage Commit");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");

    // Alice adds Charlie

    let charlie_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            charlie_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, charlie_add_proposal)
            .expect("Could not create staged proposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let (commit, welcome_option, _kpb_option) = group_alice
        .create_commit(params, backend)
        .expect("Error creating Commit");

    let staged_commit = group_alice
        .stage_commit(&commit, &proposal_store, &[], backend)
        .expect("Could not stage Commit");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");

    let mut group_charlie = CoreGroup::new_from_welcome(
        welcome_option.expect("An unexpected error occurred."),
        Some(group_alice.treesync().export_nodes()),
        charlie_key_package_bundle,
        backend,
    )
    .expect("Charlie: Error creating group from Welcome");

    // Alice removes Bob
    let bob_remove_proposal = group_alice
        .create_remove_proposal(framing_parameters, &alice_credential_bundle, 1u32, backend)
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_remove_proposal)
            .expect("Could not create staged proposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let (commit, _welcome_option, kpb_option) = group_alice
        .create_commit(params, backend)
        .expect("Error creating Commit");

    let staged_commit = group_charlie
        .stage_commit(&commit, &proposal_store, &[], backend)
        .expect("Charlie: Could not stage Commit");
    group_charlie
        .merge_commit(staged_commit)
        .expect("error merging commit");
    let staged_commit = group_alice
        .stage_commit(
            &commit,
            &proposal_store,
            &[kpb_option.expect("An unexpected error occurred.")],
            backend,
        )
        .expect("Alice: Could not stage Commit");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");

    print_tree(group_alice.treesync(), "Alice tree");
    print_tree(group_charlie.treesync(), "Charlie tree");

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
            Secret::random(ciphersuite, backend, None).expect("Not enough randomness."),
        ),
        backend,
    )
    .expect("Could not create new MlsPlaintext.");

    let enc_message = MlsCiphertext::try_from_plaintext(
        &bogus_sender_message,
        ciphersuite,
        backend,
        MlsMessageHeader {
            group_id: group_alice.group_id().clone(),
            epoch: group_alice.context().epoch(),
            sender: 1u32,
        },
        group_alice.message_secrets_mut(),
        0,
    )
    .expect("Encryption error");

    let received_message = group_charlie
        .decrypt(&enc_message, backend)
        .expect("error decrypting message");
    let received_message = group_charlie.verify(received_message, backend);
    assert_eq!(
        received_message.unwrap_err(),
        CoreGroupError::MlsPlaintextError(MlsPlaintextError::UnknownSender)
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
            Secret::random(ciphersuite, backend, None).expect("Not enough randomness."),
        ),
        backend,
    )
    .expect("Could not create new MlsPlaintext.");

    let enc_message = MlsCiphertext::try_from_plaintext(
        &bogus_sender_message,
        ciphersuite,
        backend,
        MlsMessageHeader {
            group_id: group_alice.group_id().clone(),
            epoch: group_alice.context().epoch(),
            sender: 1u32,
        },
        group_alice.message_secrets_mut(),
        0,
    )
    .expect("Encryption error");

    let received_message = group_charlie.decrypt(&enc_message, backend);
    assert_eq!(
        received_message.unwrap_err(),
        CoreGroupError::MlsCiphertextError(MlsCiphertextError::GenerationOutOfBound)
    );
}

#[apply(ciphersuites_and_backends)]
fn confirmation_tag_presence(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    // Alice creates a group
    let mut group_alice = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Error creating group.");

    // Alice adds Bob
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");

    let proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create StagedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let (mut commit, _welcome_option, _kpb_option) = group_alice
        .create_commit(params, backend)
        .expect("Error creating Commit");

    commit.unset_confirmation_tag();

    let err = group_alice
        .stage_commit(&commit, &proposal_store, &[], backend)
        .expect_err("No error despite missing confirmation tag.");

    assert_eq!(
        err,
        CoreGroupError::StageCommitError(StageCommitError::ConfirmationTagMissing)
    );
}

#[apply(ciphersuites_and_backends)]
fn invalid_plaintext_signature(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    // Alice creates a group
    let mut group_alice = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Error creating group.");

    // Alice adds Bob
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");

    let mut proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal.clone())
            .expect("Could not create StagedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let (mut commit, _welcome, _kpb_option) = group_alice
        .create_commit(params, backend)
        .expect("Error creating Commit");

    let original_encoded_commit = commit
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let mut input_commit =
        VerifiableMlsPlaintext::tls_deserialize(&mut original_encoded_commit.as_slice())
            .expect("An unexpected error occurred.");
    let original_input_commit = input_commit.clone();

    // Remove membership tag.
    let good_membership_tag = input_commit.membership_tag().clone();
    input_commit.unset_membership_tag();
    let membership_error = group_alice
        .verify_membership_tag(backend, &mut input_commit)
        .err()
        .expect("Membership verification should have returned an error");

    assert_eq!(
        membership_error,
        CoreGroupError::MlsPlaintextError(MlsPlaintextError::VerificationError(
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
        .verify_membership_tag(backend, &mut input_commit)
        .err()
        .expect("Membership verification should have returned an error");

    assert_eq!(
        membership_error,
        CoreGroupError::MlsPlaintextError(MlsPlaintextError::VerificationError(
            VerificationError::InvalidMembershipTag
        ))
    );

    let decoded_commit = group_alice
        .verify(original_input_commit, backend)
        .expect("Error verifying valid commit message");
    assert_eq!(
        decoded_commit
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
        original_encoded_commit
    );

    // Tamper with signature.
    let good_signature = commit.signature().clone();
    commit.invalidate_signature();
    let encoded_commit = commit
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let input_commit = VerifiableMlsPlaintext::tls_deserialize(&mut encoded_commit.as_slice())
        .expect("An unexpected error occurred.");
    let decoded_commit = group_alice.verify(input_commit, backend);
    assert_eq!(
        decoded_commit
            .err()
            .expect("group.verify() should have returned an error"),
        CoreGroupError::MlsPlaintextError(MlsPlaintextError::CredentialError(
            CredentialError::InvalidSignature
        ))
    );

    // Fix commit
    commit.set_signature(good_signature);
    commit.set_membership_tag_test(good_membership_tag.expect("An unexpected error occurred."));

    // Remove confirmation tag.
    let good_confirmation_tag = commit.confirmation_tag().cloned();
    commit.unset_confirmation_tag();

    let error = group_alice
        .stage_commit(&commit, &proposal_store, &[], backend)
        .expect_err("Staging commit should have yielded an error.");
    assert_eq!(
        error,
        CoreGroupError::StageCommitError(StageCommitError::ConfirmationTagMissing)
    );

    // Tamper with confirmation tag.
    let mut modified_confirmation_tag = good_confirmation_tag
        .clone()
        .expect("There should have been a membership tag.");
    modified_confirmation_tag.0.mac_value[0] ^= 0xFF;
    commit.set_confirmation_tag(modified_confirmation_tag);
    let serialized_group_before =
        serde_json::to_string(&group_alice).expect("An unexpected error occurred.");

    proposal_store.empty();
    proposal_store.add(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal.clone())
            .expect("Could not create staged proposal."),
    );

    let error = group_alice
        .stage_commit(&commit, &proposal_store, &[], backend)
        .expect_err("Staging commit should have yielded an error.");
    assert_eq!(
        error,
        CoreGroupError::StageCommitError(StageCommitError::ConfirmationTagMismatch)
    );
    let serialized_group_after =
        serde_json::to_string(&group_alice).expect("An unexpected error occurred.");
    assert_eq!(serialized_group_before, serialized_group_after);

    // Fix commit again and stage it.
    commit.set_confirmation_tag(good_confirmation_tag.expect("An unexpected error occurred."));
    let encoded_commit = commit
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let input_commit = VerifiableMlsPlaintext::tls_deserialize(&mut encoded_commit.as_slice())
        .expect("An unexpected error occurred.");
    let decoded_commit = group_alice
        .verify(input_commit, backend)
        .expect("Error verifying commit");
    assert_eq!(
        original_encoded_commit,
        decoded_commit
            .tls_serialize_detached()
            .expect("An unexpected error occurred.")
    );

    proposal_store.empty();
    proposal_store.add(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create staged proposal."),
    );

    group_alice
        .stage_commit(&decoded_commit, &proposal_store, &[], backend)
        .expect("Alice: Error staging commit.");
}
