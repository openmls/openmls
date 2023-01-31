use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{random::OpenMlsRand, types::Ciphersuite, OpenMlsCryptoProvider};

use rstest::*;
use rstest_reuse::{self, *};

use openmls_rust_crypto::OpenMlsRustCrypto;
use signable::Verifiable;
use tls_codec::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::signable::{Signable, SignatureError},
    extensions::Extensions,
    framing::*,
    group::{
        core_group::{
            create_commit_params::CreateCommitParams,
            proposals::{ProposalStore, QueuedProposal},
        },
        errors::*,
        tests::tree_printing::print_tree,
    },
    key_packages::KeyPackageBundle,
    tree::{secret_tree::SecretTree, sender_ratchet::SenderRatchetConfiguration},
    versions::ProtocolVersion,
};

/// This tests serializing/deserializing PublicMessage
#[apply(ciphersuites_and_backends)]
fn codec_plaintext(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (_credential, signature_keys) = test_utils::new_credential(
        backend,
        b"Creator",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let sender = Sender::build_member(LeafNodeIndex::new(987543210));
    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::random(backend),
        1,
        vec![],
        vec![],
        Extensions::empty(),
    );

    let serialized_context = group_context
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let signature_input = FramedContentTbs::new(
        WireFormat::PublicMessage,
        GroupId::random(backend),
        1,
        sender,
        vec![1, 2, 3].into(),
        FramedContentBody::Application(vec![4, 5, 6].into()),
    )
    .with_context(serialized_context.clone());
    let mut orig: PublicMessage = signature_input
        .sign(&signature_keys)
        .expect("Signing failed.")
        .into();

    let membership_key = MembershipKey::from_secret(
        Secret::random(ciphersuite, backend, None /* MLS version */)
            .expect("Not enough randomness."),
    );
    orig.set_membership_tag(backend, &membership_key, &serialized_context)
        .expect("Error setting membership tag.");

    let enc = orig
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let copy =
        PublicMessage::tls_deserialize(&mut enc.as_slice()).expect("An unexpected error occurred.");
    assert_eq!(orig, copy);
    assert!(!orig.is_handshake_message());
}

/// This tests serializing/deserializing PrivateMessage
#[apply(ciphersuites_and_backends)]
fn codec_ciphertext(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (_credential, signature_keys) = test_utils::new_credential(
        backend,
        b"Creator",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let sender = Sender::build_member(LeafNodeIndex::new(0));
    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::from_slice(&[5, 5, 5]),
        1,
        vec![],
        vec![],
        Extensions::empty(),
    );

    let serialized_context = group_context
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let signature_input = FramedContentTbs::new(
        WireFormat::PrivateMessage,
        GroupId::random(backend),
        1,
        sender,
        vec![1, 2, 3].into(),
        FramedContentBody::Application(vec![4, 5, 6].into()),
    )
    .with_context(serialized_context);
    let plaintext = signature_input
        .sign(&signature_keys)
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

    let mut message_secrets = MessageSecrets::random(ciphersuite, backend, LeafNodeIndex::new(0));

    let orig = PrivateMessage::encrypt_with_different_header(
        &plaintext,
        ciphersuite,
        backend,
        MlsMessageHeader {
            group_id: group_context.group_id().clone(),
            epoch: group_context.epoch(),
            sender: LeafNodeIndex::new(987543210),
        },
        &mut message_secrets,
        0,
    )
    .expect("Could not encrypt PublicMessage.");

    let enc = orig
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let copy = PrivateMessage::tls_deserialize(&mut enc.as_slice())
        .expect("An unexpected error occurred.");

    assert_eq!(orig, copy);
    assert!(!orig.is_handshake_message());
}

/// This tests the correctness of wire format checks
#[apply(ciphersuites_and_backends)]
fn wire_format_checks(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let configuration = &SenderRatchetConfiguration::default();
    let (plaintext, _credential, _keys) =
        create_content(ciphersuite, WireFormat::PrivateMessage, backend);

    let mut message_secrets = MessageSecrets::random(ciphersuite, backend, LeafNodeIndex::new(0));
    let encryption_secret_bytes = backend
        .rand()
        .random_vec(ciphersuite.hash_length())
        .expect("An unexpected error occurred.");
    let sender_encryption_secret = EncryptionSecret::from_slice(
        &encryption_secret_bytes[..],
        ProtocolVersion::default(),
        ciphersuite,
    );
    let receiver_encryption_secret = EncryptionSecret::from_slice(
        &encryption_secret_bytes[..],
        ProtocolVersion::default(),
        ciphersuite,
    );
    let sender_secret_tree = SecretTree::new(
        sender_encryption_secret,
        2u32,
        LeafNodeIndex::new(0u32).into(),
    );
    let receiver_secret_tree = SecretTree::new(
        receiver_encryption_secret,
        2u32,
        LeafNodeIndex::new(1u32).into(),
    );

    message_secrets.replace_secret_tree(sender_secret_tree);

    let sender_index = LeafNodeIndex::new(0);
    let ciphertext = PrivateMessage::encrypt_with_different_header(
        &plaintext,
        ciphersuite,
        backend,
        MlsMessageHeader {
            group_id: plaintext.group_id().clone(),
            epoch: plaintext.epoch(),
            sender: sender_index,
        },
        &mut message_secrets,
        0,
    )
    .expect("Could not encrypt PublicMessage.");

    // Decrypt the ciphertext and expect the correct wire format

    let sender_secret_tree = message_secrets.replace_secret_tree(receiver_secret_tree);

    let sender_data = ciphertext
        .sender_data(&message_secrets, backend, ciphersuite)
        .expect("Could not decrypt sender data.");
    let verifiable_plaintext = ciphertext
        .to_verifiable_content(
            ciphersuite,
            backend,
            &mut message_secrets,
            sender_index.into(),
            configuration,
            sender_data,
        )
        .expect("Could not decrypt PrivateMessage.");

    assert_eq!(
        verifiable_plaintext.wire_format(),
        WireFormat::PrivateMessage
    );

    // Create and encrypt content with the wrong wire format
    let (plaintext, _credential, signature_keys) =
        create_content(ciphersuite, WireFormat::PublicMessage, backend);
    let pk = OpenMlsSignaturePublicKey::new(
        signature_keys.public().into(),
        ciphersuite.signature_algorithm(),
    )
    .unwrap();

    let receiver_secret_tree = message_secrets.replace_secret_tree(sender_secret_tree);
    // Bypass wire format check during encryption
    let ciphertext = PrivateMessage::encrypt_without_check(
        &plaintext,
        ciphersuite,
        backend,
        &mut message_secrets,
        0,
    )
    .expect("Could not encrypt PublicMessage.");

    // Try to process a ciphertext with the wrong wire format
    let sender_secret_tree = message_secrets.replace_secret_tree(receiver_secret_tree);

    let sender_data = ciphertext
        .sender_data(&message_secrets, backend, ciphersuite)
        .expect("Could not decrypt sender data.");
    let verifiable_plaintext = ciphertext
        .to_verifiable_content(
            ciphersuite,
            backend,
            &mut message_secrets,
            sender_index.into(),
            configuration,
            sender_data,
        )
        .expect("Could not decrypt PrivateMessage.");

    // We expect the signature to fail since the original content was signed with a different wire format.
    let result: Result<AuthenticatedContent, SignatureError> =
        verifiable_plaintext.verify(backend.crypto(), &pk);

    assert_eq!(
        result.expect_err("Verification successful despite wrong wire format."),
        SignatureError::VerificationError
    );

    message_secrets.replace_secret_tree(sender_secret_tree);

    // Try to encrypt an PublicMessage with the wrong wire format
    assert_eq!(
        PrivateMessage::try_from_authenticated_content(
            &plaintext,
            ciphersuite,
            backend,
            &mut message_secrets,
            0,
        )
        .expect_err("Could encrypt despite wrong wire format."),
        MessageEncryptionError::WrongWireFormat
    );
}

fn create_content(
    ciphersuite: Ciphersuite,
    wire_format: WireFormat,
    backend: &impl OpenMlsCryptoProvider,
) -> (AuthenticatedContent, CredentialWithKey, SignatureKeyPair) {
    let (credential, signature_keys) = test_utils::new_credential(
        backend,
        b"Creator",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let sender = Sender::build_member(LeafNodeIndex::new(0));
    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::from_slice(&[5, 5, 5]),
        1,
        vec![],
        vec![],
        Extensions::empty(),
    );
    let serialized_context = group_context
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let signature_input = FramedContentTbs::new(
        wire_format,
        GroupId::random(backend),
        1,
        sender,
        vec![1, 2, 3].into(),
        FramedContentBody::Application(vec![4, 5, 6].into()),
    )
    .with_context(serialized_context);

    let content = signature_input
        .sign(&signature_keys)
        .expect("Signing failed.");
    (content, credential, signature_keys)
}

#[apply(ciphersuites_and_backends)]
fn membership_tag(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (_credential, signature_keys) = test_utils::new_credential(
        backend,
        b"Creator",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::random(backend),
        1,
        vec![],
        vec![],
        Extensions::empty(),
    );
    let membership_key = MembershipKey::from_secret(
        Secret::random(ciphersuite, backend, None /* MLS version */)
            .expect("Not enough randomness."),
    );
    let mut public_message: PublicMessage = AuthenticatedContent::new_application(
        LeafNodeIndex::new(987543210),
        &[1, 2, 3],
        &[4, 5, 6],
        &group_context,
        &signature_keys,
    )
    .expect("An unexpected error occurred.")
    .into();

    let serialized_context = group_context.tls_serialize_detached().unwrap();
    public_message
        .set_membership_tag(backend, &membership_key, &serialized_context)
        .expect("Error setting membership tag.");

    println!(
        "Membership tag error: {:?}",
        public_message.verify_membership(backend, &membership_key, &serialized_context)
    );

    // Verify signature & membership tag
    assert!(public_message
        .verify_membership(backend, &membership_key, &serialized_context)
        .is_ok());

    // Change the content of the plaintext message
    public_message.set_content(FramedContentBody::Application(vec![7, 8, 9].into()));

    // Expect the signature & membership tag verification to fail
    assert!(public_message
        .verify_membership(backend, &membership_key, &serialized_context)
        .is_err());
}

#[apply(ciphersuites_and_backends)]
fn unknown_sender(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);
    let configuration = &SenderRatchetConfiguration::default();

    // Define credential bundles
    let (alice_credential, alice_signature_keys) = test_utils::new_credential(
        backend,
        b"Alice",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let (bob_credential, bob_signature_keys) = test_utils::new_credential(
        backend,
        b"Bob",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let (charlie_credential, charlie_signature_keys) = test_utils::new_credential(
        backend,
        b"Charlie",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );

    // Generate KeyPackages
    let bob_key_package_bundle =
        KeyPackageBundle::new(backend, &bob_signature_keys, ciphersuite, bob_credential);
    let bob_key_package = bob_key_package_bundle.key_package();

    let charlie_key_package_bundle = KeyPackageBundle::new(
        backend,
        &charlie_signature_keys,
        ciphersuite,
        charlie_credential,
    );
    let charlie_key_package = charlie_key_package_bundle.key_package();

    // Alice creates a group
    let mut group_alice = CoreGroup::builder(
        GroupId::random(backend),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential,
    )
    .build(backend, &alice_signature_keys)
    .expect("Error creating group.");

    // Alice adds Bob
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            bob_key_package.clone(),
            &alice_signature_keys,
        )
        .expect("Could not create proposal.");

    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = group_alice
        .create_commit(params, backend, &alice_signature_keys)
        .expect("Error creating Commit");

    group_alice
        .merge_commit(backend, create_commit_result.staged_commit)
        .expect("error merging pending commit");

    let _group_bob = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(group_alice.treesync().export_nodes()),
        bob_key_package_bundle,
        backend,
    )
    .expect("Bob: Error creating group from Welcome");

    // Alice adds Charlie

    let charlie_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            charlie_key_package.clone(),
            &alice_signature_keys,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_authenticated_content(ciphersuite, backend, charlie_add_proposal)
            .expect("Could not create staged proposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = group_alice
        .create_commit(params, backend, &alice_signature_keys)
        .expect("Error creating Commit");

    group_alice
        .merge_commit(backend, create_commit_result.staged_commit)
        .expect("error merging pending commit");

    let mut group_charlie = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(group_alice.treesync().export_nodes()),
        charlie_key_package_bundle,
        backend,
    )
    .expect("Charlie: Error creating group from Welcome");

    // Alice removes Bob
    let bob_remove_proposal = group_alice
        .create_remove_proposal(
            framing_parameters,
            LeafNodeIndex::new(1),
            &alice_signature_keys,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_authenticated_content(ciphersuite, backend, bob_remove_proposal)
            .expect("Could not create staged proposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = group_alice
        .create_commit(params, backend, &alice_signature_keys)
        .expect("Error creating Commit");

    let staged_commit = group_charlie
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("Charlie: Could not stage Commit");
    group_charlie
        .merge_commit(backend, staged_commit)
        .expect("error merging commit");

    group_alice
        .merge_commit(backend, create_commit_result.staged_commit)
        .expect("error merging pending commit");

    print_tree(&group_alice, "Alice tree");
    print_tree(&group_charlie, "Charlie tree");

    // Alice sends a message with a sender that is outside of the group
    // Expected result: SenderError::UnknownSender
    let bogus_sender_message = AuthenticatedContent::new_application(
        LeafNodeIndex::new(0),
        &[],
        &[1, 2, 3],
        group_alice.context(),
        &alice_signature_keys,
    )
    .expect("Could not create new PublicMessage.");

    let enc_message = PrivateMessage::encrypt_with_different_header(
        &bogus_sender_message,
        ciphersuite,
        backend,
        MlsMessageHeader {
            group_id: group_alice.group_id().clone(),
            epoch: group_alice.context().epoch(),
            sender: LeafNodeIndex::new(987543210u32),
        },
        group_alice.message_secrets_test_mut(),
        0,
    )
    .expect("Encryption error");

    let received_message = group_charlie.decrypt(&enc_message, backend, configuration);
    assert_eq!(
        received_message.unwrap_err(),
        MessageDecryptionError::SenderError(SenderError::UnknownSender)
    );
}

#[apply(ciphersuites_and_backends)]
fn confirmation_tag_presence(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (framing_parameters, group_alice, alice_signature_keys, group_bob, _, _) =
        setup_alice_bob_group(ciphersuite, backend);

    // Alice does an update
    let proposal_store = ProposalStore::default();

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(true)
        .build();
    let mut create_commit_result = group_alice
        .create_commit(params, backend, &alice_signature_keys)
        .expect("Error creating Commit");

    create_commit_result.commit.unset_confirmation_tag();

    let err = group_bob
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect_err("No error despite missing confirmation tag.");

    assert_eq!(err, StageCommitError::ConfirmationTagMissing);
}

pub(crate) fn setup_alice_bob_group(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (
    FramingParameters,
    CoreGroup,
    SignatureKeyPair,
    CoreGroup,
    SignatureKeyPair,
    CredentialWithKey,
) {
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    // Create credentials and keys
    let (alice_credential, alice_signature_keys) = test_utils::new_credential(
        backend,
        b"Alice",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let (bob_credential, bob_signature_keys) = test_utils::new_credential(
        backend,
        b"Bob",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        backend,
        &bob_signature_keys,
        ciphersuite,
        bob_credential.clone(),
    );
    let bob_key_package = bob_key_package_bundle.key_package();

    // Alice creates a group
    let mut group_alice = CoreGroup::builder(
        GroupId::random(backend),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential,
    )
    .build(backend, &alice_signature_keys)
    .expect("Error creating group.");

    // Alice adds Bob
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            bob_key_package.clone(),
            &alice_signature_keys,
        )
        .expect("Could not create proposal.");

    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();

    let create_commit_result = group_alice
        .create_commit(params, backend, &alice_signature_keys)
        .expect("Error creating Commit");

    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(!commit.has_path());
    // Check that the function returned a Welcome message
    assert!(create_commit_result.welcome_option.is_some());

    group_alice
        .merge_commit(backend, create_commit_result.staged_commit)
        .expect("error merging pending commit");

    // We have to create Bob's group so he can process the commit with the
    // broken confirmation tag, because Alice can't process her own commit.
    let group_bob = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("commit didn't return a welcome as expected"),
        Some(group_alice.treesync().export_nodes()),
        bob_key_package_bundle,
        backend,
    )
    .expect("error creating group from welcome");

    (
        framing_parameters,
        group_alice,
        alice_signature_keys,
        group_bob,
        bob_signature_keys,
        bob_credential,
    )
}
