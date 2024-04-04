use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{random::OpenMlsRand, types::Ciphersuite, OpenMlsProvider};

use rstest::*;
use rstest_reuse::{self, *};

use openmls_rust_crypto::OpenMlsRustCrypto;
use signable::Verifiable;
use tls_codec::{Deserialize, Serialize};

use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    ciphersuite::signable::{Signable, SignatureError},
    extensions::Extensions,
    framing::*,
    group::{
        core_group::proposals::{ProposalStore, QueuedProposal},
        errors::*,
        CreateCommitParams,
    },
    key_packages::{test_key_packages::key_package, KeyPackageBundle},
    schedule::psk::{store::ResumptionPskStore, PskSecret},
    tree::{secret_tree::SecretTree, sender_ratchet::SenderRatchetConfiguration},
    versions::ProtocolVersion,
};

/// This tests serializing/deserializing PublicMessage
#[apply(ciphersuites_and_providers)]
fn codec_plaintext(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let (_credential, signature_keys) =
        test_utils::new_credential(provider, b"Creator", ciphersuite.signature_algorithm());
    let sender = Sender::build_member(LeafNodeIndex::new(987543210));
    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::random(provider.rand()),
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
        GroupId::random(provider.rand()),
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
        Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness."),
    );
    orig.set_membership_tag(
        provider.crypto(),
        ciphersuite,
        &membership_key,
        &serialized_context,
    )
    .expect("Error setting membership tag.");

    let enc = orig
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let copy = PublicMessageIn::tls_deserialize(&mut enc.as_slice())
        .expect("An unexpected error occurred.");
    assert_eq!(orig, copy.into());
    assert!(!orig.is_handshake_message());
}

/// This tests serializing/deserializing PrivateMessage
#[apply(ciphersuites_and_providers)]
fn codec_ciphertext(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let (_credential, signature_keys) =
        test_utils::new_credential(provider, b"Creator", ciphersuite.signature_algorithm());
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
        GroupId::random(provider.rand()),
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
        provider.crypto(),
        &JoinerSecret::random(ciphersuite, provider.rand()),
        PskSecret::from(Secret::zero(ciphersuite)),
    )
    .expect("Could not create KeySchedule.");

    let serialized_group_context = group_context
        .tls_serialize_detached()
        .expect("Could not serialize group context.");

    key_schedule
        .add_context(provider.crypto(), &serialized_group_context)
        .expect("Could not add context to key schedule");

    let mut message_secrets =
        MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0));

    let orig = PrivateMessage::encrypt_with_different_header(
        &plaintext,
        ciphersuite,
        provider,
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
    let copy = PrivateMessageIn::tls_deserialize(&mut enc.as_slice())
        .expect("An unexpected error occurred.");

    assert_eq!(orig, copy.into());
    assert!(!orig.is_handshake_message());
}

/// This tests the correctness of wire format checks
#[apply(ciphersuites_and_providers)]
fn wire_format_checks(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let configuration = &SenderRatchetConfiguration::default();
    let (plaintext, _credential, _keys) =
        create_content(ciphersuite, WireFormat::PrivateMessage, provider);

    let mut message_secrets =
        MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0));
    let encryption_secret_bytes = provider
        .rand()
        .random_vec(ciphersuite.hash_length())
        .expect("An unexpected error occurred.");
    let sender_encryption_secret = EncryptionSecret::from_slice(&encryption_secret_bytes[..]);
    let receiver_encryption_secret = EncryptionSecret::from_slice(&encryption_secret_bytes[..]);
    let sender_secret_tree = SecretTree::new(
        sender_encryption_secret,
        TreeSize::new(2u32),
        LeafNodeIndex::new(0u32),
    );
    let receiver_secret_tree = SecretTree::new(
        receiver_encryption_secret,
        TreeSize::new(2u32),
        LeafNodeIndex::new(1u32),
    );

    message_secrets.replace_secret_tree(sender_secret_tree);

    let sender_index = LeafNodeIndex::new(0);
    let ciphertext: PrivateMessageIn = PrivateMessage::encrypt_with_different_header(
        &plaintext,
        ciphersuite,
        provider,
        MlsMessageHeader {
            group_id: plaintext.group_id().clone(),
            epoch: plaintext.epoch(),
            sender: sender_index,
        },
        &mut message_secrets,
        0,
    )
    .expect("Could not encrypt PublicMessage.")
    .into();

    // Decrypt the ciphertext and expect the correct wire format

    let sender_secret_tree = message_secrets.replace_secret_tree(receiver_secret_tree);

    let sender_data = ciphertext
        .sender_data(&message_secrets, provider.crypto(), ciphersuite)
        .expect("Could not decrypt sender data.");
    let verifiable_plaintext = ciphertext
        .to_verifiable_content(
            ciphersuite,
            provider.crypto(),
            &mut message_secrets,
            sender_index,
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
        create_content(ciphersuite, WireFormat::PublicMessage, provider);
    let pk = OpenMlsSignaturePublicKey::new(
        signature_keys.public().into(),
        ciphersuite.signature_algorithm(),
    )
    .unwrap();

    let receiver_secret_tree = message_secrets.replace_secret_tree(sender_secret_tree);
    // Bypass wire format check during encryption
    let ciphertext: PrivateMessageIn = PrivateMessage::encrypt_without_check(
        &plaintext,
        ciphersuite,
        provider,
        &mut message_secrets,
        0,
    )
    .expect("Could not encrypt PublicMessage.")
    .into();

    // Try to process a ciphertext with the wrong wire format
    let sender_secret_tree = message_secrets.replace_secret_tree(receiver_secret_tree);

    let sender_data = ciphertext
        .sender_data(&message_secrets, provider.crypto(), ciphersuite)
        .expect("Could not decrypt sender data.");
    let verifiable_plaintext = ciphertext
        .to_verifiable_content(
            ciphersuite,
            provider.crypto(),
            &mut message_secrets,
            sender_index,
            configuration,
            sender_data,
        )
        .expect("Could not decrypt PrivateMessage.");

    // We expect the signature to fail since the original content was signed with a different wire format.
    let result: Result<AuthenticatedContentIn, SignatureError> =
        verifiable_plaintext.verify(provider.crypto(), &pk);

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
            provider,
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
    provider: &impl OpenMlsProvider,
) -> (AuthenticatedContent, CredentialWithKey, SignatureKeyPair) {
    let (credential, signature_keys) =
        test_utils::new_credential(provider, b"Creator", ciphersuite.signature_algorithm());
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
        GroupId::random(provider.rand()),
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

#[apply(ciphersuites_and_providers)]
fn membership_tag(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let (_credential, signature_keys) =
        test_utils::new_credential(provider, b"Creator", ciphersuite.signature_algorithm());
    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::random(provider.rand()),
        1,
        vec![],
        vec![],
        Extensions::empty(),
    );
    let membership_key = MembershipKey::from_secret(
        Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness."),
    );
    let public_message: PublicMessage = AuthenticatedContent::new_application(
        LeafNodeIndex::new(987543210),
        &[1, 2, 3],
        &[4, 5, 6],
        &group_context,
        &signature_keys,
    )
    .expect("An unexpected error occurred.")
    .into();

    let mut public_message = PublicMessageIn::from(public_message);

    let serialized_context = group_context.tls_serialize_detached().unwrap();
    public_message
        .set_membership_tag(provider, ciphersuite, &membership_key, &serialized_context)
        .expect("Error setting membership tag.");

    println!(
        "Membership tag error: {:?}",
        public_message.verify_membership(
            provider.crypto(),
            ciphersuite,
            &membership_key,
            &serialized_context
        )
    );

    // Verify signature & membership tag
    assert!(public_message
        .verify_membership(
            provider.crypto(),
            ciphersuite,
            &membership_key,
            &serialized_context
        )
        .is_ok());

    // Change the content of the plaintext message
    public_message.set_content(FramedContentBodyIn::Application(vec![7, 8, 9].into()));

    // Expect the signature & membership tag verification to fail
    assert!(public_message
        .verify_membership(
            provider.crypto(),
            ciphersuite,
            &membership_key,
            &serialized_context
        )
        .is_err());
}

#[apply(ciphersuites_and_providers)]
fn unknown_sender(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);
    let configuration = &SenderRatchetConfiguration::default();

    // Define credentials with keys
    let (alice_credential, alice_signature_keys) =
        test_utils::new_credential(provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signature_keys) =
        test_utils::new_credential(provider, b"Bob", ciphersuite.signature_algorithm());
    let (charlie_credential, charlie_signature_keys) =
        test_utils::new_credential(provider, b"Charlie", ciphersuite.signature_algorithm());

    // Generate KeyPackages
    let bob_key_package_bundle =
        KeyPackageBundle::new(provider, &bob_signature_keys, ciphersuite, bob_credential);
    let bob_key_package = bob_key_package_bundle.key_package();

    let charlie_key_package_bundle = KeyPackageBundle::new(
        provider,
        &charlie_signature_keys,
        ciphersuite,
        charlie_credential,
    );
    let charlie_key_package = charlie_key_package_bundle.key_package();

    // Alice creates a group
    let mut group_alice = CoreGroup::builder(
        GroupId::random(provider.rand()),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential,
    )
    .build(provider, &alice_signature_keys)
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
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = group_alice
        .create_commit(params, provider, &alice_signature_keys)
        .expect("Error creating Commit");

    group_alice
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging pending commit");

    let _group_bob = StagedCoreWelcome::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(group_alice.public_group().export_ratchet_tree().into()),
        bob_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
    )
    .and_then(|staged_join| staged_join.into_core_group(provider))
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
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            charlie_add_proposal,
        )
        .expect("Could not create staged proposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = group_alice
        .create_commit(params, provider, &alice_signature_keys)
        .expect("Error creating Commit");

    group_alice
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging pending commit");

    let mut group_charlie = StagedCoreWelcome::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(group_alice.public_group().export_ratchet_tree().into()),
        charlie_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
    )
    .and_then(|staged_join| staged_join.into_core_group(provider))
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
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_remove_proposal,
        )
        .expect("Could not create staged proposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = group_alice
        .create_commit(params, provider, &alice_signature_keys)
        .expect("Error creating Commit");

    let staged_commit = group_charlie
        .read_keys_and_stage_commit(&create_commit_result.commit, &proposal_store, &[], provider)
        .expect("Charlie: Could not stage Commit");
    group_charlie
        .merge_commit(provider, staged_commit)
        .expect("error merging commit");

    group_alice
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging pending commit");

    group_alice.print_ratchet_tree("Alice tree");
    group_charlie.print_ratchet_tree("Charlie tree");

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
        provider,
        MlsMessageHeader {
            group_id: group_alice.group_id().clone(),
            epoch: group_alice.context().epoch(),
            sender: LeafNodeIndex::new(987543210u32),
        },
        group_alice.message_secrets_test_mut(),
        0,
    )
    .expect("Encryption error");

    let received_message = group_charlie.decrypt_message(
        provider.crypto(),
        ProtocolMessage::from(PrivateMessageIn::from(enc_message)),
        configuration,
    );
    assert_eq!(
        received_message.unwrap_err(),
        ValidationError::UnableToDecrypt(MessageDecryptionError::SecretTreeError(
            SecretTreeError::IndexOutOfBounds
        ))
    );
}

#[apply(ciphersuites_and_providers)]
fn confirmation_tag_presence(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let (framing_parameters, group_alice, alice_signature_keys, group_bob, _, _) =
        setup_alice_bob_group(ciphersuite, provider);

    // Alice does an update
    let proposal_store = ProposalStore::default();

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(true)
        .build();
    let mut create_commit_result = group_alice
        .create_commit(params, provider, &alice_signature_keys)
        .expect("Error creating Commit");

    create_commit_result.commit.unset_confirmation_tag();

    let err = group_bob
        .read_keys_and_stage_commit(&create_commit_result.commit, &proposal_store, &[], provider)
        .expect_err("No error despite missing confirmation tag.");

    assert_eq!(err, StageCommitError::ConfirmationTagMissing);
}

pub(crate) fn setup_alice_bob_group(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
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
    let (alice_credential, alice_signature_keys) =
        test_utils::new_credential(provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signature_keys) =
        test_utils::new_credential(provider, b"Bob", ciphersuite.signature_algorithm());

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        provider,
        &bob_signature_keys,
        ciphersuite,
        bob_credential.clone(),
    );
    let bob_key_package = bob_key_package_bundle.key_package();

    // Alice creates a group
    let mut group_alice = CoreGroup::builder(
        GroupId::random(provider.rand()),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential,
    )
    .build(provider, &alice_signature_keys)
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
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();

    let create_commit_result = group_alice
        .create_commit(params, provider, &alice_signature_keys)
        .expect("Error creating Commit");

    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(!commit.has_path());
    // Check that the function returned a Welcome message
    assert!(create_commit_result.welcome_option.is_some());

    group_alice
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging pending commit");

    // We have to create Bob's group so he can process the commit with the
    // broken confirmation tag, because Alice can't process her own commit.
    let group_bob = StagedCoreWelcome::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("commit didn't return a welcome as expected"),
        Some(group_alice.public_group().export_ratchet_tree().into()),
        bob_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
    )
    .and_then(|staged_join| staged_join.into_core_group(provider))
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

/// Test divergent protocol versions in KeyPackages
#[apply(ciphersuites_and_providers)]
fn key_package_version(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let (mut key_package, _, _) = key_package(ciphersuite, provider);

    // Set an invalid protocol version
    key_package.set_version(ProtocolVersion::Mls10Draft11);

    let message = MlsMessageOut {
        version: ProtocolVersion::Mls10,
        body: MlsMessageBodyOut::KeyPackage(key_package),
    };

    let encoded = message
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    let err = MlsMessageIn::tls_deserialize(&mut encoded.as_slice())
        .expect_err("Deserialization should have failed.");

    // Expect a decoding  error
    matches!(err, tls_codec::Error::DecodingError(_));
}
