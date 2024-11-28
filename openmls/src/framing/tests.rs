use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::prelude::*;
use openmls_traits::types::Ciphersuite;

use mls_group::tests_and_kats::utils::{setup_alice_bob_group, setup_client};
use signable::Verifiable;
use tls_codec::{Deserialize, Serialize};

use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    ciphersuite::signable::{Signable, SignatureError},
    extensions::Extensions,
    framing::*,
    group::errors::*,
    key_packages::tests::key_package,
    prelude::LeafNodeParameters,
    schedule::psk::PskSecret,
    storage::OpenMlsProvider,
    test_utils::frankenstein::*,
    tree::{secret_tree::SecretTree, sender_ratchet::SenderRatchetConfiguration},
};

/// This tests serializing/deserializing PublicMessage
#[openmls_test::openmls_test]
fn codec_plaintext() {
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
#[openmls_test::openmls_test]
fn codec_ciphertext() {
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

    let orig = PrivateMessage::encrypt_with_different_header::<StorageError>(
        provider.crypto(),
        provider.rand(),
        &plaintext,
        ciphersuite,
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
#[openmls_test::openmls_test]
fn wire_format_checks() {
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
    let ciphertext: PrivateMessageIn =
        PrivateMessage::encrypt_with_different_header::<StorageError>(
            provider.crypto(),
            provider.rand(),
            &plaintext,
            ciphersuite,
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
    let ciphertext: PrivateMessageIn = PrivateMessage::encrypt_without_check::<StorageError>(
        provider.crypto(),
        provider.rand(),
        &plaintext,
        ciphersuite,
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
    assert!(matches!(
        PrivateMessage::try_from_authenticated_content::<StorageError>(
            provider.crypto(),
            provider.rand(),
            &plaintext,
            ciphersuite,
            &mut message_secrets,
            0,
        )
        .expect_err("Could encrypt despite wrong wire format."),
        MessageEncryptionError::WrongWireFormat
    ));
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

#[openmls_test::openmls_test]
fn membership_tag() {
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

#[openmls_test::openmls_test]
fn unknown_sender<Provider: OpenMlsProvider>(ciphersuite: Ciphersuite, provider: &Provider) {
    let _ = pretty_env_logger::try_init();

    // Define credentials with keys
    let (
        _charlie_credential,
        charlie_key_package_bundle,
        _charlie_signature_keys,
        _charlie_public_signature_key,
    ) = setup_client("Charlie", ciphersuite, provider);

    let (mut alice_group, alice_signature_keys, _bob_group, _bob_signature_keys, _bob_credential) =
        setup_alice_bob_group(ciphersuite, provider);

    // Alice adds Charlie
    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[charlie_key_package_bundle.key_package().clone()],
        )
        .expect("Could not add members.");

    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit.");

    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    let mut charlie_group = StagedWelcome::new_from_welcome(
        provider,
        &config,
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Could not create group from Welcome")
    .into_group(provider)
    .expect("Could not create group from Welcome");

    // Alice removes Bob
    let (commit, _welcome_option, _group_info_option) = alice_group
        .remove_members(provider, &alice_signature_keys, &[LeafNodeIndex::new(1)])
        .expect("Could not remove members.");

    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit.");

    let processed_message = charlie_group
        .process_message(provider, commit.into_protocol_message().unwrap())
        .expect("Could not process message.");

    let staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => *staged_commit,
        _ => panic!("Wrong message type."),
    };

    charlie_group
        .merge_staged_commit(provider, staged_commit)
        .expect("Could not merge commit.");

    // Alice sends a message with a sender that is outside of the group
    // Expected result: SenderError::UnknownSender
    let bogus_sender_message = AuthenticatedContent::new_application(
        LeafNodeIndex::new(0),
        &[],
        &[1, 2, 3],
        alice_group.export_group_context(),
        &alice_signature_keys,
    )
    .expect("Could not create new ApplicationMessage.");

    let enc_message = PrivateMessage::encrypt_with_different_header::<StorageError>(
        provider.crypto(),
        provider.rand(),
        &bogus_sender_message,
        ciphersuite,
        MlsMessageHeader {
            group_id: alice_group.group_id().clone(),
            epoch: alice_group.epoch(),
            sender: LeafNodeIndex::new(987543210u32),
        },
        alice_group.message_secrets_test_mut(),
        0,
    )
    .expect("Encryption error");

    let received_message = charlie_group.process_message(
        provider,
        ProtocolMessage::from(PrivateMessageIn::from(enc_message)),
    );

    assert_eq!(
        received_message.unwrap_err(),
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::SecretTreeError(SecretTreeError::IndexOutOfBounds)
        ))
    );
}

#[openmls_test::openmls_test]
fn confirmation_tag_presence<Provider: OpenMlsProvider>() {
    let (
        mut alice_group,
        alice_signature_keys,
        mut bob_group,
        _bob_signature_keys,
        _bob_credential,
    ) = setup_alice_bob_group(ciphersuite, provider);

    // Alice does an update
    let (commit, _welcome_option, _group_info_option) = alice_group
        .self_update(
            provider,
            &alice_signature_keys,
            LeafNodeParameters::default(),
        )
        .expect("Could not update group.")
        .into_contents();

    let commit = match commit.body {
        MlsMessageBodyOut::PublicMessage(pm) => pm,
        _ => panic!("Wrong message type."),
    };

    let mut franken_pm = FrankenPublicMessage::from(commit);

    franken_pm.auth.confirmation_tag = None;

    let serialized_pm = franken_pm
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let pm = match PublicMessageIn::tls_deserialize(&mut serialized_pm.as_slice()) {
        Ok(pm) => pm,
        Err(err) => {
            assert!(matches!(err, tls_codec::Error::InvalidVectorLength));
            return;
        }
    };

    // Just in case the decoding succeeds, we need to make sure that the
    // missing confirmation tag is detected when processing the message.

    let protocol_message: ProtocolMessage = pm.into();

    let err = bob_group
        .process_message(provider, protocol_message)
        .expect_err("Could not process message.");

    assert_eq!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ConfirmationTagMissing)
    );
}

/// Test divergent protocol versions in KeyPackages
#[openmls_test::openmls_test]
fn key_package_version() {
    let (key_package, _, _) = key_package(ciphersuite, provider);

    let mut franken_key_package = FrankenKeyPackage::from(key_package);

    // Set an invalid protocol version
    franken_key_package.payload.protocol_version = 999;

    let message = FrankenMlsMessage {
        version: 1,
        body: FrankenMlsMessageBody::KeyPackage(franken_key_package),
    };

    let encoded = message
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    let err = MlsMessageIn::tls_deserialize(&mut encoded.as_slice())
        .expect_err("Deserialization should have failed.");

    // Expect a decoding  error
    matches!(err, tls_codec::Error::DecodingError(_));
}
