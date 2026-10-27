use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::random::OpenMlsRand;
use tls_codec::Serialize;

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::ReuseGuard,
    framing::{
        mls_auth_content::AuthenticatedContent, private_message_in::PrivateMessageIn,
        MlsSenderData, MlsSenderDataAad, PrivateContentAad,
    },
    group::past_secrets::MessageSecretsStore,
    group::{
        mls_group::tests_and_kats::utils::setup_client, MlsGroup, ProcessMessageError,
        StageCommitError, StagedWelcome, ValidationError,
    },
    messages::proposals::{Proposal, RemoveProposal},
    prelude::*,
    test_utils::*,
    tree::{secret_tree::SecretType, sender_ratchet::SenderRatchetConfiguration},
};

const FORGED_GENERATION: u32 = 900;

struct Members<Provider> {
    alice_provider: Provider,
    alice_signer: SignatureKeyPair,
    alice_group: MlsGroup,
    bob_provider: Provider,
    bob_signer: SignatureKeyPair,
    bob_group: MlsGroup,
}

fn setup<Provider: OpenMlsProvider + Default>(ciphersuite: Ciphersuite) -> Members<Provider> {
    let alice_provider = Provider::default();
    let bob_provider = Provider::default();
    let (alice_credential, _, alice_signer, _) =
        setup_client("Alice", ciphersuite, &alice_provider);
    let (_, bob_key_package_bundle, bob_signer, _) =
        setup_client("Bob", ciphersuite, &bob_provider);

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build(&alice_provider, &alice_signer, alice_credential)
        .unwrap();
    let (_, welcome, _) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            &[bob_key_package_bundle.key_package().clone()],
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        &MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build(),
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .and_then(|staged_welcome| staged_welcome.into_group(&bob_provider))
    .unwrap();

    Members {
        alice_provider,
        alice_signer,
        alice_group,
        bob_provider,
        bob_signer,
        bob_group,
    }
}

enum ForgedPlaintext<'a> {
    Garbage,
    Content(&'a AuthenticatedContent),
}

/// Builds a PrivateMessage that names `sender` and `generation` in its sender
/// data, using only the secrets the `receiver` holds for the current epoch.
fn forge_private_message(
    receiver: &MlsGroup,
    provider: &impl OpenMlsProvider,
    content_type: ContentType,
    sender: LeafNodeIndex,
    generation: u32,
    plaintext: ForgedPlaintext<'_>,
) -> ProtocolMessage {
    let ciphersuite = receiver.ciphersuite();
    let crypto = provider.crypto();
    let group_id = receiver.group_id().clone();
    let epoch = receiver.epoch();
    let mut message_secrets = receiver.message_secrets().clone();
    let reuse_guard = ReuseGuard::try_from_random(provider.rand()).unwrap();

    let ciphertext = match plaintext {
        ForgedPlaintext::Garbage => provider.rand().random_vec(64).unwrap(),
        ForgedPlaintext::Content(content) => {
            let (ratchet_key, ratchet_nonce) = message_secrets
                .secret_tree_mut()
                .secret_for_decryption(
                    ciphersuite,
                    crypto,
                    sender,
                    SecretType::from(&content_type),
                    generation,
                    &SenderRatchetConfiguration::default(),
                )
                .unwrap()
                .available()
                .unwrap();
            let mut serialized_content = Vec::new();
            content
                .content()
                .serialize_without_type(&mut serialized_content)
                .unwrap();
            content
                .test_signature()
                .tls_serialize(&mut serialized_content)
                .unwrap();
            let aad = PrivateContentAad {
                group_id: group_id.clone(),
                epoch,
                content_type,
                authenticated_data: VLByteSlice(content.authenticated_data()),
            }
            .tls_serialize_detached()
            .unwrap();
            ratchet_key
                .aead_seal(
                    crypto,
                    &serialized_content,
                    &aad,
                    &ratchet_nonce.xor_with_reuse_guard(&reuse_guard),
                )
                .unwrap()
        }
    };

    let sender_data_key = message_secrets
        .sender_data_secret()
        .derive_aead_key(crypto, ciphersuite, &ciphertext)
        .unwrap();
    let sender_data_nonce = message_secrets
        .sender_data_secret()
        .derive_aead_nonce(ciphersuite, crypto, &ciphertext)
        .unwrap();
    let sender_data_aad = MlsSenderDataAad::test_new(group_id.clone(), epoch, content_type)
        .tls_serialize_detached()
        .unwrap();
    let encrypted_sender_data = sender_data_key
        .aead_seal(
            crypto,
            &MlsSenderData::from_sender(sender, generation, reuse_guard)
                .tls_serialize_detached()
                .unwrap(),
            &sender_data_aad,
            &sender_data_nonce,
        )
        .unwrap();

    PrivateMessageIn::from(PrivateMessage::new(
        group_id,
        epoch,
        content_type,
        Vec::new().into(),
        encrypted_sender_data.into(),
        ciphertext.into(),
    ))
    .into()
}

fn forged_application_content(
    group: &MlsGroup,
    sender: LeafNodeIndex,
    signer: &SignatureKeyPair,
) -> AuthenticatedContent {
    AuthenticatedContent::new_application(sender, &[], b"forged", group.context(), signer).unwrap()
}

fn forged_proposal_content(
    group: &MlsGroup,
    sender: LeafNodeIndex,
    signer: &SignatureKeyPair,
) -> AuthenticatedContent {
    AuthenticatedContent::member_proposal(
        FramingParameters::new(&[], WireFormat::PrivateMessage),
        sender,
        Proposal::remove(RemoveProposal {
            removed: group.own_leaf_index(),
        }),
        group.context(),
        signer,
    )
    .unwrap()
}

fn with_tampered_authenticated_data(message: &ProtocolMessage) -> ProtocolMessage {
    let ProtocolMessage::PrivateMessage(private_message) = message.clone() else {
        panic!("expected a PrivateMessage");
    };
    let mut tampered = PrivateMessage::from(private_message);
    tampered.authenticated_data = b"tampered".to_vec().into();
    PrivateMessageIn::from(tampered).into()
}

fn create_application_message(
    group: &mut MlsGroup,
    provider: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    payload: &[u8],
) -> ProtocolMessage {
    group
        .create_message(provider, signer, payload)
        .unwrap()
        .into_protocol_message()
        .unwrap()
}

fn assert_aead_error<StorageError>(error: ProcessMessageError<StorageError>) {
    assert!(matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::AeadError
        ))
    ));
}

fn stored_message_secrets(
    provider: &impl OpenMlsProvider,
    group: &MlsGroup,
) -> MessageSecretsStore {
    provider
        .storage()
        .message_secrets(group.group_id())
        .unwrap()
        .unwrap()
}

fn assert_application_message(processed: ProcessedMessage, expected: &[u8]) {
    let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
        panic!("expected an application message");
    };
    assert_eq!(message.into_bytes(), expected);
}

#[openmls_test::openmls_test]
fn tampered_message_does_not_consume_generation() {
    let Members {
        alice_provider,
        alice_signer,
        mut alice_group,
        bob_provider,
        mut bob_group,
        ..
    } = setup::<Provider>(ciphersuite);

    let message =
        create_application_message(&mut alice_group, &alice_provider, &alice_signer, b"m0");

    let error = bob_group
        .process_message(&bob_provider, with_tampered_authenticated_data(&message))
        .unwrap_err();
    assert_aead_error(error);

    let processed = bob_group.process_message(&bob_provider, message).unwrap();
    assert_application_message(processed, b"m0");
}

#[openmls_test::openmls_test]
fn undecryptable_content_does_not_advance_ratchet() {
    let Members {
        alice_provider,
        alice_signer,
        mut alice_group,
        bob_provider,
        mut bob_group,
        ..
    } = setup::<Provider>(ciphersuite);

    let forged = forge_private_message(
        &bob_group,
        &bob_provider,
        ContentType::Application,
        alice_group.own_leaf_index(),
        FORGED_GENERATION,
        ForgedPlaintext::Garbage,
    );
    let error = bob_group
        .process_message(&bob_provider, forged)
        .unwrap_err();
    assert!(matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::AeadError
        ))
    ));

    let message = alice_group
        .create_message(&alice_provider, &alice_signer, b"m0")
        .unwrap()
        .into_protocol_message()
        .unwrap();
    let processed = bob_group.process_message(&bob_provider, message).unwrap();
    assert_application_message(processed, b"m0");
}

#[openmls_test::openmls_test]
fn invalid_signature_does_not_advance_ratchet() {
    let Members {
        alice_provider,
        alice_signer,
        mut alice_group,
        bob_provider,
        bob_signer,
        mut bob_group,
    } = setup::<Provider>(ciphersuite);

    let alice_leaf = alice_group.own_leaf_index();
    let content = forged_application_content(&bob_group, alice_leaf, &bob_signer);
    let forged = forge_private_message(
        &bob_group,
        &bob_provider,
        ContentType::Application,
        alice_leaf,
        FORGED_GENERATION,
        ForgedPlaintext::Content(&content),
    );
    let error = bob_group
        .process_message(&bob_provider, forged)
        .unwrap_err();
    assert!(matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::InvalidSignature)
    ));

    let message = alice_group
        .create_message(&alice_provider, &alice_signer, b"m0")
        .unwrap()
        .into_protocol_message()
        .unwrap();

    let mut loaded_bob_group = MlsGroup::load(bob_provider.storage(), bob_group.group_id())
        .unwrap()
        .unwrap();
    let processed = loaded_bob_group
        .process_message(&bob_provider, message.clone())
        .unwrap();
    assert_application_message(processed, b"m0");

    let processed = bob_group.process_message(&bob_provider, message).unwrap();
    assert_application_message(processed, b"m0");
}

#[openmls_test::openmls_test]
fn invalid_signature_does_not_advance_handshake_ratchet() {
    let Members {
        alice_provider,
        alice_signer,
        mut alice_group,
        bob_provider,
        bob_signer,
        mut bob_group,
    } = setup::<Provider>(ciphersuite);

    let alice_leaf = alice_group.own_leaf_index();
    let content = forged_proposal_content(&bob_group, alice_leaf, &bob_signer);
    let forged = forge_private_message(
        &bob_group,
        &bob_provider,
        ContentType::Proposal,
        alice_leaf,
        FORGED_GENERATION,
        ForgedPlaintext::Content(&content),
    );
    let error = bob_group
        .process_message(&bob_provider, forged)
        .unwrap_err();
    assert!(matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::InvalidSignature)
    ));

    let commit = alice_group
        .self_update(
            &alice_provider,
            &alice_signer,
            LeafNodeParameters::default(),
        )
        .unwrap()
        .into_commit()
        .into_protocol_message()
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let ProcessedMessageContent::StagedCommitMessage(staged_commit) = bob_group
        .process_message(&bob_provider, commit)
        .unwrap()
        .into_content()
    else {
        panic!("expected a commit");
    };
    bob_group
        .merge_staged_commit(&bob_provider, *staged_commit)
        .unwrap();
    assert_eq!(bob_group.epoch(), alice_group.epoch());
    assert_eq!(
        bob_group.epoch_authenticator(),
        alice_group.epoch_authenticator()
    );
}

#[openmls_test::openmls_test]
fn tampered_copy_does_not_consume_out_of_order_generation() {
    let Members {
        alice_provider,
        alice_signer,
        mut alice_group,
        bob_provider,
        mut bob_group,
        ..
    } = setup::<Provider>(ciphersuite);

    let messages: Vec<_> = [b"m0", b"m1", b"m2"]
        .into_iter()
        .map(|payload| {
            create_application_message(&mut alice_group, &alice_provider, &alice_signer, payload)
        })
        .collect();

    let processed = bob_group
        .process_message(&bob_provider, messages[2].clone())
        .unwrap();
    assert_application_message(processed, b"m2");

    let error = bob_group
        .process_message(
            &bob_provider,
            with_tampered_authenticated_data(&messages[0]),
        )
        .unwrap_err();
    assert_aead_error(error);

    let processed = bob_group
        .process_message(&bob_provider, messages[0].clone())
        .unwrap();
    assert_application_message(processed, b"m0");
    let processed = bob_group
        .process_message(&bob_provider, messages[1].clone())
        .unwrap();
    assert_application_message(processed, b"m1");
}

#[openmls_test::openmls_test]
fn failed_commit_staging_does_not_consume_generation() {
    let Members {
        alice_provider,
        alice_signer,
        mut alice_group,
        bob_provider,
        mut bob_group,
        ..
    } = setup::<Provider>(ciphersuite);

    let (_, charlie_key_package_bundle, _, _) =
        setup_client("Charlie", ciphersuite, &alice_provider);
    let (proposal, _) = alice_group
        .propose_add_member(
            &alice_provider,
            &alice_signer,
            charlie_key_package_bundle.key_package(),
        )
        .unwrap();
    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(&alice_provider, &alice_signer)
        .unwrap();
    let proposal = proposal.into_protocol_message().unwrap();
    let commit = commit.into_protocol_message().unwrap();

    let error = bob_group
        .process_message(&bob_provider, commit.clone())
        .unwrap_err();
    assert!(matches!(
        error,
        ProcessMessageError::InvalidCommit(StageCommitError::MissingProposal)
    ));

    let ProcessedMessageContent::ProposalMessage(queued_proposal) = bob_group
        .process_message(&bob_provider, proposal)
        .unwrap()
        .into_content()
    else {
        panic!("expected a proposal");
    };
    bob_group
        .store_pending_proposal(bob_provider.storage(), *queued_proposal)
        .unwrap();

    let ProcessedMessageContent::StagedCommitMessage(staged_commit) = bob_group
        .process_message(&bob_provider, commit)
        .unwrap()
        .into_content()
    else {
        panic!("expected a commit");
    };
    bob_group
        .merge_staged_commit(&bob_provider, *staged_commit)
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();
    assert_eq!(
        bob_group.epoch_authenticator(),
        alice_group.epoch_authenticator()
    );
}

#[openmls_test::openmls_test]
fn rejected_messages_leave_message_secrets_unchanged() {
    let Members {
        alice_provider,
        alice_signer,
        mut alice_group,
        bob_provider,
        bob_signer,
        mut bob_group,
    } = setup::<Provider>(ciphersuite);

    // Bob initializes Alice's ratchets, which changes the secret tree
    // independently of any ratchet update.
    let message =
        create_application_message(&mut alice_group, &alice_provider, &alice_signer, b"m0");
    bob_group.process_message(&bob_provider, message).unwrap();

    let alice_leaf = alice_group.own_leaf_index();
    let application_content = forged_application_content(&bob_group, alice_leaf, &bob_signer);
    let proposal_content = forged_proposal_content(&bob_group, alice_leaf, &bob_signer);
    let message =
        create_application_message(&mut alice_group, &alice_provider, &alice_signer, b"m1");
    let rejected_messages = [
        with_tampered_authenticated_data(&message),
        forge_private_message(
            &bob_group,
            &bob_provider,
            ContentType::Application,
            alice_leaf,
            FORGED_GENERATION,
            ForgedPlaintext::Garbage,
        ),
        forge_private_message(
            &bob_group,
            &bob_provider,
            ContentType::Application,
            alice_leaf,
            u32::MAX,
            ForgedPlaintext::Garbage,
        ),
        forge_private_message(
            &bob_group,
            &bob_provider,
            ContentType::Application,
            alice_leaf,
            FORGED_GENERATION,
            ForgedPlaintext::Content(&application_content),
        ),
        forge_private_message(
            &bob_group,
            &bob_provider,
            ContentType::Proposal,
            alice_leaf,
            FORGED_GENERATION,
            ForgedPlaintext::Content(&proposal_content),
        ),
    ];

    for rejected_message in rejected_messages {
        let in_memory = bob_group.message_secrets_store().clone();
        let in_storage = stored_message_secrets(&bob_provider, &bob_group);

        bob_group
            .process_message(&bob_provider, rejected_message)
            .unwrap_err();

        assert!(bob_group.message_secrets_store() == &in_memory);
        assert!(stored_message_secrets(&bob_provider, &bob_group) == in_storage);
    }
    bob_group
        .ensure_persistence(bob_provider.storage())
        .unwrap();
}
