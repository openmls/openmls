//! Tests for targeted messages (draft-ietf-mls-targeted-messages).

use openmls_test::openmls_test;
use openmls_traits::{storage::StorageProvider as _, types::HpkeCiphertext};
use tls_codec::{DeserializeBytes as _, Serialize as TlsSerializeTrait, VLByteSlice};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    framing::{MlsMessageBodyOut, MlsMessageIn},
    group::mls_group::{config::MlsGroupJoinConfig, tests_and_kats::utils::setup_alice_bob_group},
    targeted_messages::{
        derive_sender_auth_data_key_nonce, derive_sender_auth_data_secret,
        derive_targeted_message_psk, ProcessTargetedMessageError, SenderAuthDataAAD,
        TargetedMessageContent, TargetedMessageGroupContext, TargetedMessageIn,
        TargetedMessagePskId, TargetedMessageSenderAuthData, TargetedMessageTBM,
    },
    treesync::node::encryption_keys::EncryptionKeyPair,
};

/// Helper function that serializes an MlsMessageOut then deserializes it as
/// MlsMessageIn to extract the TargetedMessageIn.
fn extract_targeted_message_in(msg: &crate::framing::MlsMessageOut) -> TargetedMessageIn {
    let bytes = msg.tls_serialize_detached().expect("Serialization failed");
    let (mls_in, _) = MlsMessageIn::tls_deserialize_bytes(&bytes).expect("Deserialization failed");
    mls_in
        .into_targeted_message()
        .expect("Not a targeted message")
}

fn decrypt_targeted_message_content_with_real_tbm(
    provider: &impl crate::storage::OpenMlsProvider,
    group: &crate::group::MlsGroup,
    message: &TargetedMessageIn,
) -> TargetedMessageContent {
    let ctx = TargetedMessageGroupContext {
        ciphersuite: group.ciphersuite(),
        group_id: group.group_id(),
        epoch: group.context().epoch(),
        exporter_secret: group.group_epoch_secrets().exporter_secret(),
    };

    let sender_auth_data_secret =
        derive_sender_auth_data_secret(provider.crypto(), ctx.ciphersuite, ctx.exporter_secret)
            .expect("Failed to derive sender auth data secret");
    let (key, nonce) = derive_sender_auth_data_key_nonce(
        provider.crypto(),
        ctx.ciphersuite,
        &sender_auth_data_secret,
        message.ciphertext.as_slice(),
    )
    .expect("Failed to derive sender auth data key and nonce");
    let sender_auth_aad = SenderAuthDataAAD {
        group_id: ctx.group_id,
        epoch: ctx.epoch,
        recipient_leaf_index: group.own_leaf_index().u32(),
    };
    let sender_auth_aad_bytes = sender_auth_aad
        .tls_serialize_detached()
        .expect("Failed to serialize sender auth AAD");
    let sender_auth_data_bytes = key
        .aead_open(
            provider.crypto(),
            message.encrypted_sender_auth_data.as_slice(),
            &sender_auth_aad_bytes,
            &nonce,
        )
        .expect("Failed to decrypt sender auth data");
    let sender_auth_data =
        TargetedMessageSenderAuthData::tls_deserialize_exact_bytes(&sender_auth_data_bytes)
            .expect("Failed to deserialize sender auth data");

    let psk = derive_targeted_message_psk(provider.crypto(), ctx.ciphersuite, ctx.exporter_secret)
        .expect("Failed to derive targeted message PSK");
    let psk_id_bytes = TargetedMessagePskId::new(ctx.group_id, ctx.epoch)
        .tls_serialize_detached()
        .expect("Failed to serialize PSK ID");
    let tbm = TargetedMessageTBM {
        group_id: ctx.group_id,
        epoch: ctx.epoch,
        recipient_leaf_index: group.own_leaf_index().u32(),
        authenticated_data: VLByteSlice(message.authenticated_data.as_slice()),
        sender_leaf_index: sender_auth_data.sender_leaf_index,
        kem_output: VLByteSlice(sender_auth_data.kem_output.as_slice()),
    };
    let tbm_bytes = tbm
        .tls_serialize_detached()
        .expect("Failed to serialize TBM");

    let epoch_keypairs = provider
        .storage()
        .encryption_epoch_key_pairs::<_, _, EncryptionKeyPair>(
            group.group_id(),
            &group.context().epoch(),
            group.own_leaf_index().u32(),
        )
        .expect("Failed to load epoch keypairs");
    let own_encryption_key = group
        .public_group()
        .leaf(group.own_leaf_index())
        .expect("Own leaf node not found")
        .encryption_key();
    let own_keypair: &EncryptionKeyPair = epoch_keypairs
        .iter()
        .find(|kp| kp.public_key() == own_encryption_key)
        .expect("Own encryption keypair not found");
    let hpke_ciphertext = HpkeCiphertext {
        kem_output: sender_auth_data.kem_output,
        ciphertext: message.ciphertext.clone(),
    };
    let content_bytes = own_keypair
        .private_key()
        .decrypt_with_label_psk_aad(
            crate::ciphersuite::hpke::PskEncryptParams {
                label: super::TARGETED_MESSAGE_DATA_LABEL,
                context: &[],
                psk: &psk,
                psk_id: &psk_id_bytes,
                ciphersuite: ctx.ciphersuite,
            },
            &tbm_bytes,
            &hpke_ciphertext,
            provider.crypto(),
        )
        .expect("Failed to decrypt content with the real TBM");

    TargetedMessageContent::deserialize_detached(&content_bytes)
        .expect("Failed to deserialize targeted message content")
}

#[openmls_test]
fn targeted_message_round_trip() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let payload = b"Hello Bob, this is a targeted message!";
    let bob_leaf_index = bob_group.own_leaf_index();

    let mls_msg_out = alice_group
        .create_targeted_message(alice_provider, &alice_signer, bob_leaf_index, payload)
        .expect("Failed to create targeted message");

    // Verify the MlsMessageOut wraps a TargetedMessage
    match mls_msg_out.body() {
        MlsMessageBodyOut::TargetedMessage(tm) => {
            assert_eq!(tm.group_id(), alice_group.group_id());
            assert_eq!(tm.epoch(), alice_group.epoch());
            assert_eq!(tm.recipient_leaf_index(), bob_leaf_index.u32());
        }
        _ => panic!("Expected TargetedMessage variant"),
    }

    let targeted_in = extract_targeted_message_in(&mls_msg_out);

    let processed = bob_group
        .process_targeted_message(bob_provider, &targeted_in)
        .expect("Failed to process targeted message");

    assert_eq!(processed.application_data(), payload);
    assert_eq!(processed.sender_leaf_index(), alice_group.own_leaf_index());
}

#[openmls_test]
fn targeted_message_wrong_recipient() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let bob_leaf_index = bob_group.own_leaf_index();

    let mls_msg_out = alice_group
        .create_targeted_message(alice_provider, &alice_signer, bob_leaf_index, b"secret")
        .expect("Failed to create targeted message");

    let targeted_in = extract_targeted_message_in(&mls_msg_out);

    // Alice tries to process a message meant for Bob
    let result = alice_group.process_targeted_message(alice_provider, &targeted_in);
    assert!(result.is_err());
}

#[openmls_test]
fn targeted_message_serialization() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let bob_leaf_index = bob_group.own_leaf_index();

    let mls_msg_out = alice_group
        .create_targeted_message(alice_provider, &alice_signer, bob_leaf_index, b"payload")
        .expect("Failed to create targeted message");

    // Serialize/deserialize at the MlsMessage level
    let bytes = mls_msg_out
        .tls_serialize_detached()
        .expect("Serialization failed");
    let (mls_in, rest) =
        MlsMessageIn::tls_deserialize_bytes(&bytes).expect("Deserialization failed");
    assert!(rest.is_empty());

    let targeted_in = mls_in
        .into_targeted_message()
        .expect("Not a targeted message");

    let processed = bob_group
        .process_targeted_message(bob_provider, &targeted_in)
        .expect("Failed to process deserialized targeted message");
    assert_eq!(processed.application_data(), b"payload");
}

#[openmls_test]
fn targeted_message_bidirectional() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, mut bob_group, bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    // Alice -> Bob
    let alice_msg = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            b"Hello Bob",
        )
        .expect("Alice failed to create targeted message");

    let targeted_in = extract_targeted_message_in(&alice_msg);
    let processed = bob_group
        .process_targeted_message(bob_provider, &targeted_in)
        .expect("Bob failed to process");
    assert_eq!(processed.application_data(), b"Hello Bob");

    // Bob -> Alice
    let bob_msg = bob_group
        .create_targeted_message(
            bob_provider,
            &bob_signer,
            alice_group.own_leaf_index(),
            b"Hello Alice",
        )
        .expect("Bob failed to create targeted message");

    let targeted_in = extract_targeted_message_in(&bob_msg);
    let processed = alice_group
        .process_targeted_message(alice_provider, &targeted_in)
        .expect("Alice failed to process");
    assert_eq!(processed.application_data(), b"Hello Alice");
}

#[openmls_test]
fn targeted_message_invalid_recipient_leaf() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, _bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let result = alice_group.create_targeted_message(
        alice_provider,
        &alice_signer,
        LeafNodeIndex::new(99),
        b"payload",
    );
    assert!(result.is_err());
}

#[openmls_test]
fn targeted_message_empty_payload() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let mls_msg_out = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            b"",
        )
        .expect("Failed to create targeted message with empty payload");

    let targeted_in = extract_targeted_message_in(&mls_msg_out);
    let processed = bob_group
        .process_targeted_message(bob_provider, &targeted_in)
        .expect("Failed to process");
    assert!(processed.application_data().is_empty());
}

#[openmls_test]
fn targeted_message_uses_real_sender_auth_data_in_tbm() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let payload = b"payload bound to real sender auth data";
    let mls_msg_out = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            payload,
        )
        .expect("Failed to create targeted message");

    let targeted_in = extract_targeted_message_in(&mls_msg_out);
    let content =
        decrypt_targeted_message_content_with_real_tbm(bob_provider, &bob_group, &targeted_in);

    assert_eq!(content.application_data(), payload);
}

#[openmls_test]
fn targeted_message_aad_is_one_shot() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let aad = b"targeted message aad".to_vec();
    alice_group.set_aad(aad.clone());

    let first_message = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            b"first",
        )
        .expect("Failed to create first targeted message");
    assert!(alice_group.aad().is_empty());

    let second_message = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            b"second",
        )
        .expect("Failed to create second targeted message");

    let first_processed = bob_group
        .process_targeted_message(bob_provider, &extract_targeted_message_in(&first_message))
        .expect("Failed to process first targeted message");
    let second_processed = bob_group
        .process_targeted_message(bob_provider, &extract_targeted_message_in(&second_message))
        .expect("Failed to process second targeted message");

    assert_eq!(first_processed.authenticated_data(), aad.as_slice());
    assert!(second_processed.authenticated_data().is_empty());
}

// --- B1: Adversarial/negative test cases ---

#[cfg(test)]
impl TargetedMessageIn {
    fn with_epoch(mut self, epoch: crate::group::GroupEpoch) -> Self {
        self.epoch = epoch;
        self
    }

    fn with_group_id(mut self, group_id: crate::group::GroupId) -> Self {
        self.group_id = group_id;
        self
    }

    fn with_tampered_ciphertext(mut self) -> Self {
        let mut bytes = self.ciphertext.as_slice().to_vec();
        bytes[0] ^= 0xff;
        self.ciphertext = bytes.into();
        self
    }

    fn with_tampered_sender_auth_data(mut self) -> Self {
        let mut bytes = self.encrypted_sender_auth_data.as_slice().to_vec();
        bytes[0] ^= 0xff;
        self.encrypted_sender_auth_data = bytes.into();
        self
    }
}

#[openmls_test]
fn targeted_message_epoch_mismatch() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let mls_msg_out = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            b"test",
        )
        .expect("Failed to create targeted message");

    let targeted_in = extract_targeted_message_in(&mls_msg_out).with_epoch(99u64.into());

    let result = bob_group.process_targeted_message(bob_provider, &targeted_in);
    assert!(matches!(
        result,
        Err(ProcessTargetedMessageError::EpochMismatch)
    ));
}

#[openmls_test]
fn targeted_message_group_id_mismatch() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let mls_msg_out = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            b"test",
        )
        .expect("Failed to create targeted message");

    let targeted_in = extract_targeted_message_in(&mls_msg_out)
        .with_group_id(crate::group::GroupId::from_slice(b"wrong-group"));

    let result = bob_group.process_targeted_message(bob_provider, &targeted_in);
    assert!(matches!(
        result,
        Err(ProcessTargetedMessageError::GroupIdMismatch)
    ));
}

#[openmls_test]
fn targeted_message_ciphertext_tampered() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let mls_msg_out = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            b"test",
        )
        .expect("Failed to create targeted message");

    let targeted_in = extract_targeted_message_in(&mls_msg_out).with_tampered_ciphertext();

    let result = bob_group.process_targeted_message(bob_provider, &targeted_in);
    // Tampering with ciphertext affects both sender auth data
    // key derivation and content decryption
    assert!(result.is_err());
}

#[openmls_test]
fn targeted_message_sender_auth_data_tampered() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let mls_msg_out = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            b"test",
        )
        .expect("Failed to create targeted message");

    let targeted_in = extract_targeted_message_in(&mls_msg_out).with_tampered_sender_auth_data();

    let result = bob_group.process_targeted_message(bob_provider, &targeted_in);
    assert!(matches!(
        result,
        Err(ProcessTargetedMessageError::SenderAuthDataDecryptionFailed)
    ));
}

#[openmls_test]
fn targeted_message_padding_round_trip() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let payload = b"short";
    let config = MlsGroupJoinConfig::builder().padding_size(256).build();
    alice_group
        .set_configuration(alice_provider.storage(), &config)
        .expect("Failed to set padding size");

    let mls_msg_out = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            payload,
        )
        .expect("Failed to create padded targeted message");

    let targeted_in = extract_targeted_message_in(&mls_msg_out);
    let processed = bob_group
        .process_targeted_message(bob_provider, &targeted_in)
        .expect("Failed to process padded targeted message");

    // Padding must be stripped — only the original application data is returned.
    assert_eq!(processed.application_data(), payload);
}

#[openmls_test]
fn targeted_message_padding_grows_ciphertext() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let payload = b"same payload";

    let unpadded = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            payload,
        )
        .expect("create unpadded");

    let config = MlsGroupJoinConfig::builder().padding_size(512).build();
    alice_group
        .set_configuration(alice_provider.storage(), &config)
        .expect("Failed to set padding size");
    let padded = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            payload,
        )
        .expect("create padded");

    let unpadded_in = extract_targeted_message_in(&unpadded);
    let padded_in = extract_targeted_message_in(&padded);
    assert!(
        padded_in.ciphertext.as_slice().len() > unpadded_in.ciphertext.as_slice().len() + 256,
        "padded ciphertext should be substantially larger"
    );
}

#[openmls_test]
fn targeted_message_padding_rejects_nonzero_bytes() {
    let mut bytes = TargetedMessageContent::new(b"data", 4)
        .serialize_detached()
        .expect("serialize");
    let last = bytes.len() - 1;
    bytes[last] = 0xff;
    let result = TargetedMessageContent::deserialize_detached(&bytes);
    assert!(result.is_err());
}

#[openmls_test]
fn targeted_message_signature_bound_to_sender_leaf_index() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, bob_group, _bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);

    let mls_msg_out = alice_group
        .create_targeted_message(
            alice_provider,
            &alice_signer,
            bob_group.own_leaf_index(),
            b"genuine",
        )
        .expect("create");
    let targeted_in = extract_targeted_message_in(&mls_msg_out);

    let ctx = TargetedMessageGroupContext {
        ciphersuite: bob_group.ciphersuite(),
        group_id: bob_group.group_id(),
        epoch: bob_group.context().epoch(),
        exporter_secret: bob_group.group_epoch_secrets().exporter_secret(),
    };
    let auth_secret =
        derive_sender_auth_data_secret(bob_provider.crypto(), ctx.ciphersuite, ctx.exporter_secret)
            .expect("derive auth secret");
    let (key, nonce) = derive_sender_auth_data_key_nonce(
        bob_provider.crypto(),
        ctx.ciphersuite,
        &auth_secret,
        targeted_in.ciphertext.as_slice(),
    )
    .expect("derive key/nonce");
    let aad = SenderAuthDataAAD {
        group_id: ctx.group_id,
        epoch: ctx.epoch,
        recipient_leaf_index: bob_group.own_leaf_index().u32(),
    };
    let aad_bytes = aad.tls_serialize_detached().expect("serialize AAD");

    let plaintext = key
        .aead_open(
            bob_provider.crypto(),
            targeted_in.encrypted_sender_auth_data.as_slice(),
            &aad_bytes,
            &nonce,
        )
        .expect("aead open");
    let mut sender_auth_data =
        TargetedMessageSenderAuthData::tls_deserialize_exact_bytes(&plaintext)
            .expect("deserialize sender auth data");
    assert_eq!(
        sender_auth_data.sender_leaf_index,
        alice_group.own_leaf_index().u32()
    );

    // Forge: claim the message came from Bob (the recipient) rather than Alice.
    sender_auth_data.sender_leaf_index = bob_group.own_leaf_index().u32();
    let forged_plaintext = sender_auth_data
        .tls_serialize_detached()
        .expect("serialize forged sender auth data");
    let forged_encrypted = key
        .aead_seal(bob_provider.crypto(), &forged_plaintext, &aad_bytes, &nonce)
        .expect("aead seal");

    let mut forged_msg = targeted_in;
    forged_msg.encrypted_sender_auth_data = forged_encrypted.into();

    let result = bob_group.process_targeted_message(bob_provider, &forged_msg);
    assert!(matches!(
        result,
        Err(ProcessTargetedMessageError::SignatureVerificationFailed)
    ));
}
