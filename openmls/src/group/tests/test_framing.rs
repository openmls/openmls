use std::io::Write;

use itertools::iproduct;
use openmls_traits::{
    crypto::OpenMlsCrypto, random::OpenMlsRand, types::Ciphersuite, OpenMlsCryptoProvider,
};
use rstest::*;
use rstest_reuse::{self, *};
use tls_codec::Serialize;

use super::utils::*;
use crate::{
    binary_tree::*,
    ciphersuite::signable::Signable,
    framing::{MessageDecryptionError, WireFormat, *},
    group::*,
    schedule::{message_secrets::MessageSecrets, EncryptionSecret},
    test_utils::*,
    tree::{
        index::SecretTreeLeafIndex, secret_tree::SecretTree, secret_tree::SecretType,
        sender_ratchet::SenderRatchetConfiguration,
    },
    versions::ProtocolVersion,
    *,
};

#[apply(backends)]
fn padding(backend: &impl OpenMlsCryptoProvider) {
    // Create a test config for a single client supporting all possible
    // ciphersuites.
    let alice_config = TestClientConfig {
        name: "alice",
        ciphersuites: backend.crypto().supported_ciphersuites(),
    };

    let mut test_group_configs = Vec::new();

    // Create a group config for each ciphersuite.
    for &ciphersuite in backend.crypto().supported_ciphersuites().iter() {
        let test_group = TestGroupConfig {
            ciphersuite,
            config: CoreGroupConfig::default(),
            members: vec![alice_config.clone()],
        };
        test_group_configs.push(test_group);
    }

    // Create the test setup config.
    let test_setup_config = TestSetupConfig {
        clients: vec![alice_config],
        groups: test_group_configs,
    };

    // Initialize the test setup according to config.
    let test_setup = setup(test_setup_config, backend);

    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();

    for padding_size in 0..50 {
        // Create a message in each group and test the padding.
        for group_state in alice.group_states.borrow_mut().values_mut() {
            let credential = alice
                .credentials
                .get(&group_state.ciphersuite())
                .expect("An unexpected error occurred.");
            for _ in 0..10 {
                let message = randombytes(random_usize() % 1000);
                let aad = randombytes(random_usize() % 1000);
                let private_message = group_state
                    .create_application_message(
                        &aad,
                        &message,
                        padding_size,
                        backend,
                        &credential.signer,
                    )
                    .expect("An unexpected error occurred.");
                let ciphertext = private_message.ciphertext();
                let length = ciphertext.len();
                let overflow = if padding_size > 0 {
                    length % padding_size
                } else {
                    0
                };
                if overflow != 0 {
                    panic!(
                        "Error: padding overflow of {overflow} bytes, message length: {length}, padding block size: {padding_size}"
                    );
                }
            }
        }
    }
}

/// Check that PrivateContentTbe's padding field is verified to be all-zero.
#[apply(ciphersuites_and_backends)]
fn bad_padding(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let tests = {
        // { 2^i } ∪ { 2^i +- 1 }
        let padding_sizes = [
            0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
        ];

        // Decryption can fail due to other reasons. Thus, let's make sure that the code
        // below works with correct padding.
        let should_fail_cases = [true, false];

        iproduct!(padding_sizes, should_fail_cases)
    };

    for (padding_size, should_fail) in tests {
        // This will be set later.
        let calculated_padding_length;

        let alice_credential_with_keys = generate_credential_bundle(
            b"Alice".to_vec(),
            ciphersuite.signature_algorithm(),
            backend,
        );

        let sender = Sender::build_member(LeafNodeIndex::new(654));

        let group_context = GroupContext::new(
            ciphersuite,
            GroupId::random(backend),
            1,
            vec![],
            vec![],
            Extensions::empty(),
        );

        let plaintext = {
            let plaintext_tbs = FramedContentTbs::new(
                WireFormat::PrivateMessage,
                GroupId::random(backend),
                1,
                sender,
                vec![1, 2, 3].into(),
                FramedContentBody::Application(vec![4, 5, 6].into()),
            )
            .with_context(vec![7, 8, 9]);

            plaintext_tbs
                .sign(&alice_credential_with_keys.signer)
                .unwrap()
        };

        let mut message_secrets =
            MessageSecrets::random(ciphersuite, backend, LeafNodeIndex::new(0));

        let encryption_secret_bytes = backend
            .rand()
            .random_vec(ciphersuite.hash_length())
            .unwrap();

        let sender_secret_tree = {
            let sender_encryption_secret = EncryptionSecret::from_slice(
                &encryption_secret_bytes[..],
                ProtocolVersion::default(),
                ciphersuite,
            );

            SecretTree::new(
                sender_encryption_secret,
                2u32,
                LeafNodeIndex::new(0u32).into(),
            )
        };

        let receiver_secret_tree = {
            let receiver_encryption_secret = EncryptionSecret::from_slice(
                &encryption_secret_bytes[..],
                ProtocolVersion::default(),
                ciphersuite,
            );

            SecretTree::new(
                receiver_encryption_secret,
                2u32,
                LeafNodeIndex::new(1u32).into(),
            )
        };

        message_secrets.replace_secret_tree(sender_secret_tree);

        let group_id = group_context.group_id().clone();
        let epoch = group_context.epoch();

        let tampered_ciphertext = {
            let leaf_index = match plaintext.sender() {
                Sender::Member(leaf_index) => *leaf_index,
                _ => panic!("Unexpected match."),
            };

            let private_message_content_aad_bytes = {
                let private_message_content_aad = PrivateContentAad {
                    group_id: group_id.clone(),
                    epoch,
                    content_type: plaintext.content().content_type(),
                    authenticated_data: TlsByteSliceU32(plaintext.authenticated_data()),
                };

                private_message_content_aad
                    .tls_serialize_detached()
                    .unwrap()
            };

            // Extract generation and key material for encryption
            let secret_type = SecretType::from(&plaintext.content().content_type());
            let (generation, (ratchet_key, ratchet_nonce)) = message_secrets
                .secret_tree_mut()
                .secret_for_encryption(ciphersuite, backend, SecretTreeLeafIndex(0), secret_type)
                .unwrap();

            // Sample reuse guard uniformly at random.
            let reuse_guard: ReuseGuard = ReuseGuard::try_from_random(backend).unwrap();

            // Prepare the nonce by xoring with the reuse guard.
            let prepared_nonce = ratchet_nonce.xor_with_reuse_guard(&reuse_guard);

            let padded = {
                let plaintext_length = plaintext.content().serialized_len_without_type()
                    + plaintext.test_signature().tls_serialized_len()
                    + plaintext.confirmation_tag().tls_serialized_len();

                // Set the `calculated_padding_length from above now.
                // This will be reused later to check if the test should fail.
                calculated_padding_length = if padding_size > 0 {
                    let padding_offset = plaintext_length + ciphersuite.aead_algorithm().tag_size();

                    (padding_size - (padding_offset % padding_size)) % padding_size
                } else {
                    0
                };

                let mut buffer = Vec::with_capacity(plaintext_length + calculated_padding_length);

                plaintext
                    .content()
                    .serialize_without_type(&mut buffer)
                    .unwrap();
                plaintext
                    .test_signature()
                    .tls_serialize(&mut buffer)
                    .unwrap();
                plaintext
                    .confirmation_tag()
                    .tls_serialize(&mut buffer)
                    .unwrap();
                let padding = {
                    let mut tmp = vec![0u8; calculated_padding_length];

                    if should_fail && calculated_padding_length > 0 {
                        // This should be sufficient. It is rather unlikely that we screw up the
                        // "every byte is zero" check itself. It is more likely that this check
                        // is not conducted at all. So this is what is tested here.
                        tmp[0] = 0x42;
                    }

                    tmp
                };
                buffer.write_all(&padding).unwrap();

                buffer.to_vec()
            };

            let ciphertext = ratchet_key
                .aead_seal(
                    backend,
                    &padded,
                    &private_message_content_aad_bytes,
                    &prepared_nonce,
                )
                .unwrap();
            // Derive the sender data key from the key schedule using the ciphertext.
            let sender_data_key = message_secrets
                .sender_data_secret()
                .derive_aead_key(backend, &ciphertext)
                .unwrap();
            // Derive initial nonce from the key schedule using the ciphertext.
            let sender_data_nonce = message_secrets
                .sender_data_secret()
                .derive_aead_nonce(ciphersuite, backend, &ciphertext)
                .unwrap();
            // Compute sender data nonce by xoring reuse guard and key schedule
            // nonce as per spec.

            let mls_sender_data_aad = MlsSenderDataAad::test_new(
                group_id.clone(),
                epoch,
                plaintext.content().content_type(),
            );
            // Serialize the sender data AAD
            let mls_sender_data_aad_bytes = mls_sender_data_aad.tls_serialize_detached().unwrap();
            let sender_data = MlsSenderData::from_sender(leaf_index, generation, reuse_guard);
            // Encrypt the sender data
            let encrypted_sender_data = sender_data_key
                .aead_seal(
                    backend,
                    &sender_data.tls_serialize_detached().unwrap(),
                    &mls_sender_data_aad_bytes,
                    &sender_data_nonce,
                )
                .unwrap();

            PrivateMessage::new(
                group_id,
                epoch,
                plaintext.content().content_type(),
                plaintext.authenticated_data().into(),
                encrypted_sender_data.into(),
                ciphertext.into(),
            )
        };

        message_secrets.replace_secret_tree(receiver_secret_tree);

        let sender_data = tampered_ciphertext
            .sender_data(&message_secrets, backend, ciphersuite)
            .expect("Could not decrypt sender data.");

        let verifiable_plaintext_result = tampered_ciphertext.to_verifiable_content(
            ciphersuite,
            backend,
            &mut message_secrets,
            SecretTreeLeafIndex(0),
            &SenderRatchetConfiguration::default(),
            sender_data,
        );

        if should_fail && calculated_padding_length > 0 {
            // Decryption should fail because the padding contains a non-zero byte.
            assert_eq!(
                verifiable_plaintext_result,
                Err(MessageDecryptionError::MalformedContent)
            );
        } else {
            assert!(matches!(verifiable_plaintext_result, Ok(_)))
        }
    }
}
