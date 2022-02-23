use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::random::OpenMlsRand;

use crate::{
    schedule::EncryptionSecret,
    test_utils::*,
    tree::{
        index::SecretTreeLeafIndex, secret_tree::*, sender_ratchet::SenderRatchetConfiguration,
    },
    versions::ProtocolVersion,
};
use std::collections::HashMap;

// This tests the boundaries of the generations from a SecretTree
#[apply(ciphersuites_and_backends)]
fn test_boundaries(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let configuration = &SenderRatchetConfiguration::default();
    let encryption_secret = EncryptionSecret::random(ciphersuite, backend);
    let mut secret_tree = SecretTree::new(
        encryption_secret,
        SecretTreeLeafIndex::from(3u32),
        2u32.into(),
    );
    let secret_type = SecretType::ApplicationSecret;
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(0u32),
            secret_type,
            0,
            configuration
        )
        .is_ok());
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(1u32),
            secret_type,
            0,
            configuration
        )
        .is_ok());
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(0u32),
            secret_type,
            1,
            configuration
        )
        .is_ok());
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(0u32),
            secret_type,
            1_000,
            configuration,
        )
        .is_ok());
    assert_eq!(
        secret_tree.secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(1u32),
            secret_type,
            // We're at generation 1, so 1001 is still ok.
            1002,
            configuration,
        ),
        Err(SecretTreeError::TooDistantInTheFuture)
    );
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(0u32),
            secret_type,
            996,
            configuration,
        )
        .is_ok());
    assert_eq!(
        secret_tree.secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(0u32),
            secret_type,
            995,
            configuration,
        ),
        Err(SecretTreeError::TooDistantInThePast)
    );
    assert_eq!(
        secret_tree.secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(3u32),
            secret_type,
            0,
            configuration,
        ),
        Err(SecretTreeError::IndexOutOfBounds)
    );
    let encryption_secret = EncryptionSecret::random(ciphersuite, backend);
    let mut largetree = SecretTree::new(
        encryption_secret,
        SecretTreeLeafIndex::from(100_000u32),
        2u32.into(),
    );
    assert!(largetree
        .secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(0u32),
            secret_type,
            0,
            configuration
        )
        .is_ok());
    assert!(largetree
        .secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(99_999u32),
            secret_type,
            0,
            configuration,
        )
        .is_ok());
    assert!(largetree
        .secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(99_999u32),
            secret_type,
            1_000,
            configuration,
        )
        .is_ok());
    assert_eq!(
        largetree.secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(100_000u32),
            secret_type,
            0,
            configuration,
        ),
        Err(SecretTreeError::IndexOutOfBounds)
    );
}

// This tests if the generation gets incremented correctly and that the returned
// values are unique.
#[apply(ciphersuites_and_backends)]
fn increment_generation(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    const SIZE: usize = 100;
    const MAX_GENERATIONS: usize = 10;

    let mut unique_values: HashMap<Vec<u8>, bool> = HashMap::new();
    let encryption_secret = EncryptionSecret::random(ciphersuite, backend);
    let mut secret_tree = SecretTree::new(
        encryption_secret,
        SecretTreeLeafIndex::from(SIZE as u32),
        0u32.into(),
    );
    for i in 0..SIZE {
        assert_eq!(
            secret_tree.generation(
                SecretTreeLeafIndex::from(i as u32),
                SecretType::HandshakeSecret
            ),
            0
        );
        assert_eq!(
            secret_tree.generation(
                SecretTreeLeafIndex::from(i as u32),
                SecretType::ApplicationSecret
            ),
            0
        );
    }
    for i in 0..MAX_GENERATIONS {
        // We are index 0, so we can't get a decryption secret for that leaf.
        for j in 1..SIZE {
            let next_gen = secret_tree.generation((j as u32).into(), SecretType::HandshakeSecret);
            let (handshake_key, handshake_nonce) = secret_tree
                .secret_for_decryption(
                    ciphersuite,
                    backend,
                    SecretTreeLeafIndex::from(j as u32),
                    SecretType::HandshakeSecret,
                    i as u32,
                    &SenderRatchetConfiguration::default(),
                )
                .expect("Index out of bounds.");
            assert_eq!(next_gen, i as u32);
            assert!(unique_values
                .insert(handshake_key.as_slice().to_vec(), true)
                .is_none());
            assert!(unique_values
                .insert(handshake_nonce.as_slice().to_vec(), true)
                .is_none());
            let next_gen = secret_tree.generation((j as u32).into(), SecretType::ApplicationSecret);
            let (application_key, application_nonce) = secret_tree
                .secret_for_decryption(
                    ciphersuite,
                    backend,
                    SecretTreeLeafIndex::from(j as u32),
                    SecretType::ApplicationSecret,
                    i as u32,
                    &SenderRatchetConfiguration::default(),
                )
                .expect("Index out of bounds.");
            assert_eq!(next_gen, i as u32);
            assert!(unique_values
                .insert(application_key.as_slice().to_vec(), true)
                .is_none());
            assert!(unique_values
                .insert(application_nonce.as_slice().to_vec(), true)
                .is_none());
        }
    }
}

#[apply(ciphersuites_and_backends)]
fn secret_tree(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let leaf_index = 0u32;
    let generation = 0;
    let n_leaves = 10u32;
    let configuration = &SenderRatchetConfiguration::default();
    let mut secret_tree = SecretTree::new(
        EncryptionSecret::from_slice(
            &backend
                .rand()
                .random_vec(ciphersuite.hash_length())
                .expect("An unexpected error occurred.")[..],
            ProtocolVersion::default(),
            ciphersuite,
        ),
        SecretTreeLeafIndex::from(n_leaves),
        1u32.into(),
    );
    println!("Secret tree: {:?}", secret_tree);
    let (application_secret_key, application_secret_nonce) = secret_tree
        .secret_for_decryption(
            ciphersuite,
            backend,
            SecretTreeLeafIndex::from(leaf_index),
            SecretType::ApplicationSecret,
            generation,
            configuration,
        )
        .expect("Error getting decryption secret");
    println!(
        "application_secret_key: {:x?}",
        application_secret_key.as_slice()
    );
    println!(
        "application_secret_nonce: {:x?}",
        application_secret_nonce.as_slice()
    );
    println!("Secret tree: {:?}", secret_tree);
}
