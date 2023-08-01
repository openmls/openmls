use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::random::OpenMlsRand;

use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    schedule::EncryptionSecret,
    test_utils::*,
    tree::{secret_tree::*, sender_ratchet::SenderRatchetConfiguration},
    versions::ProtocolVersion,
};
use std::collections::HashMap;

// This tests the boundaries of the generations from a SecretTree
#[apply(ciphersuites_and_providers)]
fn test_boundaries(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let configuration = &SenderRatchetConfiguration::default();
    let encryption_secret = EncryptionSecret::random(ciphersuite, provider.rand());
    let mut secret_tree = SecretTree::new(
        encryption_secret,
        TreeSize::from_leaf_count(3u32),
        LeafNodeIndex::new(2u32),
    );
    let secret_type = SecretType::ApplicationSecret;
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(0u32),
            secret_type,
            0,
            configuration
        )
        .is_ok());
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(1u32),
            secret_type,
            0,
            configuration
        )
        .is_ok());
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(0u32),
            secret_type,
            1,
            configuration
        )
        .is_ok());
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(0u32),
            secret_type,
            1_000,
            configuration,
        )
        .is_ok());
    assert_eq!(
        secret_tree.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(1u32),
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
            provider.crypto(),
            LeafNodeIndex::new(0u32),
            secret_type,
            996,
            configuration,
        )
        .is_ok());
    assert_eq!(
        secret_tree.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(0u32),
            secret_type,
            995,
            configuration,
        ),
        Err(SecretTreeError::TooDistantInThePast)
    );
    assert_eq!(
        secret_tree.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(4u32),
            secret_type,
            0,
            configuration,
        ),
        Err(SecretTreeError::IndexOutOfBounds)
    );
    let encryption_secret = EncryptionSecret::random(ciphersuite, provider.rand());
    let mut largetree = SecretTree::new(
        encryption_secret,
        TreeSize::from_leaf_count(100_000u32),
        LeafNodeIndex::new(2u32),
    );
    assert!(largetree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(0u32),
            secret_type,
            0,
            configuration
        )
        .is_ok());
    largetree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(99_999u32),
            secret_type,
            0,
            configuration,
        )
        .unwrap();
    assert!(largetree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(99_999u32),
            secret_type,
            1_000,
            configuration,
        )
        .is_ok());
    assert_eq!(
        largetree.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(200_000u32),
            secret_type,
            0,
            configuration,
        ),
        Err(SecretTreeError::IndexOutOfBounds)
    );
}

// This tests if the generation gets incremented correctly and that the returned
// values are unique.
#[apply(ciphersuites_and_providers)]
fn increment_generation(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    const SIZE: usize = 100;
    const MAX_GENERATIONS: usize = 10;

    let mut unique_values: HashMap<Vec<u8>, bool> = HashMap::new();
    let encryption_secret = EncryptionSecret::random(ciphersuite, provider.rand());
    let mut secret_tree = SecretTree::new(
        encryption_secret,
        TreeSize::from_leaf_count(SIZE as u32),
        LeafNodeIndex::new(0u32),
    );
    for i in 0..SIZE {
        assert_eq!(
            secret_tree.generation(LeafNodeIndex::new(i as u32), SecretType::HandshakeSecret),
            0
        );
        assert_eq!(
            secret_tree.generation(LeafNodeIndex::new(i as u32), SecretType::ApplicationSecret),
            0
        );
    }
    for i in 0..MAX_GENERATIONS {
        // We are index 0, so we can't get a decryption secret for that leaf.
        for j in 1..SIZE {
            let next_gen =
                secret_tree.generation(LeafNodeIndex::new(j as u32), SecretType::HandshakeSecret);
            let (handshake_key, handshake_nonce) = secret_tree
                .secret_for_decryption(
                    ciphersuite,
                    provider.crypto(),
                    LeafNodeIndex::new(j as u32),
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
            let next_gen =
                secret_tree.generation(LeafNodeIndex::new(j as u32), SecretType::ApplicationSecret);
            let (application_key, application_nonce) = secret_tree
                .secret_for_decryption(
                    ciphersuite,
                    provider.crypto(),
                    LeafNodeIndex::new(j as u32),
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

#[apply(ciphersuites_and_providers)]
fn secret_tree(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let leaf_index = 0u32;
    let generation = 0;
    let n_leaves = 10u32;
    let configuration = &SenderRatchetConfiguration::default();
    let mut secret_tree = SecretTree::new(
        EncryptionSecret::from_slice(
            &provider
                .rand()
                .random_vec(ciphersuite.hash_length())
                .expect("An unexpected error occurred.")[..],
            ProtocolVersion::default(),
            ciphersuite,
        ),
        TreeSize::new(n_leaves),
        LeafNodeIndex::new(1u32),
    );
    let (application_secret_key, application_secret_nonce) = secret_tree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(leaf_index),
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
}
