use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::random::OpenMlsRand;

use crate::prelude::ProtocolVersion;
use crate::schedule::EncryptionSecret;

use crate::config::Config;
use crate::tree::index::LeafIndex;
use crate::tree::{secret_tree::*, *};
use std::collections::HashMap;

// This tests the boundaries of the generations from a SecretTree
#[test]
fn test_boundaries() {
    let crypto = OpenMlsRustCrypto::default();
    for ciphersuite in Config::supported_ciphersuites() {
        let encryption_secret = EncryptionSecret::random(ciphersuite, &crypto);
        let mut secret_tree = SecretTree::new(encryption_secret, LeafIndex::from(2u32));
        let secret_type = SecretType::ApplicationSecret;
        assert!(secret_tree
            .secret_for_decryption(ciphersuite, &crypto, LeafIndex::from(0u32), secret_type, 0)
            .is_ok());
        assert!(secret_tree
            .secret_for_decryption(ciphersuite, &crypto, LeafIndex::from(1u32), secret_type, 0)
            .is_ok());
        assert!(secret_tree
            .secret_for_decryption(ciphersuite, &crypto, LeafIndex::from(0u32), secret_type, 1)
            .is_ok());
        assert!(secret_tree
            .secret_for_decryption(
                ciphersuite,
                &crypto,
                LeafIndex::from(0u32),
                secret_type,
                1_000
            )
            .is_ok());
        assert_eq!(
            secret_tree.secret_for_decryption(
                ciphersuite,
                &crypto,
                LeafIndex::from(1u32),
                secret_type,
                1001
            ),
            Err(SecretTreeError::TooDistantInTheFuture)
        );
        assert!(secret_tree
            .secret_for_decryption(
                ciphersuite,
                &crypto,
                LeafIndex::from(0u32),
                secret_type,
                996
            )
            .is_ok());
        assert_eq!(
            secret_tree.secret_for_decryption(
                ciphersuite,
                &crypto,
                LeafIndex::from(0u32),
                secret_type,
                995
            ),
            Err(SecretTreeError::TooDistantInThePast)
        );
        assert_eq!(
            secret_tree.secret_for_decryption(
                ciphersuite,
                &crypto,
                LeafIndex::from(2u32),
                secret_type,
                0
            ),
            Err(SecretTreeError::IndexOutOfBounds)
        );
        let encryption_secret = EncryptionSecret::random(ciphersuite, &crypto);
        let mut largetree = SecretTree::new(encryption_secret, LeafIndex::from(100_000u32));
        assert!(largetree
            .secret_for_decryption(ciphersuite, &crypto, LeafIndex::from(0u32), secret_type, 0)
            .is_ok());
        assert!(largetree
            .secret_for_decryption(
                ciphersuite,
                &crypto,
                LeafIndex::from(99_999u32),
                secret_type,
                0
            )
            .is_ok());
        assert!(largetree
            .secret_for_decryption(
                ciphersuite,
                &crypto,
                LeafIndex::from(99_999u32),
                secret_type,
                1_000
            )
            .is_ok());
        assert_eq!(
            largetree.secret_for_decryption(
                ciphersuite,
                &crypto,
                LeafIndex::from(100_000u32),
                secret_type,
                0
            ),
            Err(SecretTreeError::IndexOutOfBounds)
        );
    }
}

// This tests if the generation gets incremented correctly and that the returned
// values are unique.
#[test]
fn increment_generation() {
    let crypto = OpenMlsRustCrypto::default();
    const SIZE: usize = 100;
    const MAX_GENERATIONS: usize = 10;

    for ciphersuite in Config::supported_ciphersuites() {
        let mut unique_values: HashMap<Vec<u8>, bool> = HashMap::new();
        let encryption_secret = EncryptionSecret::random(ciphersuite, &crypto);
        let mut secret_tree = SecretTree::new(encryption_secret, LeafIndex::from(SIZE as u32));
        for i in 0..SIZE {
            assert_eq!(
                secret_tree.generation(LeafIndex::from(i as u32), SecretType::HandshakeSecret),
                0
            );
            assert_eq!(
                secret_tree.generation(LeafIndex::from(i as u32), SecretType::ApplicationSecret),
                0
            );
        }
        for i in 0..MAX_GENERATIONS {
            for j in 0..SIZE {
                let (next_gen, (handshake_key, handshake_nonce)) = secret_tree
                    .secret_for_encryption(
                        ciphersuite,
                        &crypto,
                        LeafIndex::from(j as u32),
                        SecretType::HandshakeSecret,
                    )
                    .expect("Index out of bounds.");
                assert_eq!(next_gen, i as u32);
                assert!(unique_values
                    .insert(handshake_key.as_slice().to_vec(), true)
                    .is_none());
                assert!(unique_values
                    .insert(handshake_nonce.as_slice().to_vec(), true)
                    .is_none());
                let (next_gen, (application_key, application_nonce)) = secret_tree
                    .secret_for_encryption(
                        ciphersuite,
                        &crypto,
                        LeafIndex::from(j as u32),
                        SecretType::ApplicationSecret,
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
}

#[test]
fn secret_tree() {
    let crypto = OpenMlsRustCrypto::default();
    let ciphersuite = &Config::supported_ciphersuites()[0];
    let leaf_index = 0u32;
    let generation = 0;
    let n_leaves = 10u32;
    let mut secret_tree = SecretTree::new(
        EncryptionSecret::from_slice(
            &crypto.rand().random_vec(ciphersuite.hash_length()).unwrap()[..],
            ProtocolVersion::default(),
            ciphersuite,
        ),
        LeafIndex::from(n_leaves),
    );
    println!("Secret tree: {:?}", secret_tree);
    let (application_secret_key, application_secret_nonce) = secret_tree
        .secret_for_decryption(
            ciphersuite,
            &crypto,
            LeafIndex::from(leaf_index),
            SecretType::ApplicationSecret,
            generation,
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
