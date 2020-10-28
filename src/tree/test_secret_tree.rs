// This tests the boundaries of the generations from a SecretTree
#[test]
fn test_boundaries() {
    use crate::ciphersuite::*;
    use crate::tree::{index::*, secret_tree::*};

    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);
    let mut secret_tree = SecretTree::new(&Secret::from([0u8; 32].to_vec()), LeafIndex::from(2u32));
    let secret_type = SecretType::ApplicationSecret;
    assert!(secret_tree
        .get_secret_for_decryption(&ciphersuite, LeafIndex::from(0u32), secret_type, 0)
        .is_ok());
    assert!(secret_tree
        .get_secret_for_decryption(&ciphersuite, LeafIndex::from(1u32), secret_type, 0)
        .is_ok());
    assert!(secret_tree
        .get_secret_for_decryption(&ciphersuite, LeafIndex::from(0u32), secret_type, 1)
        .is_ok());
    assert!(secret_tree
        .get_secret_for_decryption(&ciphersuite, LeafIndex::from(0u32), secret_type, 1_000)
        .is_ok());
    assert_eq!(
        secret_tree.get_secret_for_decryption(
            &ciphersuite,
            LeafIndex::from(1u32),
            secret_type,
            1001
        ),
        Err(SecretTreeError::TooDistantInTheFuture)
    );
    assert!(secret_tree
        .get_secret_for_decryption(&ciphersuite, LeafIndex::from(0u32), secret_type, 996)
        .is_ok());
    assert_eq!(
        secret_tree.get_secret_for_decryption(
            &ciphersuite,
            LeafIndex::from(0u32),
            secret_type,
            995
        ),
        Err(SecretTreeError::TooDistantInThePast)
    );
    assert_eq!(
        secret_tree.get_secret_for_decryption(&ciphersuite, LeafIndex::from(2u32), secret_type, 0),
        Err(SecretTreeError::IndexOutOfBounds)
    );
    let mut largetree = SecretTree::new(
        &Secret::from([0u8; 32].to_vec()),
        LeafIndex::from(100_000u32),
    );
    assert!(largetree
        .get_secret_for_decryption(&ciphersuite, LeafIndex::from(0u32), secret_type, 0)
        .is_ok());
    assert!(largetree
        .get_secret_for_decryption(&ciphersuite, LeafIndex::from(99_999u32), secret_type, 0)
        .is_ok());
    assert!(largetree
        .get_secret_for_decryption(&ciphersuite, LeafIndex::from(99_999u32), secret_type, 1_000)
        .is_ok());
    assert_eq!(
        largetree.get_secret_for_decryption(
            &ciphersuite,
            LeafIndex::from(100_000u32),
            secret_type,
            0
        ),
        Err(SecretTreeError::IndexOutOfBounds)
    );
}

// This tests if the generation gets incremented correctly and that the returned values are unique.
#[test]
fn increment_generation() {
    use crate::ciphersuite::*;
    use crate::tree::{secret_tree::*, *};
    use std::collections::HashMap;

    const SIZE: usize = 100;
    const MAX_GENERATIONS: usize = 10;
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let mut unique_values: HashMap<Vec<u8>, bool> = HashMap::new();
    let mut secret_tree = SecretTree::new(
        &Secret::from([1u8, 2u8, 3u8].to_vec()),
        LeafIndex::from(SIZE as u32),
    );
    for i in 0..SIZE {
        assert_eq!(
            secret_tree.get_generation(LeafIndex::from(i as u32), SecretType::HandshakeSecret),
            0
        );
        assert_eq!(
            secret_tree.get_generation(LeafIndex::from(i as u32), SecretType::ApplicationSecret),
            0
        );
    }
    for i in 0..MAX_GENERATIONS {
        for j in 0..SIZE {
            let (next_gen, (handshake_key, handshake_nonce)) = secret_tree
                .get_secret_for_encryption(
                    &ciphersuite,
                    LeafIndex::from(j as u32),
                    SecretType::HandshakeSecret,
                );
            assert_eq!(next_gen, i as u32);
            assert!(unique_values
                .insert(handshake_key.as_slice().to_vec(), true)
                .is_none());
            assert!(unique_values
                .insert(handshake_nonce.as_slice().to_vec(), true)
                .is_none());
            let (next_gen, (application_key, application_nonce)) = secret_tree
                .get_secret_for_encryption(
                    &ciphersuite,
                    LeafIndex::from(j as u32),
                    SecretType::ApplicationSecret,
                );
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
