#[test]
fn test_boundaries() {
    use crate::ciphersuite::*;
    use crate::tree::{index::*, secret_tree::*};

    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);
    let mut secret_tree = SecretTree::new(&[0u8; 32], LeafIndex::from(2u32));
    let secret_type = SecretType::ApplicationSecret;
    assert!(secret_tree
        .get_secret(&ciphersuite, LeafIndex::from(0u32), secret_type, 0)
        .is_ok());
    assert!(secret_tree
        .get_secret(&ciphersuite, LeafIndex::from(1u32), secret_type, 0)
        .is_ok());
    assert!(secret_tree
        .get_secret(&ciphersuite, LeafIndex::from(0u32), secret_type, 1)
        .is_ok());
    assert!(secret_tree
        .get_secret(&ciphersuite, LeafIndex::from(0u32), secret_type, 1_000)
        .is_ok());
    assert_eq!(
        secret_tree.get_secret(&ciphersuite, LeafIndex::from(1u32), secret_type, 1001),
        Err(SecretTreeError::TooDistantInTheFuture)
    );
    assert!(secret_tree
        .get_secret(&ciphersuite, LeafIndex::from(0u32), secret_type, 996)
        .is_ok());
    assert_eq!(
        secret_tree.get_secret(&ciphersuite, LeafIndex::from(0u32), secret_type, 995),
        Err(SecretTreeError::TooDistantInThePast)
    );
    assert_eq!(
        secret_tree.get_secret(&ciphersuite, LeafIndex::from(2u32), secret_type, 0),
        Err(SecretTreeError::IndexOutOfBounds)
    );
    let mut largetree = SecretTree::new(&[0u8; 32], LeafIndex::from(100_000u32));
    assert!(largetree
        .get_secret(&ciphersuite, LeafIndex::from(0u32), secret_type, 0)
        .is_ok());
    assert!(largetree
        .get_secret(&ciphersuite, LeafIndex::from(99_999u32), secret_type, 0)
        .is_ok());
    assert!(largetree
        .get_secret(&ciphersuite, LeafIndex::from(99_999u32), secret_type, 1_000)
        .is_ok());
    assert_eq!(
        largetree.get_secret(&ciphersuite, LeafIndex::from(100_000u32), secret_type, 0),
        Err(SecretTreeError::IndexOutOfBounds)
    );
}

#[test]
fn increment_generation() {
    use crate::ciphersuite::*;
    use crate::tree::{secret_tree::*, *};

    const SIZE: usize = 1000;
    const MAX_GENERATIONS: usize = 10;
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let mut secret_tree = SecretTree::new(&[1, 2, 3], LeafIndex::from(SIZE as u32));
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
            let (next_gen, _secret) = secret_tree
                .next_secret(
                    &ciphersuite,
                    LeafIndex::from(j as u32),
                    SecretType::HandshakeSecret,
                )
                .unwrap();
            assert_eq!(next_gen, i as u32);
            let (next_gen, _secret) = secret_tree
                .next_secret(
                    &ciphersuite,
                    LeafIndex::from(j as u32),
                    SecretType::ApplicationSecret,
                )
                .unwrap();
            assert_eq!(next_gen, i as u32);
        }
    }
}
