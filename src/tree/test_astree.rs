#[test]
fn test_boundaries() {
    use crate::ciphersuite::*;
    use crate::tree::{astree::*, index::*};

    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);
    let mut astree = ASTree::new(&[0u8; 32], LeafIndex::from(2u32));
    assert!(astree
        .get_secret(&ciphersuite, LeafIndex::from(0u32), 0)
        .is_ok());
    assert!(astree
        .get_secret(&ciphersuite, LeafIndex::from(1u32), 0)
        .is_ok());
    assert!(astree
        .get_secret(&ciphersuite, LeafIndex::from(0u32), 1)
        .is_ok());
    assert!(astree
        .get_secret(&ciphersuite, LeafIndex::from(0u32), 1_000)
        .is_ok());
    assert_eq!(
        astree.get_secret(&ciphersuite, LeafIndex::from(1u32), 1001),
        Err(ASError::TooDistantInTheFuture)
    );
    assert!(astree
        .get_secret(&ciphersuite, LeafIndex::from(0u32), 996)
        .is_ok());
    assert_eq!(
        astree.get_secret(&ciphersuite, LeafIndex::from(0u32), 995),
        Err(ASError::TooDistantInThePast)
    );
    assert_eq!(
        astree.get_secret(&ciphersuite, LeafIndex::from(2u32), 0),
        Err(ASError::IndexOutOfBounds)
    );
    let mut largetree = ASTree::new(&[0u8; 32], LeafIndex::from(100_000u32));
    assert!(largetree
        .get_secret(&ciphersuite, LeafIndex::from(0u32), 0)
        .is_ok());
    assert!(largetree
        .get_secret(&ciphersuite, LeafIndex::from(99_999u32), 0)
        .is_ok());
    assert!(largetree
        .get_secret(&ciphersuite, LeafIndex::from(99_999u32), 1_000)
        .is_ok());
    assert_eq!(
        largetree.get_secret(&ciphersuite, LeafIndex::from(100_000u32), 0),
        Err(ASError::IndexOutOfBounds)
    );
}
