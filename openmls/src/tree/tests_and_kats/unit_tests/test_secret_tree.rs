use openmls_traits::random::OpenMlsRand;

use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    schedule::EncryptionSecret,
    tree::{
        secret_tree::*,
        sender_ratchet::{SenderRatchet, SenderRatchetConfiguration},
    },
};
use std::collections::HashMap;

// This tests the boundaries of the generations from a SecretTree
#[openmls_test::openmls_test]
fn test_boundaries() {
    let provider = &Provider::default();

    let configuration = &SenderRatchetConfiguration::default();
    let encryption_secret = EncryptionSecret::random(ciphersuite, provider.rand());
    let mut secret_tree = SecretTree::new(
        encryption_secret,
        TreeSize::from_leaf_count(3u32),
        LeafNodeIndex::new(2u32),
    );
    assert_eq!(secret_tree.own_index(), LeafNodeIndex::new(2u32));
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

#[openmls_test::openmls_test]
fn prepare_decryption_leaves_ratchet_unchanged() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let mut secret_tree = SecretTree::new(
        EncryptionSecret::random(ciphersuite, provider.rand()),
        TreeSize::from_leaf_count(2u32),
        LeafNodeIndex::new(1u32),
    );
    let sender = LeafNodeIndex::new(0u32);
    let secret_type = SecretType::ApplicationSecret;

    let (first_secret, first_update) = secret_tree
        .prepare_decryption(
            ciphersuite,
            provider.crypto(),
            sender,
            secret_type,
            10,
            configuration,
        )
        .unwrap();
    assert!(first_update.is_some());
    let ratchet = secret_tree.sender_ratchet(sender, secret_type).cloned();
    assert_eq!(secret_tree.generation(sender, secret_type), 0);

    let (second_secret, _) = secret_tree
        .prepare_decryption(
            ciphersuite,
            provider.crypto(),
            sender,
            secret_type,
            10,
            configuration,
        )
        .unwrap();
    assert_eq!(first_secret, second_secret);
    assert_eq!(
        secret_tree.sender_ratchet(sender, secret_type),
        ratchet.as_ref()
    );
}

#[openmls_test::openmls_test]
fn prepare_and_apply_match_sender_ratchet() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let mut secret_tree = SecretTree::new(
        EncryptionSecret::random(ciphersuite, provider.rand()),
        TreeSize::from_leaf_count(2u32),
        LeafNodeIndex::new(1u32),
    );
    let sender = LeafNodeIndex::new(0u32);
    let secret_type = SecretType::HandshakeSecret;
    secret_tree
        .prepare_decryption(
            ciphersuite,
            provider.crypto(),
            sender,
            secret_type,
            0,
            configuration,
        )
        .unwrap();
    let Some(SenderRatchet::DecryptionRatchet(mut sender_ratchet)) =
        secret_tree.sender_ratchet(sender, secret_type).cloned()
    else {
        panic!("expected a decryption ratchet");
    };

    // Current, forward, current, window, reuse, window, forward, too old and
    // too far ahead.
    for generation in [0, 3, 4, 1, 1, 2, 10, 2, 2_000] {
        let expected = sender_ratchet
            .secret_for_decryption(ciphersuite, provider.crypto(), generation, configuration)
            .map(DecryptionSecret::Available);
        let actual = secret_tree.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            sender,
            secret_type,
            generation,
            configuration,
        );
        assert_eq!(actual, expected, "generation {generation}");
        assert_eq!(
            secret_tree.sender_ratchet(sender, secret_type),
            Some(&SenderRatchet::DecryptionRatchet(sender_ratchet.clone())),
            "generation {generation}"
        );
    }
}

#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn prepare_decryption_leaves_own_dual_use_ratchet_unchanged() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let own_index = LeafNodeIndex::new(0u32);
    let mut secret_tree = SecretTree::new(
        EncryptionSecret::random(ciphersuite, provider.rand()),
        TreeSize::from_leaf_count(2u32),
        own_index,
    );
    let secret_type = SecretType::ApplicationSecret;
    let (_, sent_secret) = secret_tree
        .secret_for_encryption(ciphersuite, provider.crypto(), own_index, secret_type)
        .unwrap();
    let ratchet = secret_tree.sender_ratchet(own_index, secret_type).cloned();

    for generation in [0, 5] {
        let (_, update) = secret_tree
            .prepare_decryption(
                ciphersuite,
                provider.crypto(),
                own_index,
                secret_type,
                generation,
                configuration,
            )
            .unwrap();
        assert!(update.is_some());
        assert_eq!(
            secret_tree.sender_ratchet(own_index, secret_type),
            ratchet.as_ref()
        );
    }

    let decryption_secret = secret_tree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            own_index,
            secret_type,
            0,
            configuration,
        )
        .unwrap();
    assert_eq!(decryption_secret, DecryptionSecret::Available(sent_secret));
}

// This tests if the generation gets incremented correctly and that the returned
// values are unique.
#[openmls_test::openmls_test]
fn increment_generation() {
    let provider = &Provider::default();

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
                .expect("Index out of bounds.")
                .available()
                .expect("Expected key material of another member.");
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
                .expect("Index out of bounds.")
                .available()
                .expect("Expected key material of another member.");
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

#[openmls_test::openmls_test]
fn secret_tree() {
    let provider = &Provider::default();

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
        .expect("Error getting decryption secret")
        .available()
        .expect("Expected key material of another member.");
    println!(
        "application_secret_key: {:x?}",
        application_secret_key.as_slice()
    );
    println!(
        "application_secret_nonce: {:x?}",
        application_secret_nonce.as_slice()
    );
}
