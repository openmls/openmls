use crate::{
    ciphersuite::Secret, test_utils::*, tree::secret_tree::SecretTreeError, tree::sender_ratchet::*,
};

// Test the maximum forward ratcheting
#[openmls_test::openmls_test]
fn test_max_forward_distance() {
    let provider = &Provider::default();

    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet1 = DecryptionRatchet::new(secret.clone());
    let mut ratchet2 = DecryptionRatchet::new(secret);

    // We expect this to still work
    let _secret = ratchet1
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            configuration.maximum_forward_distance(),
            configuration,
        )
        .expect("Expected decryption secret.");

    // We expect this to return an error
    let err = ratchet2
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            configuration.maximum_forward_distance() + 1,
            configuration,
        )
        .expect_err("Expected error.");

    assert_eq!(err, SecretTreeError::TooDistantInTheFuture);

    // Test if there's an overflow in the maximum forward distance check.
    ratchet1.ratchet_secret_mut().set_generation(u32::MAX - 5);
    ratchet1
        .secret_for_decryption(ciphersuite, provider.crypto(), u32::MAX - 1, configuration)
        .expect("Error ratcheting to very high generation");
}

// Test out-of-order generations
#[openmls_test::openmls_test]
fn test_out_of_order_generations() {
    let provider = &Provider::default();

    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet1 = DecryptionRatchet::new(secret);

    // Ratchet forward twice the size of the window
    for i in 0..configuration.out_of_order_tolerance() * 2 {
        let _secret = ratchet1
            .secret_for_decryption(ciphersuite, provider.crypto(), i, configuration)
            .expect("Expected decryption secret.");
    }

    // Check that secrets from before the window are not accessible anymore
    let err = ratchet1
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            configuration.out_of_order_tolerance() - 1,
            configuration,
        )
        .expect_err("Expected error.");

    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    // All secrets within the window should have been deleted because of FS.
    for i in configuration.out_of_order_tolerance()..configuration.out_of_order_tolerance() * 2 {
        assert_eq!(
            ratchet1
                .secret_for_decryption(ciphersuite, provider.crypto(), i, configuration)
                .expect_err("Expected decryption secret."),
            SecretTreeError::SecretReuseError
        );
    }
}

// Test forward secrecy
#[openmls_test::openmls_test]
fn test_forward_secrecy() {
    let provider = &Provider::default();

    // Encryption Ratchets are forward-secret by default, since they don't store
    // any keys. Thus, we can only test FS on Decryption Ratchets.
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DecryptionRatchet::new(secret);

    // Let's ratchet once and see if the ratchet keeps any keys around.
    let _ratchet_secrets = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 0, configuration)
        .expect("Error ratcheting forward.");

    // The generation should have increased.
    assert_eq!(ratchet.generation(), 1);

    // And we should get an error for generation 0.
    let err = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 0, configuration)
        .expect_err("No error when trying to retrieve key outside of tolerance window.");
    assert_eq!(err, SecretTreeError::SecretReuseError);

    // Let's ratchet forward a few times, making the ratchet keep the secrets round for out-of-order decryption.
    let _ratchet_secrets = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 10, configuration)
        .expect("Error ratcheting forward.");

    // First, let's make sure that the window works.
    let err = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 5, configuration)
        .expect_err("No error when trying to retrieve key outside of tolerance window.");
    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    // Now let's get a few keys. The first time we're trying to get the key of a given generation, it should work. The second time, we should get a SecretReuseError.
    for generation in 10 - configuration.out_of_order_tolerance() + 1..10 {
        let keys = ratchet.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            generation,
            configuration,
        );
        assert!(keys.is_ok());

        let err = ratchet
            .secret_for_decryption(ciphersuite, provider.crypto(), generation, configuration)
            .expect_err("No error when trying to retrieve deleted key.");
        assert_eq!(err, SecretTreeError::SecretReuseError);
    }
}

// Test if a sender ratchet overflow is caught
#[test]
fn sender_ratchet_generation_overflow() {
    let provider = OpenMlsRustCrypto::default();
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = RatchetSecret::initial_ratchet_secret(secret);
    ratchet.set_generation(u32::MAX - 1);
    let _ = ratchet
        .ratchet_forward(provider.crypto(), ciphersuite)
        .expect("error ratcheting forward");
    let err = ratchet
        .ratchet_forward(provider.crypto(), ciphersuite)
        .expect_err("no error exceeding generation u32::MAX");
    assert_eq!(err, SecretTreeError::RatchetTooLong)
}

#[openmls_test::openmls_test]
fn decryption_follows_the_ratchet_chain() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut chain = RatchetSecret::initial_ratchet_secret(secret.clone());
    let chain_keys: Vec<_> = (0..=10)
        .map(|_| {
            chain
                .ratchet_forward(provider.crypto(), ciphersuite)
                .unwrap()
                .1
        })
        .collect();
    let mut ratchet = DecryptionRatchet::new(secret);

    let cases = [
        (0, None),
        (3, None),
        (4, None),
        (1, None),
        (1, Some(SecretTreeError::SecretReuseError)),
        (2, None),
        (10, None),
        (2, Some(SecretTreeError::TooDistantInThePast)),
        (2_000, Some(SecretTreeError::TooDistantInTheFuture)),
    ];
    for (generation, expected_error) in cases {
        let result = ratchet.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            generation,
            configuration,
        );
        match expected_error {
            Some(error) => assert_eq!(result, Err(error), "generation {generation}"),
            None => assert_eq!(
                result,
                Ok(chain_keys[generation as usize].clone()),
                "generation {generation}"
            ),
        }
    }
}

#[openmls_test::openmls_test]
fn peek_leaves_decryption_ratchet_unchanged() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DecryptionRatchet::new(secret);
    ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 3, configuration)
        .unwrap();
    let unchanged = ratchet.clone();

    for generation in [1, 7] {
        let (first_secret, _) = ratchet
            .peek(ciphersuite, provider.crypto(), generation, configuration)
            .unwrap();
        let (second_secret, _) = ratchet
            .peek(ciphersuite, provider.crypto(), generation, configuration)
            .unwrap();
        assert_eq!(first_secret, second_secret);
        assert_eq!(ratchet, unchanged);
    }
}

#[openmls_test::openmls_test]
fn stale_peeked_generation_is_rejected() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DecryptionRatchet::new(secret);

    let (_, forward) = ratchet
        .peek(ciphersuite, provider.crypto(), 5, configuration)
        .unwrap();
    let (_, other_forward) = ratchet
        .peek(ciphersuite, provider.crypto(), 6, configuration)
        .unwrap();
    ratchet.consume(forward, configuration).unwrap();
    assert_eq!(
        ratchet.consume(other_forward, configuration),
        Err(SecretTreeError::LibraryError)
    );

    let (_, past) = ratchet
        .peek(ciphersuite, provider.crypto(), 2, configuration)
        .unwrap();
    let (_, same_past) = ratchet
        .peek(ciphersuite, provider.crypto(), 2, configuration)
        .unwrap();
    ratchet.consume(past, configuration).unwrap();
    assert_eq!(
        ratchet.consume(same_past, configuration),
        Err(SecretTreeError::SecretReuseError)
    );
}
