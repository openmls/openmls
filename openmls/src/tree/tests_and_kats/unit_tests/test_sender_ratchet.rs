use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    ciphersuite::Secret, config::Config, test_utils::*, tree::secret_tree::SecretTreeError,
    tree::sender_ratchet::*,
};

// Test the maximum forward ratcheting
#[apply(ciphersuites_and_backends)]
fn test_max_forward_distance(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, backend, Config::supported_versions()[0])
        .expect("Not enough randomness.");
    let mut ratchet1 = DecryptionRatchet::new(&secret);
    let mut ratchet2 = DecryptionRatchet::new(&secret);

    // We expect this to still work
    let _secret = ratchet1
        .secret_for_decryption(
            ciphersuite,
            backend,
            configuration.maximum_forward_distance(),
            configuration,
        )
        .expect("Expected decryption secret.");

    // We expect this to return an error
    let err = ratchet2
        .secret_for_decryption(
            ciphersuite,
            backend,
            configuration.maximum_forward_distance() + 1,
            configuration,
        )
        .expect_err("Expected error.");

    assert_eq!(err, SecretTreeError::TooDistantInTheFuture);
}

// Test out-of-order generations
#[apply(ciphersuites_and_backends)]
fn test_out_of_order_generations(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, backend, Config::supported_versions()[0])
        .expect("Not enough randomness.");
    let mut ratchet1 = DecryptionRatchet::new(&secret);

    // Ratchet forward twice the size of the window
    for i in 0..configuration.out_of_order_tolerance() * 2 {
        let _secret = ratchet1
            .secret_for_decryption(ciphersuite, backend, i, configuration)
            .expect("Expected decryption secret.");
    }

    // Check that secrets from before the window are not accessible anymore
    let err = ratchet1
        .secret_for_decryption(
            ciphersuite,
            backend,
            configuration.out_of_order_tolerance() - 1,
            configuration,
        )
        .expect_err("Expected error.");

    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    // All secrets within the window should have been deleted because of FS.
    for i in configuration.out_of_order_tolerance()..configuration.out_of_order_tolerance() * 2 {
        assert_eq!(
            ratchet1
                .secret_for_decryption(ciphersuite, backend, i, configuration)
                .expect_err("Expected decryption secret."),
            SecretTreeError::SecretReuseError
        );
    }
}

// Test forward secrecy
#[apply(ciphersuites_and_backends)]
fn test_forward_secrecy(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Encryption Ratchets are forward-secret by default, since they don't store
    // any keys. Thus, we can only test FS on Decryption Ratchets.
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, backend, Config::supported_versions()[0])
        .expect("Not enough randomness.");
    let mut ratchet = DecryptionRatchet::new(&secret);

    // Let's ratchet once and see if the ratchet keeps any keys around.
    let _ratchet_secrets = ratchet
        .secret_for_decryption(ciphersuite, backend, 0, configuration)
        .expect("Error ratcheting forward.");

    // The generation should have increased.
    assert_eq!(ratchet.generation(), 1);

    // And we should get an error for generation 0.
    let err = ratchet
        .secret_for_decryption(ciphersuite, backend, 0, configuration)
        .expect_err("No error when trying to retrieve key outside of tolerance window.");
    assert_eq!(err, SecretTreeError::SecretReuseError);

    // Let's ratchet forward a few times, making the ratchet keep the secrets round for out-of-order decryption.
    let _ratchet_secrets = ratchet
        .secret_for_decryption(ciphersuite, backend, 10, configuration)
        .expect("Error ratcheting forward.");

    // First, let's make sure that the window works.
    let err = ratchet
        .secret_for_decryption(ciphersuite, backend, 5, configuration)
        .expect_err("No error when trying to retrieve key outside of tolerance window.");
    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    // Now let's get a few keys. The first time we're trying to get the key of a given generation, it should work. The second time, we should get a SecretReuseError.
    for generation in 10 - configuration.out_of_order_tolerance() + 1..10 {
        let keys = ratchet.secret_for_decryption(ciphersuite, backend, generation, configuration);
        assert!(keys.is_ok());

        let err = ratchet
            .secret_for_decryption(ciphersuite, backend, generation, configuration)
            .expect_err("No error when trying to retrieve deleted key.");
        assert_eq!(err, SecretTreeError::SecretReuseError);
    }
}
