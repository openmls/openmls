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
    let leaf = 0u32.into();
    let secret = Secret::random(ciphersuite, backend, Config::supported_versions()[0])
        .expect("Not enough randomness.");
    let mut ratchet1 = SenderRatchet::new(leaf, &secret);
    let mut ratchet2 = SenderRatchet::new(leaf, &secret);

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
    let leaf = 0u32.into();
    let secret = Secret::random(ciphersuite, backend, Config::supported_versions()[0])
        .expect("Not enough randomness.");
    let mut ratchet1 = SenderRatchet::new(leaf, &secret);

    // Ratchet forward twice the size of the window
    for i in 0..configuration.out_of_order_tolerance() * 2 {
        let _secret = ratchet1
            .secret_for_decryption(ciphersuite, backend, i, configuration)
            .expect("Expected decryption secret.");
    }

    // Check that secrets from before th window are not accessible anymore
    let err = ratchet1
        .secret_for_decryption(
            ciphersuite,
            backend,
            configuration.out_of_order_tolerance() - 1,
            configuration,
        )
        .expect_err("Expected error.");

    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    // Check that all secrets within the window are accessible
    for i in configuration.out_of_order_tolerance()..configuration.out_of_order_tolerance() * 2 {
        let _secret = ratchet1
            .secret_for_decryption(ciphersuite, backend, i, configuration)
            .expect("Expected decryption secret.");
    }
}

// Test forward secrecy
#[apply(ciphersuites_and_backends)]
fn test_forward_secrecy(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let configuration = &SenderRatchetConfiguration::default();
    let leaf = 0u32.into();
    let secret = Secret::random(ciphersuite, backend, Config::supported_versions()[0])
        .expect("Not enough randomness.");
    let mut ratchet1 = SenderRatchet::new(leaf, &secret);

    // Generate an encryption secret
    let (generation, _encryption_secret) = ratchet1.secret_for_encryption(ciphersuite, backend);

    // We expect this to fail, because we should no longer have the key material for this generation
    let err = ratchet1
        .secret_for_decryption(ciphersuite, backend, generation, configuration)
        .expect_err("Expected error.");

    assert_eq!(err, SecretTreeError::TooDistantInThePast);
}
