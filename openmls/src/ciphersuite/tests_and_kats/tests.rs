//! Unit tests for the ciphersuites.

use openmls_traits::types::HpkeCiphertext;

use crate::ciphersuite::*;

// Spot test to make sure hpke seal/open work.
#[openmls_test::openmls_test]
fn test_hpke_seal_open() {
    let provider = &Provider::default();

    let plaintext = &[1, 2, 3];
    let kp = provider
        .crypto()
        .derive_hpke_keypair(
            ciphersuite.hpke_config(),
            Secret::random(ciphersuite, provider.rand())
                .expect("Not enough randomness.")
                .as_slice(),
        )
        .expect("error deriving hpke key pair");
    let ciphertext = hpke::encrypt_with_label(
        &kp.public,
        "label",
        &[1, 2, 3],
        plaintext,
        ciphersuite,
        provider.crypto(),
    )
    .unwrap();
    let decrypted_payload = hpke::decrypt_with_label(
        &kp.private,
        "label",
        &[1, 2, 3],
        &ciphertext,
        ciphersuite,
        provider.crypto(),
    )
    .expect("Unexpected error while decrypting a valid ciphertext.");
    assert_eq!(decrypted_payload, plaintext);

    let mut broken_kem_output = ciphertext.kem_output.clone();
    broken_kem_output.pop();
    let mut broken_ciphertext = ciphertext.ciphertext.clone();
    broken_ciphertext.pop();
    let broken_ciphertext1 = HpkeCiphertext {
        kem_output: broken_kem_output,
        ciphertext: ciphertext.ciphertext.clone(),
    };
    let broken_ciphertext2 = HpkeCiphertext {
        kem_output: ciphertext.kem_output,
        ciphertext: broken_ciphertext,
    };
    assert_eq!(
        hpke::decrypt_with_label(
            &kp.private,
            "label",
            &[1, 2, 3],
            &broken_ciphertext1,
            ciphersuite,
            provider.crypto(),
        )
        .map_err(|_| CryptoError::HpkeDecryptionError)
        .expect_err("Erroneously correct ciphertext decryption of broken ciphertext."),
        CryptoError::HpkeDecryptionError
    );
    assert_eq!(
        hpke::decrypt_with_label(
            &kp.private,
            "label",
            &[1, 2, 3],
            &broken_ciphertext2,
            ciphersuite,
            provider.crypto(),
        )
        .map_err(|_| CryptoError::HpkeDecryptionError)
        .expect_err("Erroneously correct ciphertext decryption of broken ciphertext."),
        CryptoError::HpkeDecryptionError
    );
}

// Basic test for aead encrypt/decrypt using the provider.
#[openmls_test::openmls_test]
fn test_aead_encrypt_decrypt() {
    let provider = &Provider::default();
    let aead_algorithm = ciphersuite.aead_algorithm();

    let plaintext = &[1, 2, 3];
    let key = vec![0; aead_algorithm.key_size()];
    let nonce = vec![0; aead_algorithm.nonce_size()];

    let ctxt_tag = provider
        .crypto()
        .aead_encrypt(aead_algorithm, &key, plaintext, &nonce, b"aad")
        .expect("error encrypting");

    let plaintext_out = provider
        .crypto()
        .aead_decrypt(aead_algorithm, &key, &ctxt_tag, &nonce, b"aad")
        .expect("error decrypting");
    assert_eq!(plaintext_out, plaintext);
}
