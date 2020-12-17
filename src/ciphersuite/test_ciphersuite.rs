//! Unit tests for the ciphersuites.

use crate::ciphersuite::CryptoError;
use crate::config::Config;

use super::{HpkeCiphertext, Secret};

// Spot test to make sure hpke seal/open work.
#[test]
fn test_hpke_seal_open() {
    // Test through ciphersuites.
    for ciphersuite in Config::supported_ciphersuites() {
        println!("Test {:?}", ciphersuite.name());
        println!("Ciphersuite {:?}", ciphersuite);
        let plaintext = &[1, 2, 3];
        let kp = ciphersuite.derive_hpke_keypair(&Secret::from(vec![1, 2, 3]));
        let ciphertext = ciphersuite.hpke_seal(kp.public_key(), &[], &[], plaintext);
        let decrypted_payload = ciphersuite
            .hpke_open(&ciphertext, kp.private_key(), &[], &[])
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
            kem_output: ciphertext.kem_output.clone(),
            ciphertext: broken_ciphertext,
        };
        assert_eq!(
            ciphersuite
                .hpke_open(&broken_ciphertext1, kp.private_key(), &[], &[])
                .expect_err("Erroneously correct ciphertext decryption of broken ciphertext."),
            CryptoError::HpkeDecryptionError
        );
        assert_eq!(
            ciphersuite
                .hpke_open(&broken_ciphertext2, kp.private_key(), &[], &[])
                .expect_err("Erroneously correct ciphertext decryption of broken ciphertext."),
            CryptoError::HpkeDecryptionError
        );
    }
}

#[test]
fn test_sign_verify() {
    for ciphersuite in Config::supported_ciphersuites() {
        let keypair = ciphersuite.new_signature_keypair().unwrap();
        let payload = &[1, 2, 3];
        let signature = keypair.sign(payload).unwrap();
        assert!(keypair.verify(&signature, payload));
    }
}
