//! Unit tests for the ciphersuites.

use super::*;
use crate::config::Config;

// Spot test to make sure hpke seal/open work.
#[test]
fn test_hpke_seal_open() {
    // Test through ciphersuites.
    for &suite in Config::supported_ciphersuites() {
        println!("Test {:?}", suite);
        let ciphersuite = Ciphersuite::new(suite);
        println!("Ciphersuite {:?}", ciphersuite);
        let plaintext = &[1, 2, 3];
        let kp = ciphersuite.derive_hpke_keypair(&[1, 2, 3]);
        let ciphertext = ciphersuite.hpke_seal(kp.public_key(), &[], &[], plaintext);
        let decrypted_payload = ciphersuite.hpke_open(&ciphertext, kp.private_key(), &[], &[]);
        assert_eq!(decrypted_payload, plaintext);
    }
}

#[test]
fn test_sign_verify() {
    for &ciphersuite_name in Config::supported_ciphersuites() {
        let ciphersuite = Ciphersuite::new(ciphersuite_name);
        let keypair = ciphersuite.new_signature_keypair();
        let payload = &[1, 2, 3];
        let signature = keypair.sign(payload).unwrap();
        assert!(keypair.verify(&signature, payload));
    }
}
