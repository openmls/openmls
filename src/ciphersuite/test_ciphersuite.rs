//! Unit tests for the ciphersuites.

use crate::config::Config;

use super::Secret;

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
        let decrypted_payload = ciphersuite.hpke_open(&ciphertext, kp.private_key(), &[], &[]);
        assert_eq!(decrypted_payload, plaintext);
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
