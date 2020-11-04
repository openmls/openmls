//! Unit tests for the ciphersuites.

use super::*;
use crate::config::Config;

// Spot test to make sure hpke seal/open work.
#[test]
fn test_hpke_seal_open() {
    // Test through ciphersuites.
    for ciphersuite in Config::supported_ciphersuites() {
        println!("Test {:?}", ciphersuite.name());
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
    let ciphersuite =
        Config::ciphersuite(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
            .unwrap();
    let keypair = ciphersuite.new_signature_keypair();
    let payload = &[1, 2, 3];
    let signature = keypair.sign(payload).unwrap();
    assert!(keypair.verify(&signature, payload));
}
