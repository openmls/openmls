//! Unit tests for the ciphersuites.

use super::*;
use crate::config::Config;

// Spot test to make sure hpke seal works.
#[test]
fn test_hpke_seal() {
    // Test through ciphersuites.
    for &suite in Config::supported_ciphersuites() {
        println!("Test {:?}", suite);
        let ciphersuite = Ciphersuite::new(suite);
        println!("Ciphersuite {:?}", ciphersuite);
        let kp = ciphersuite.derive_hpke_keypair(&[1, 2, 3]);
        ciphersuite.hpke_seal(kp.public_key(), &[], &[], &[1, 2, 3]);
    }
}

#[test]
fn test_sign_verify() {
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let keypair = ciphersuite.new_signature_keypair();
    let payload = &[1, 2, 3];
    let signature = keypair.sign(payload).unwrap();
    assert!(keypair.verify(&signature, payload));
}
