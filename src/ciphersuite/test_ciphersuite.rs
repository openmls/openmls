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
        ciphersuite.hpke_seal(kp.get_public_key_ref(), &[], &[], &[1, 2, 3]);
    }
}
