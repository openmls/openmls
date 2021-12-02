use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::tree::sender_ratchet::SenderRatchet;

use crate::config::Config;
use crate::prelude::{LeafIndex, Secret};

#[test]
fn test_ratchet_generations() {
    let crypto = &OpenMlsRustCrypto::default();

    for ciphersuite in Config::supported_ciphersuites() {
        let leaf0 = 0u32.into();
        let secret = Secret::random(ciphersuite, crypto, Config::supported_versions()[0])
            .expect("Not enough randomness.");
        let mut linear_ratchet = SenderRatchet::new(leaf0, &secret);
        let mut testratchet = SenderRatchet::new(leaf0, &secret);

        let _ = linear_ratchet.secret_for_decryption(ciphersuite, crypto, 0);
        let _ = linear_ratchet.secret_for_decryption(ciphersuite, crypto, 1);
        let secret = linear_ratchet
            .secret_for_decryption(ciphersuite, crypto, 2)
            .expect("Could not derive the secret.");
        // jump 2 generations instead of going one by one
        let secret2 = testratchet
            .secret_for_decryption(ciphersuite, crypto, 2)
            .expect("Could not derive the secret.");
        /* We should have the same secret */
        assert_eq!(secret, secret2);
    }
}
