//! Key Schedule Unit Tests

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};

use crate::{
    ciphersuite::Secret,
    config::Config,
    prelude::{ExternalPsk, PreSharedKeyId, Psk, PskType},
};

use super::PskSecret;

#[test]
fn test_psks() {
    // Create a new PSK secret from multiple PSKs.
    let backend = OpenMlsRustCrypto::default();
    let prng = backend.rand();
    for ciphersuite in Config::supported_ciphersuites() {
        let psks = &vec![0u8; 33]
            .iter()
            .map(|_| {
                Secret::from_slice(
                    &prng.random_vec(55).unwrap(),
                    Config::supported_versions()[0],
                    ciphersuite,
                )
            })
            .collect::<Vec<Secret>>();
        let psk_ids = &vec![0u8; 33]
            .iter()
            .map(|_| {
                let id = prng.random_vec(12).unwrap();
                let nonce = prng.random_vec(17).unwrap();
                PreSharedKeyId::new(
                    PskType::External,
                    Psk::External(ExternalPsk::new(id)),
                    nonce,
                )
            })
            .collect::<Vec<PreSharedKeyId>>();
        let psk_secret = PskSecret::new(ciphersuite, &backend, psk_ids, psks)
            .expect("Could not calculate PSK secret.");
    }
}
