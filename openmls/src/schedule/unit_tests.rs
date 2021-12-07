//! Key Schedule Unit Tests

use crate::test_utils::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};

use crate::{
    ciphersuite::Secret,
    config::Config,
    prelude::{ExternalPsk, PreSharedKeyId, Psk, PskType},
};

use super::PskSecret;

#[apply(ciphersuites_and_backends)]
fn test_psks(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Create a new PSK secret from multiple PSKs.
    let prng = backend.rand();
    let psks = &vec![0u8; 33]
        .iter()
        .map(|_| {
            Secret::from_slice(
                &prng.random_vec(55).expect("An unexpected error occurred."),
                Config::supported_versions()[0],
                ciphersuite,
            )
        })
        .collect::<Vec<Secret>>();
    let psk_ids = &vec![0u8; 33]
        .iter()
        .map(|_| {
            let id = prng.random_vec(12).expect("An unexpected error occurred.");
            let nonce = prng.random_vec(17).expect("An unexpected error occurred.");
            PreSharedKeyId::new(
                PskType::External,
                Psk::External(ExternalPsk::new(id)),
                nonce,
            )
        })
        .collect::<Vec<PreSharedKeyId>>();
    let _psk_secret = PskSecret::new(ciphersuite, backend, psk_ids, psks)
        .expect("Could not calculate PSK secret.");
}
