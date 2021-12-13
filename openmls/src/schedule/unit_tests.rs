//! Key Schedule Unit Tests

use crate::test_utils::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::key_store::OpenMlsKeyStore;
use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};

use crate::{
    ciphersuite::Secret,
    config::Config,
    prelude::{ExternalPsk, PreSharedKeyId, Psk},
    schedule::psk::PskBundle,
};

use super::PskSecret;

#[apply(ciphersuites_and_backends)]
fn test_psks(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Create a new PSK secret from multiple PSKs.
    let prng = backend.rand();

    let psk_ids = (0..33)
        .map(|_| {
            let id = prng.random_vec(12).expect("An unexpected error occurred.");
            PreSharedKeyId::new(
                ciphersuite,
                backend.rand(),
                Psk::External(ExternalPsk::new(id)),
            )
            .expect("An unexpected error occurred.")
        })
        .collect::<Vec<PreSharedKeyId>>();

    for (secret, psk_id) in (0..33)
        .map(|_| {
            Secret::from_slice(
                &prng.random_vec(55).expect("An unexpected error occurred."),
                Config::supported_versions()[0],
                ciphersuite,
            )
        })
        .zip(psk_ids.clone())
    {
        let psk_bundle =
            PskBundle::new(psk_id.clone(), secret).expect("Could not create PskBundle.");
        backend
            .key_store()
            .store(&psk_id, &psk_bundle)
            .expect("An unexpected error occured.");
    }

    let _psk_secret =
        PskSecret::new(ciphersuite, backend, &psk_ids).expect("Could not calculate PSK secret.");
}
