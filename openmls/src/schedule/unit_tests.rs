//! Key Schedule Unit Tests

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{random::OpenMlsRand, OpenMlsProvider};

use super::PskSecret;
use crate::{
    ciphersuite::Secret,
    schedule::psk::{store::ResumptionPskStore, *},
    test_utils::*,
    versions::ProtocolVersion,
};

#[apply(ciphersuites_and_providers)]
fn test_psks(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // Create a new PSK secret from multiple PSKs.
    let prng = provider.rand();

    let psk_ids = (0..33)
        .map(|_| {
            let id = prng.random_vec(12).expect("An unexpected error occurred.");
            PreSharedKeyId::new(
                ciphersuite,
                provider.rand(),
                Psk::External(ExternalPsk::new(id)),
            )
            .expect("An unexpected error occurred.")
        })
        .collect::<Vec<PreSharedKeyId>>();

    for (secret, psk_id) in (0..33)
        .map(|_| {
            Secret::from_slice(
                &prng.random_vec(55).expect("An unexpected error occurred."),
                ProtocolVersion::Mls10,
                ciphersuite,
            )
        })
        .zip(psk_ids.clone())
    {
        psk_id
            .write_to_key_store(provider, ciphersuite, secret.as_slice())
            .unwrap();
    }

    let _psk_secret = {
        let resumption_psk_store = ResumptionPskStore::new(1024);

        let psks = load_psks(provider.key_store(), &resumption_psk_store, &psk_ids).unwrap();

        PskSecret::new(provider.crypto(), ciphersuite, psks).unwrap()
    };
}
