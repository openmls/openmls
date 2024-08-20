//! Key Schedule Unit Tests

use openmls_traits::{random::OpenMlsRand, OpenMlsProvider};

use crate::{
    ciphersuite::Secret,
    schedule::psk::{store::ResumptionPskStore, PskSecret, *},
};

#[openmls_test::openmls_test]
fn test_psks() {
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
        .map(|_| Secret::from_slice(&prng.random_vec(55).expect("An unexpected error occurred.")))
        .zip(psk_ids.clone())
    {
        psk_id.store(provider, secret.as_slice()).unwrap();
    }

    let _psk_secret = {
        let resumption_psk_store = ResumptionPskStore::new(1024);

        let psks = load_psks(provider.storage(), &resumption_psk_store, &psk_ids).unwrap();

        PskSecret::new(provider.crypto(), ciphersuite, psks).unwrap()
    };
}
