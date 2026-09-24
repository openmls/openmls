//! Key Schedule Unit Tests

use openmls_traits::random::OpenMlsRand;

use crate::{
    ciphersuite::Secret,
    schedule::psk::{store::ResumptionPskStore, PskSecret, *},
};

#[openmls_test::openmls_test]
fn test_psks() {
    let provider = &Provider::default();

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

#[cfg(feature = "extensions-draft")]
#[openmls_test::openmls_test]
fn test_application_psks() {
    use tls_codec::{Deserialize as _, Serialize as _};

    use crate::schedule::errors::PskError;

    let provider = &Provider::default();
    let prng = provider.rand();

    // Create application PSK ids for different components.
    let psk_ids = (0..7)
        .map(|component_id| {
            let id = prng.random_vec(12).expect("An unexpected error occurred.");
            PreSharedKeyId::new(
                ciphersuite,
                provider.rand(),
                Psk::Application(ApplicationPsk::new(component_id, id.into())),
            )
            .expect("An unexpected error occurred.")
        })
        .collect::<Vec<PreSharedKeyId>>();

    for (component_id, psk_id) in psk_ids.iter().enumerate() {
        // The accessors return the values the PSK was created from.
        let Psk::Application(application_psk) = psk_id.psk() else {
            panic!("Expected an application PSK.");
        };
        assert_eq!(application_psk.component_id(), component_id as u16);
        assert_eq!(application_psk.psk_id().len(), 12);

        // An application PSK id serializes with PSKType `application(3)` and
        // round-trips through the TLS codec.
        let serialized = psk_id
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");
        assert_eq!(serialized[0], 3);
        let deserialized = PreSharedKeyId::tls_deserialize_exact(serialized.as_slice())
            .expect("An unexpected error occurred.");
        assert_eq!(&deserialized, psk_id);
    }

    // Store the PSKs and create a new PSK secret from them.
    for psk_id in &psk_ids {
        let secret =
            Secret::from_slice(&prng.random_vec(55).expect("An unexpected error occurred."));
        psk_id.store(provider, secret.as_slice()).unwrap();
    }

    let resumption_psk_store = ResumptionPskStore::new(1024);

    let psks = load_psks(provider.storage(), &resumption_psk_store, &psk_ids).unwrap();
    PskSecret::new(provider.crypto(), ciphersuite, psks).unwrap();

    // Loading an application PSK that is not in storage fails.
    let unknown_psk_id = PreSharedKeyId::new(
        ciphersuite,
        provider.rand(),
        Psk::Application(ApplicationPsk::new(0x8000, b"unknown".to_vec().into())),
    )
    .expect("An unexpected error occurred.");
    assert_eq!(
        load_psks(
            provider.storage(),
            &resumption_psk_store,
            std::slice::from_ref(&unknown_psk_id),
        )
        .unwrap_err(),
        PskError::KeyNotFound
    );
}
