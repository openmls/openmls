//! Key Schedule Unit Tests

use openmls_traits::random::OpenMlsRand;

use crate::{
    ciphersuite::Secret,
    group::GroupId,
    schedule::{
        psk::{store::ResumptionPskStore, PskSecret, *},
        ResumptionPskSecret,
    },
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

        let psks = load_psks(
            provider.storage(),
            &resumption_psk_store,
            None,
            None,
            &psk_ids,
        )
        .unwrap();

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

    let psks = load_psks(
        provider.storage(),
        &resumption_psk_store,
        None,
        None,
        &psk_ids,
    )
    .unwrap();
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
            None,
            None,
            std::slice::from_ref(&unknown_psk_id),
        )
        .unwrap_err(),
        PskError::KeyNotFound
    );
}

#[openmls_test::openmls_test]
fn test_psks_resumption_application_no_group() {
    use crate::schedule::errors::PskError;

    let provider = &Provider::default();

    let group_id = GroupId::from_slice(b"A");
    let epoch = 1.into();

    let psk_ids = vec![PreSharedKeyId::new(
        ciphersuite,
        provider.rand(),
        Psk::Resumption(ResumptionPsk::new(
            ResumptionPskUsage::Application,
            group_id.clone(),
            epoch,
        )),
    )
    .unwrap()];

    let resumption_psk = ResumptionPskSecret {
        secret: Secret::from_slice(b"secret"),
    };
    let mut resumption_psk_store = ResumptionPskStore::new(1024);
    resumption_psk_store.add(epoch, resumption_psk);

    // Works if `group_id` is `Some`
    load_psks(
        provider.storage(),
        &resumption_psk_store,
        Some(&group_id),
        None,
        &psk_ids,
    )
    .expect("Expected secret to be loaded");

    // Not allowed if `group_id` is `None`
    let error = load_psks(
        provider.storage(),
        &resumption_psk_store,
        None,
        None,
        &psk_ids,
    )
    .expect_err("expected resumption usage application without group to fail");
    assert_eq!(error, PskError::NotAllowed);
}

#[openmls_test::openmls_test]
fn test_psks_resumption_application_other_group() {
    use crate::schedule::errors::PskError;

    let provider = &Provider::default();

    let group_id = GroupId::from_slice(b"A");
    let other_group_id = GroupId::from_slice(b"B");

    let psk_ids = vec![PreSharedKeyId::new(
        ciphersuite,
        provider.rand(),
        Psk::Resumption(ResumptionPsk::new(
            ResumptionPskUsage::Application,
            other_group_id.clone(),
            1.into(),
        )),
    )
    .unwrap()];

    let resumption_psk_store = ResumptionPskStore::new(1024);

    let error = load_psks(
        provider.storage(),
        &resumption_psk_store,
        Some(&group_id),
        None,
        &psk_ids,
    )
    .expect_err("expected resumption usage application from other group to fail");
    assert_eq!(
        error,
        PskError::DifferentGroupId {
            expected: group_id,
            got: other_group_id
        }
    );
}
