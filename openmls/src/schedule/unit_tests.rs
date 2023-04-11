//! Key Schedule Unit Tests

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};

use super::PskSecret;
use crate::{ciphersuite::Secret, schedule::psk::*, test_utils::*, versions::ProtocolVersion};

#[apply(ciphersuites_and_backends)]
fn test_psks(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
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
                ProtocolVersion::Mls10,
                ciphersuite,
            )
        })
        .zip(psk_ids.clone())
    {
        psk_id
            .write_to_key_store(backend, ciphersuite, secret.as_slice())
            .unwrap();
    }

    let _psk_secret =
        PskSecret::new(ciphersuite, backend, &psk_ids).expect("Could not calculate PSK secret.");
}
