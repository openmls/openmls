//! ## Pre-Shared Keys
//!
//! Parameters:
//! * Ciphersuite
//! * Number of PreSharedKeys
//!
//! Format:
//! ```text
//! {
//!   "cipher_suite": /* uint16 */,
//!
//!   // Chosen by the generator
//!   "psks": [
//!     {
//!       "psk_id": /* hex-encoded binary data */,
//!       "psk": /* hex-encoded binary data */,
//!       "psk_nonce": /* hex-encoded binary data */,
//!     },
//!     ...
//!   ],
//!
//!   // Computed values
//!   "psk_secret": /* hex-encoded binary data */,
//! }
//! ```
//!
//! Verification:
//!
//! * For each PreSharedKey in psks, compute PreSharedKeyID with external
//!   PSKType and with provided psk_id and psk_nonce
//! * Use the computed PreSharedKeyID values and provided psk values to compute
//!   the psk_secret as described in the specification and verify that it
//!   matches the provided psk_secret

use openmls_traits::crypto::OpenMlsCrypto;
use serde::Deserialize;

use crate::{
    schedule::psk::{
        load_psks, store::ResumptionPskStore, ExternalPsk, PreSharedKeyId, Psk, PskSecret,
    },
    test_utils::*,
};

#[derive(Deserialize)]
struct PskElement {
    #[serde(with = "hex")]
    psk_id: Vec<u8>,
    #[serde(with = "hex")]
    psk: Vec<u8>,
    #[serde(with = "hex")]
    psk_nonce: Vec<u8>,
}

#[derive(Deserialize)]
struct TestElement {
    cipher_suite: u16,
    psks: Vec<PskElement>,
    #[serde(with = "hex")]
    psk_secret: Vec<u8>,
}

fn run_test_vector(test: TestElement, provider: &impl OpenMlsProvider) -> Result<(), String> {
    let ciphersuite = Ciphersuite::try_from(test.cipher_suite).unwrap();
    // Skip unsupported ciphersuites.
    if !provider
        .crypto()
        .supported_ciphersuites()
        .contains(&ciphersuite)
    {
        log::debug!("Unsupported ciphersuite {0:?} ...", test.cipher_suite);
        return Ok(());
    }

    let psk_ids = test
        .psks
        .iter()
        .map(|psk| {
            let external_psk = ExternalPsk::new(psk.psk_id.clone());
            let psk_type = Psk::External(external_psk);

            let psk_id = PreSharedKeyId::new_with_nonce(psk_type, psk.psk_nonce.clone());

            psk_id.store(provider, &psk.psk).unwrap();
            psk_id
        })
        .collect::<Vec<_>>();

    // Prepare the PskSecret
    let psk_secret = {
        let resumption_psk_store = ResumptionPskStore::new(1024);

        let psks = load_psks(provider.storage(), &resumption_psk_store, &psk_ids).unwrap();

        PskSecret::new(provider.crypto(), ciphersuite, psks).unwrap()
    };

    if psk_secret.secret().as_slice() == test.psk_secret {
        Ok(())
    } else {
        Err("PSK secret does not match expected value.".to_string())
    }
}

#[openmls_test::openmls_test]
fn read_test_vectors_ps() {
    let _ = pretty_env_logger::try_init();
    log::debug!("Reading test vectors ...");

    let tests: Vec<TestElement> = read_json!("../../../../test_vectors/psk_secret.json");

    for test_vector in tests {
        match run_test_vector(test_vector, provider) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking PSK secret test vector.\n{e:?}"),
        }
    }
    log::trace!("Finished test vector verification");
}
