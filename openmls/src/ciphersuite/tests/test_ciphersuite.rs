//! Unit tests for the ciphersuites.
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::HpkeCiphertext;

use crate::{ciphersuite::*, test_utils::*};

// Spot test to make sure hpke seal/open work.
#[apply(ciphersuites_and_backends)]
fn test_hpke_seal_open(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let plaintext = &[1, 2, 3];
    let kp = backend.crypto().derive_hpke_keypair(
        ciphersuite.hpke_config(),
        Secret::random(ciphersuite, backend, None)
            .expect("Not enough randomness.")
            .as_slice(),
    );
    let ciphertext =
        backend
            .crypto()
            .hpke_seal(ciphersuite.hpke_config(), &kp.public, &[], &[], plaintext);
    let decrypted_payload = backend
        .crypto()
        .hpke_open(
            ciphersuite.hpke_config(),
            &ciphertext,
            &kp.private,
            &[],
            &[],
        )
        .expect("Unexpected error while decrypting a valid ciphertext.");
    assert_eq!(decrypted_payload, plaintext);

    let mut broken_kem_output = ciphertext.kem_output.clone();
    broken_kem_output.pop();
    let mut broken_ciphertext = ciphertext.ciphertext.clone();
    broken_ciphertext.pop();
    let broken_ciphertext1 = HpkeCiphertext {
        kem_output: broken_kem_output,
        ciphertext: ciphertext.ciphertext.clone(),
    };
    let broken_ciphertext2 = HpkeCiphertext {
        kem_output: ciphertext.kem_output,
        ciphertext: broken_ciphertext,
    };
    assert_eq!(
        backend
            .crypto()
            .hpke_open(
                ciphersuite.hpke_config(),
                &broken_ciphertext1,
                &kp.private,
                &[],
                &[]
            )
            .map_err(|_| CryptoError::HpkeDecryptionError)
            .expect_err("Erroneously correct ciphertext decryption of broken ciphertext."),
        CryptoError::HpkeDecryptionError
    );
    assert_eq!(
        backend
            .crypto()
            .hpke_open(
                ciphersuite.hpke_config(),
                &broken_ciphertext2,
                &kp.private,
                &[],
                &[]
            )
            .map_err(|_| CryptoError::HpkeDecryptionError)
            .expect_err("Erroneously correct ciphertext decryption of broken ciphertext."),
        CryptoError::HpkeDecryptionError
    );
}

#[apply(backends)]
fn supported_ciphersuites(backend: &impl OpenMlsCryptoProvider) {
    const SUPPORTED_CIPHERSUITE_NAMES: &[Ciphersuite] = &[
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    ];

    const UNSUPPORTED_CIPHERSUITE_NAMES: &[Ciphersuite] = &[
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
        Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
        Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
    ];

    for ciphersuite in SUPPORTED_CIPHERSUITE_NAMES {
        // Create signature keypair
        let _signature_keypair =
            SignatureKeyPair::new(ciphersuite.signature_algorithm(), backend.crypto())
                .expect("Could not create signature keypair.");
    }

    for ciphersuite in UNSUPPORTED_CIPHERSUITE_NAMES {
        // Create signature keypair
        let _signature_keypair =
            SignatureKeyPair::new(SignatureScheme::from(*ciphersuite), backend.crypto())
                .expect_err("Could create signature keypair with unsupported ciphersuite.");
    }
}
