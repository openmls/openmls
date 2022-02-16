//! Unit tests for the ciphersuites.
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

#[apply(ciphersuites_and_backends)]
fn test_sign_verify(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let keypair = SignatureKeypair::new(ciphersuite.signature_algorithm(), backend)
        .expect("An unexpected error occurred.");
    let payload = &[1, 2, 3];
    let signature = keypair
        .sign(backend, payload)
        .expect("An unexpected error occurred.");
    assert!(keypair.verify(backend, &signature, payload).is_ok());
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
        let _signature_keypair = SignatureKeypair::new(ciphersuite.signature_algorithm(), backend)
            .expect("Could not create signature keypair.");
    }

    for ciphersuite in UNSUPPORTED_CIPHERSUITE_NAMES {
        // Create signature keypair
        let _signature_keypair =
            SignatureKeypair::new(SignatureScheme::from(*ciphersuite), backend)
                .expect_err("Could create signature keypair with unsupported ciphersuite.");
    }
}

#[apply(ciphersuites_and_backends)]
fn test_signatures(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Test that valid signatures are properly verified.
    let payload = vec![0u8];
    let signature_scheme =
        SignatureScheme::try_from(ciphersuite).expect("error deriving signature scheme");
    let keypair = SignatureKeypair::new(signature_scheme, backend)
        .expect("error generating signature keypair");
    let mut signature = keypair
        .sign(backend, &payload)
        .expect("error creating signature");
    println!("Done signing payload\n");
    keypair
        .verify(backend, &signature, &payload)
        .expect("error verifying signature");
    println!("Done verifying payload\n");

    // Tamper with signature such that verification fails. We choose a byte
    // somewhere in the middle to make the verification fail, not the DER
    // decoding (in the case of ECDSA signatures).
    let mut modified_signature = signature.as_slice().to_vec();
    modified_signature[20] ^= 0xFF;
    signature.modify(&modified_signature);

    assert_eq!(
        keypair
            .verify(backend, &signature, &payload)
            .expect_err("error verifying signature"),
        CryptoError::InvalidSignature
    );
}
