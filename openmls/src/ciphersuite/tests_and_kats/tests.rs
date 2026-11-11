//! Unit tests for the ciphersuites.

use openmls_traits::types::HpkeCiphertext;

use crate::ciphersuite::*;

// Spot test to make sure hpke seal/open work.
#[openmls_test::openmls_test]
fn test_hpke_seal_open() {
    let provider = &Provider::default();

    let plaintext = &[1, 2, 3];
    let kp = provider
        .crypto()
        .derive_hpke_keypair(
            ciphersuite.hpke_config(),
            Secret::random(ciphersuite, provider.rand())
                .expect("Not enough randomness.")
                .as_slice(),
        )
        .expect("error deriving hpke key pair");
    let ciphertext = hpke::encrypt_with_label(
        &kp.public,
        "label",
        &[1, 2, 3],
        plaintext,
        ciphersuite,
        provider.crypto(),
    )
    .unwrap();
    let decrypted_payload = hpke::decrypt_with_label(
        &kp.private,
        "label",
        &[1, 2, 3],
        &ciphertext,
        ciphersuite,
        provider.crypto(),
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
        hpke::decrypt_with_label(
            &kp.private,
            "label",
            &[1, 2, 3],
            &broken_ciphertext1,
            ciphersuite,
            provider.crypto(),
        )
        .map_err(|_| CryptoError::HpkeDecryptionError)
        .expect_err("Erroneously correct ciphertext decryption of broken ciphertext."),
        CryptoError::HpkeDecryptionError
    );
    assert_eq!(
        hpke::decrypt_with_label(
            &kp.private,
            "label",
            &[1, 2, 3],
            &broken_ciphertext2,
            ciphersuite,
            provider.crypto(),
        )
        .map_err(|_| CryptoError::HpkeDecryptionError)
        .expect_err("Erroneously correct ciphertext decryption of broken ciphertext."),
        CryptoError::HpkeDecryptionError
    );
}

// Spot test for safe hpke seal/open.
#[cfg(feature = "extensions-draft")]
#[openmls_test::openmls_test]
fn test_safe_hpke_seal_open() {
    use crate::component::ComponentId;

    let provider = &Provider::default();

    const CONTEXT: &[u8] = &[1, 2, 3];
    const LABEL: &str = "label";

    let plaintext = &[1, 2, 3];
    let kp = provider
        .crypto()
        .derive_hpke_keypair(
            ciphersuite.hpke_config(),
            Secret::random(ciphersuite, provider.rand())
                .expect("Not enough randomness.")
                .as_slice(),
        )
        .expect("error deriving hpke key pair");

    const COMPONENT_ID: ComponentId = 1;

    let ciphertext = hpke::safe_encrypt_with_label(
        &kp.public,
        plaintext,
        ciphersuite,
        SafeEncryptionContext {
            component_id: COMPONENT_ID,
            label: LABEL,
            context: CONTEXT,
        },
        provider.crypto(),
    )
    .unwrap();
    let decrypted_payload = hpke::safe_decrypt_with_label(
        &kp.private,
        &ciphertext,
        ciphersuite,
        SafeEncryptionContext {
            component_id: COMPONENT_ID,
            label: LABEL,
            context: CONTEXT,
        },
        provider.crypto(),
    )
    .expect("Unexpected error while decrypting a valid ciphertext.");
    assert_eq!(decrypted_payload, plaintext);

    let mut broken_kem_output: Vec<u8> = ciphertext.kem_output.clone().into();
    broken_kem_output[0] ^= 0xff;
    let mut broken_ciphertext: Vec<u8> = ciphertext.ciphertext.clone().into();
    broken_ciphertext[1] ^= 0xff;

    let broken_ciphertext1 = HpkeCiphertext {
        kem_output: broken_kem_output.into(),
        ciphertext: ciphertext.ciphertext.clone(),
    };
    let broken_ciphertext2 = HpkeCiphertext {
        kem_output: ciphertext.kem_output,
        ciphertext: broken_ciphertext.into(),
    };
    assert_eq!(
        hpke::safe_decrypt_with_label(
            &kp.private,
            &broken_ciphertext1,
            ciphersuite,
            SafeEncryptionContext {
                component_id: COMPONENT_ID,
                label: LABEL,
                context: CONTEXT,
            },
            provider.crypto(),
        )
        .map_err(|_| CryptoError::HpkeDecryptionError)
        .expect_err("Erroneously correct ciphertext decryption of broken ciphertext."),
        CryptoError::HpkeDecryptionError
    );
    assert_eq!(
        hpke::safe_decrypt_with_label(
            &kp.private,
            &broken_ciphertext2,
            ciphersuite,
            SafeEncryptionContext {
                component_id: COMPONENT_ID,
                label: LABEL,
                context: CONTEXT,
            },
            provider.crypto(),
        )
        .map_err(|_| CryptoError::HpkeDecryptionError)
        .expect_err("Erroneously correct ciphertext decryption of broken ciphertext."),
        CryptoError::HpkeDecryptionError
    );
}

// Known-answer test for SafeDecryptWithLabel (draft-ietf-mls-extensions-10,
// Sections 4.1 and 4.2) with ciphersuite
// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
//
// The HPKE info is the EncryptContext of RFC 9420, Section 5.1.3, with the
// encoded ComponentOperationLabel as Label:
//
//   23                                  label<V>, 35 bytes
//     4d4c5320312e3020                  "MLS 1.0 "
//     0d                                base_label<V>, 13 bytes
//       4d4c5320436f6d706f6e656e74      "MLS Component"
//     0102                              component_id
//     0a                                label<V>, 10 bytes
//       74657374206c6162656c            "test label"
//   0c                                  context<V>, 12 bytes
//     7465737420636f6e74657874          "test context"
//
// The vector was generated outside OpenMLS with the `hpke` crate 0.13.0
// (https://github.com/rozbb/rust-hpke), which does not share code with
// hpke-rs, using the info above and an empty AAD:
//
//   let (sk, pk) = X25519HkdfSha256::derive_keypair(
//       b"mls-extensions-10 component label KAT");
//   let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0); // 0.9.0
//   let (kem_output, ciphertext) =
//       hpke::single_shot_seal::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(
//           &OpModeS::Base, &pk, &info, b"component plaintext", &[], &mut rng)?;
#[cfg(feature = "extensions-draft")]
#[test]
fn test_safe_hpke_decrypt_kat() {
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::OpenMlsProvider;

    let provider = OpenMlsRustCrypto::default();
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let private_key =
        hex::decode("d7f23c75f4e16bdaa40a032e3e8afa3d6d5c7dc154cf94c90556f1099530d465").unwrap();
    let ciphertext = HpkeCiphertext {
        kem_output: hex::decode("98ed6abc1e7d0eb8b4a7695af96e4b3b42d2276ca74d6a232c7298234324af50")
            .unwrap()
            .into(),
        ciphertext: hex::decode(
            "ecd8f3c62dbb8b2f9ac6bd5efe66c70ef9765f0994aca0bab31e0b4bc32ce10fc69cd1",
        )
        .unwrap()
        .into(),
    };

    let plaintext = hpke::safe_decrypt_with_label(
        &private_key,
        &ciphertext,
        ciphersuite,
        SafeEncryptionContext {
            component_id: 0x0102,
            label: "test label",
            context: b"test context",
        },
        provider.crypto(),
    )
    .expect("Failed to decrypt the known-answer ciphertext.");
    assert_eq!(plaintext, b"component plaintext");
}
