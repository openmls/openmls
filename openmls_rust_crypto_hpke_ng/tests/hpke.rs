//! Integration tests for the hpke-ng-backed RustCrypto provider.
//!
//! Exercises the HPKE methods OpenMLS calls through `OpenMlsCrypto`:
//! `derive_hpke_keypair`, `hpke_seal`/`hpke_open` (seal/open round-trip),
//! and `hpke_setup_sender_and_export`/`hpke_setup_receiver_and_export`
//! (sender/receiver export agreement). All three OpenMLS-supported
//! ciphersuites are covered.

use openmls_rust_crypto_hpke_ng::RustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType},
};

// `HpkeConfig` is not `Copy`, so each test rebuilds it from the Copy parts.
type ConfigParts = (HpkeKemType, HpkeKdfType, HpkeAeadType);

fn config_parts() -> [(&'static str, ConfigParts); 3] {
    [
        (
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            (
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ),
        ),
        (
            "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519",
            (
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::ChaCha20Poly1305,
            ),
        ),
        (
            "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
            (
                HpkeKemType::DhKemP256,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ),
        ),
    ]
}

fn cfg(parts: ConfigParts) -> HpkeConfig {
    HpkeConfig(parts.0, parts.1, parts.2)
}

#[test]
fn supported_ciphersuites_match_legacy_provider() {
    let crypto = RustCrypto::default();
    let supported = crypto.supported_ciphersuites();
    assert_eq!(supported.len(), 3);
    assert!(supported.contains(&Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519));
    assert!(supported.contains(&Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519));
    assert!(supported.contains(&Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256));
}

#[test]
fn derive_hpke_keypair_is_deterministic() {
    let crypto = RustCrypto::default();
    for (name, parts) in config_parts() {
        let ikm = b"test ikm bytes for derive_hpke_keypair";
        let kp1 = crypto.derive_hpke_keypair(cfg(parts), ikm).expect(name);
        let kp2 = crypto.derive_hpke_keypair(cfg(parts), ikm).expect(name);
        assert_eq!(kp1.public, kp2.public, "{name}: pk diverges");
        assert_eq!(&*kp1.private, &*kp2.private, "{name}: sk diverges");
    }
}

#[test]
fn seal_open_roundtrips_for_each_supported_ciphersuite() {
    let crypto = RustCrypto::default();
    let info = b"mls 1.0 test info";
    let aad = b"associated authenticated data";
    let pt = b"plaintext payload that needs sealing";
    for (name, parts) in config_parts() {
        let ikm = b"32-byte minimum keying material xx";
        let kp = crypto.derive_hpke_keypair(cfg(parts), ikm).expect(name);

        let ct = crypto
            .hpke_seal(cfg(parts), &kp.public, info, aad, pt)
            .expect(name);
        let recovered = crypto
            .hpke_open(cfg(parts), &ct, &kp.private, info, aad)
            .expect(name);
        assert_eq!(recovered, pt, "{name}: open ≠ seal");
    }
}

#[test]
fn open_rejects_tampered_ciphertext() {
    let crypto = RustCrypto::default();
    for (name, parts) in config_parts() {
        let kp = crypto
            .derive_hpke_keypair(cfg(parts), b"32-byte minimum keying material xx")
            .expect(name);
        let mut ct = crypto
            .hpke_seal(cfg(parts), &kp.public, b"info", b"aad", b"hi")
            .expect(name);
        // Flip a bit in the AEAD output. The MAC tag check must reject.
        let mut bytes: Vec<u8> = ct.ciphertext.as_slice().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        ct.ciphertext = bytes.into();
        let result = crypto.hpke_open(cfg(parts), &ct, &kp.private, b"info", b"aad");
        assert!(result.is_err(), "{name}: tampered ciphertext was accepted");
    }
}

#[test]
fn sender_and_receiver_exports_match() {
    let crypto = RustCrypto::default();
    let exporter_context = b"mls exporter context";
    let exporter_length = 32usize;
    for (name, parts) in config_parts() {
        let kp = crypto
            .derive_hpke_keypair(cfg(parts), b"32-byte minimum keying material xx")
            .expect(name);

        let (enc, sender_secret) = crypto
            .hpke_setup_sender_and_export(
                cfg(parts),
                &kp.public,
                b"info",
                exporter_context,
                exporter_length,
            )
            .expect(name);

        let receiver_secret = crypto
            .hpke_setup_receiver_and_export(
                cfg(parts),
                &enc,
                &kp.private,
                b"info",
                exporter_context,
                exporter_length,
            )
            .expect(name);

        assert_eq!(
            &*sender_secret,
            &*receiver_secret,
            "{name}: exporter secrets diverge"
        );
        assert_eq!(
            sender_secret.len(),
            exporter_length,
            "{name}: exporter length wrong"
        );
    }
}

#[test]
fn fresh_seal_outputs_differ() {
    // The randomness path runs through `RngCompat09`. If the bridge produced
    // duplicate bytes, two consecutive `hpke_seal` calls with the same inputs
    // would emit identical ciphertexts (the ephemeral DH key is sampled fresh
    // each time). This catches a wrapper that, e.g., short-circuits `fill_bytes`.
    let crypto = RustCrypto::default();
    let parts = (
        HpkeKemType::DhKem25519,
        HpkeKdfType::HkdfSha256,
        HpkeAeadType::AesGcm128,
    );
    let kp = crypto
        .derive_hpke_keypair(cfg(parts), b"32-byte minimum keying material xx")
        .unwrap();
    let ct1 = crypto
        .hpke_seal(cfg(parts), &kp.public, b"info", b"aad", b"hello")
        .unwrap();
    let ct2 = crypto
        .hpke_seal(cfg(parts), &kp.public, b"info", b"aad", b"hello")
        .unwrap();
    assert_ne!(ct1.kem_output, ct2.kem_output);
    assert_ne!(ct1.ciphertext, ct2.ciphertext);
}

#[test]
fn unsupported_kem_kdf_pairing_returns_error() {
    let crypto = RustCrypto::default();
    // P-384 KEM with SHA-256 KDF is not a natural HPKE pairing and is not a
    // valid MLS ciphersuite. The dispatch's wildcard arm must turn that into
    // `UnsupportedCiphersuite` rather than panic.
    let parts = (
        HpkeKemType::DhKemP384,
        HpkeKdfType::HkdfSha256,
        HpkeAeadType::AesGcm128,
    );
    let result = crypto.hpke_seal(cfg(parts), &[0u8; 65], b"info", b"aad", b"pt");
    assert!(result.is_err());
}
