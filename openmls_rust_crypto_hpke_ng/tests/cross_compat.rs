//! Cross-compatibility tests: the hpke-ng-backed provider must agree with the
//! hpke-rs-backed `openmls_rust_crypto` on every observable HPKE output. If
//! they ever drift, two MLS endpoints running different providers would fail
//! to interoperate.
//!
//! What this checks (per OpenMLS-supported ciphersuite):
//!  * `derive_hpke_keypair`: same IKM ⇒ same `(private, public)` bytes.
//!  * Cross-direction seal/open: a ciphertext produced by one provider is
//!    decrypted correctly by the other.

use openmls_rust_crypto::RustCrypto as Legacy;
use openmls_rust_crypto_hpke_ng::RustCrypto as Ng;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType},
};

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
fn derive_hpke_keypair_byte_identical_across_providers() {
    let legacy = Legacy::default();
    let ng = Ng::default();
    let ikm = b"shared keying material across provider implementations";
    for (name, parts) in config_parts() {
        let legacy_kp = legacy.derive_hpke_keypair(cfg(parts), ikm).expect(name);
        let ng_kp = ng.derive_hpke_keypair(cfg(parts), ikm).expect(name);
        assert_eq!(legacy_kp.public, ng_kp.public, "{name}: pk diverges");
        assert_eq!(
            &*legacy_kp.private,
            &*ng_kp.private,
            "{name}: sk diverges"
        );
    }
}

#[test]
fn ng_seal_legacy_open() {
    let legacy = Legacy::default();
    let ng = Ng::default();
    let info = b"mls 1.0 cross-compat";
    let aad = b"associated authenticated data";
    let pt = b"hello from hpke-ng";
    for (name, parts) in config_parts() {
        let kp = ng
            .derive_hpke_keypair(cfg(parts), b"32-byte minimum keying material xx")
            .expect(name);
        let ct = ng
            .hpke_seal(cfg(parts), &kp.public, info, aad, pt)
            .expect(name);
        let recovered = legacy
            .hpke_open(cfg(parts), &ct, &kp.private, info, aad)
            .expect(name);
        assert_eq!(recovered, pt, "{name}: legacy.open(ng.seal) mismatch");
    }
}

#[test]
fn legacy_seal_ng_open() {
    let legacy = Legacy::default();
    let ng = Ng::default();
    let info = b"mls 1.0 cross-compat";
    let aad = b"associated authenticated data";
    let pt = b"hello from hpke-rs";
    for (name, parts) in config_parts() {
        let kp = legacy
            .derive_hpke_keypair(cfg(parts), b"32-byte minimum keying material xx")
            .expect(name);
        let ct = legacy
            .hpke_seal(cfg(parts), &kp.public, info, aad, pt)
            .expect(name);
        let recovered = ng
            .hpke_open(cfg(parts), &ct, &kp.private, info, aad)
            .expect(name);
        assert_eq!(recovered, pt, "{name}: ng.open(legacy.seal) mismatch");
    }
}

#[test]
fn cross_provider_exporter_secrets_match() {
    // Sender on legacy + receiver on ng (and vice versa) should derive the same
    // exporter secret. This catches drift in the HPKE key schedule that the
    // bare seal/open round-trip might miss when the AEAD masks an off-by-one.
    let legacy = Legacy::default();
    let ng = Ng::default();
    let exp_ctx = b"cross-compat exporter";
    let exp_len = 32usize;
    for (name, parts) in config_parts() {
        let kp = legacy
            .derive_hpke_keypair(cfg(parts), b"32-byte minimum keying material xx")
            .expect(name);

        // Legacy sender, ng receiver.
        let (enc, sender_secret) = legacy
            .hpke_setup_sender_and_export(cfg(parts), &kp.public, b"info", exp_ctx, exp_len)
            .expect(name);
        let receiver_secret = ng
            .hpke_setup_receiver_and_export(cfg(parts), &enc, &kp.private, b"info", exp_ctx, exp_len)
            .expect(name);
        assert_eq!(
            &*sender_secret,
            &*receiver_secret,
            "{name}: ng.recv ≠ legacy.send"
        );

        // ng sender, legacy receiver.
        let (enc, sender_secret) = ng
            .hpke_setup_sender_and_export(cfg(parts), &kp.public, b"info", exp_ctx, exp_len)
            .expect(name);
        let receiver_secret = legacy
            .hpke_setup_receiver_and_export(cfg(parts), &enc, &kp.private, b"info", exp_ctx, exp_len)
            .expect(name);
        assert_eq!(
            &*sender_secret,
            &*receiver_secret,
            "{name}: legacy.recv ≠ ng.send"
        );
    }
}
