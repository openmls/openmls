//! The libcrux provider draws all of its randomness from the configured
//! entropy source, including the HPKE encapsulation randomness, which
//! `hpke-rs` would otherwise take from the operating system.
//!
//! The tests use a seeded, deterministic source: two providers built from the
//! same seed must produce identical HPKE ciphertexts. If any part of the
//! encapsulation drew from another source, the outputs would differ.

use std::convert::Infallible;

use openmls_libcrux_crypto::{CryptoProvider, Provider, TryCryptoRng, TryRng};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{Ciphersuite, CryptoError},
    OpenMlsProvider,
};

/// A deterministic SplitMix64 stream. Not an entropy source: it only makes
/// the provider's output reproducible for these tests.
struct SeededSource(u64);

impl TryRng for SeededSource {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Ok(z ^ (z >> 31))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let word = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for SeededSource {}

/// A source that always fails.
struct FailingSource;

#[derive(Debug)]
struct SourceUnavailable;

impl std::fmt::Display for SourceUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "entropy source unavailable")
    }
}

impl std::error::Error for SourceUnavailable {}

impl TryRng for FailingSource {
    type Error = SourceUnavailable;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(SourceUnavailable)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(SourceUnavailable)
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        Err(SourceUnavailable)
    }
}

impl TryCryptoRng for FailingSource {}

fn seeded(seed: u64) -> CryptoProvider<SeededSource> {
    CryptoProvider::with_entropy_source(SeededSource(seed)).unwrap()
}

fn ciphersuites() -> Vec<Ciphersuite> {
    CryptoProvider::new().unwrap().supported_ciphersuites()
}

/// Generate a recipient key pair with an OS-seeded provider, so that only the
/// sender's randomness depends on the seed under test.
fn recipient(ciphersuite: Ciphersuite) -> openmls_traits::types::HpkeKeyPair {
    let provider = CryptoProvider::new().unwrap();
    let ikm = provider.random_vec(ciphersuite.hash_length()).unwrap();
    provider
        .derive_hpke_keypair(ciphersuite.hpke_config(), &ikm)
        .unwrap()
}

#[test]
fn hpke_seal_is_determined_by_the_entropy_source() {
    for ciphersuite in ciphersuites() {
        let key_pair = recipient(ciphersuite);
        let seal = |provider: &CryptoProvider<SeededSource>| {
            provider
                .hpke_seal(
                    ciphersuite.hpke_config(),
                    &key_pair.public,
                    b"info",
                    b"aad",
                    b"plaintext",
                )
                .unwrap()
        };

        let first = seal(&seeded(1));
        let second = seal(&seeded(1));
        let other = seal(&seeded(2));

        assert_eq!(first, second, "{ciphersuite:?}: same seed, same ciphertext");
        assert_ne!(
            first.kem_output, other.kem_output,
            "{ciphersuite:?}: different seed, different KEM output"
        );

        let opened = CryptoProvider::new()
            .unwrap()
            .hpke_open(
                ciphersuite.hpke_config(),
                &first,
                &key_pair.private,
                b"info",
                b"aad",
            )
            .unwrap();
        assert_eq!(opened, b"plaintext", "{ciphersuite:?}: round trip");
    }
}

#[test]
fn hpke_setup_sender_is_determined_by_the_entropy_source() {
    for ciphersuite in ciphersuites() {
        let key_pair = recipient(ciphersuite);
        let export = |provider: &CryptoProvider<SeededSource>| {
            provider
                .hpke_setup_sender_and_export(
                    ciphersuite.hpke_config(),
                    &key_pair.public,
                    b"info",
                    b"context",
                    32,
                )
                .unwrap()
        };

        let (first_enc, first_secret) = export(&seeded(1));
        let (second_enc, second_secret) = export(&seeded(1));
        let (other_enc, _) = export(&seeded(2));

        assert_eq!(
            first_enc, second_enc,
            "{ciphersuite:?}: same seed, same enc"
        );
        assert_eq!(
            &first_secret[..],
            &second_secret[..],
            "{ciphersuite:?}: same seed, same exported secret"
        );
        assert_ne!(first_enc, other_enc, "{ciphersuite:?}: different seed");

        let received = CryptoProvider::new()
            .unwrap()
            .hpke_setup_receiver_and_export(
                ciphersuite.hpke_config(),
                &first_enc,
                &key_pair.private,
                b"info",
                b"context",
                32,
            )
            .unwrap();
        assert_eq!(
            &received[..],
            &first_secret[..],
            "{ciphersuite:?}: receiver derives the same secret"
        );
    }
}

#[cfg(feature = "targeted-messages-draft")]
#[test]
fn hpke_seal_psk_is_determined_by_the_entropy_source() {
    for ciphersuite in ciphersuites() {
        let key_pair = recipient(ciphersuite);
        let seal = |provider: &CryptoProvider<SeededSource>| {
            provider
                .hpke_seal_psk(
                    ciphersuite.hpke_config(),
                    &key_pair.public,
                    b"info",
                    b"aad",
                    b"plaintext",
                    &[7u8; 32],
                    b"psk id",
                )
                .unwrap()
        };

        let first = seal(&seeded(1));
        let second = seal(&seeded(1));
        let other = seal(&seeded(2));

        assert_eq!(first, second, "{ciphersuite:?}: same seed, same ciphertext");
        assert_ne!(
            first.kem_output, other.kem_output,
            "{ciphersuite:?}: different seed, different KEM output"
        );

        let opened = CryptoProvider::new()
            .unwrap()
            .hpke_open_psk(
                ciphersuite.hpke_config(),
                &first,
                &key_pair.private,
                b"info",
                b"aad",
                &[7u8; 32],
                b"psk id",
            )
            .unwrap();
        assert_eq!(opened, b"plaintext", "{ciphersuite:?}: PSK round trip");
    }
}

#[test]
fn signature_keys_are_determined_by_the_entropy_source() {
    for ciphersuite in ciphersuites() {
        let scheme = ciphersuite.signature_algorithm();
        let first = seeded(1).signature_key_gen(scheme).unwrap();
        let second = seeded(1).signature_key_gen(scheme).unwrap();
        let other = seeded(2).signature_key_gen(scheme).unwrap();

        assert_eq!(first, second, "{scheme:?}: same seed, same key");
        assert_ne!(
            first.0, other.0,
            "{scheme:?}: different seed, different key"
        );
    }
}

#[test]
fn signatures_are_determined_by_the_entropy_source() {
    for ciphersuite in ciphersuites() {
        let scheme = ciphersuite.signature_algorithm();
        let (private, public) = CryptoProvider::new()
            .unwrap()
            .signature_key_gen(scheme)
            .unwrap();
        let sign = |seed| seeded(seed).sign(scheme, b"message", &private).unwrap();

        let first = sign(1);
        assert_eq!(first, sign(1), "{scheme:?}: same seed, same signature");
        CryptoProvider::new()
            .unwrap()
            .verify_signature(scheme, b"message", &public, &first)
            .unwrap();
    }
}

#[test]
fn provider_rand_and_crypto_share_the_entropy_source() {
    let scheme = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm();

    // Draw from `rand()`, then from `crypto()`, then from `rand()` again.
    let interleaved = || {
        let provider = Provider::with_entropy_source(SeededSource(1)).unwrap();
        let before: [u8; 32] = provider.rand().random_array().unwrap();
        let key = provider.crypto().signature_key_gen(scheme).unwrap();
        let after: [u8; 32] = provider.rand().random_array().unwrap();
        (before, key, after)
    };

    let first = interleaved();
    let second = interleaved();
    assert_eq!(first, second, "the whole sequence is reproducible");

    // Without the `crypto()` draw, the second `rand()` draw differs: the
    // crypto operation advanced the stream that `rand()` draws from.
    let provider = Provider::with_entropy_source(SeededSource(1)).unwrap();
    let before: [u8; 32] = provider.rand().random_array().unwrap();
    let next: [u8; 32] = provider.rand().random_array().unwrap();
    assert_eq!(before, first.0);
    assert_ne!(next, first.2);
}

#[test]
fn failing_source_is_reported() {
    assert_eq!(
        CryptoProvider::with_entropy_source(FailingSource).err(),
        Some(CryptoError::InsufficientRandomness)
    );
    assert!(Provider::with_entropy_source(FailingSource).is_err());
}
