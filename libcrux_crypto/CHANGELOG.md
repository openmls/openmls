# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- [#2281](https://github.com/openmls/openmls/pull/2281): The ML-KEM-768 + P-256 hybrid KEM (`MLKEM768-P256`) via `hpke-rs-libcrux`, so `MLS_128_MLKEM768P256_AES128GCM_SHA256_P256` (TBD3) and `MLS_128_MLKEM768P256_AES256GCM_SHA384_P256` (TBD4) from `draft-ietf-mls-pq-ciphersuites` are now supported (behind the `draft-ietf-mls-pq-ciphersuites` feature flag). `MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87` (already accepted by `supports()`) is now also advertised in `supported_ciphersuites()`. `MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384` (TBD5) and `MLS_192_MLKEM1024_AES256GCM_SHA384_P384` (TBD8) remain unsupported because libcrux has no ECDSA P-384 implementation; the ML-KEM-1024 + P-384 HPKE KEM itself is implemented.
- [#2215](https://github.com/openmls/openmls/pull/2215): ECDSA P-256 signature support via `libcrux-ecdsa`, enabling the `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` ciphersuite. Key and signature encodings (raw scalar, uncompressed SEC1 point, DER signatures) match the RustCrypto provider.

- [#2170](https://github.com/openmls/openmls/pull/2170): ML-DSA-44/65/87 signatures via `libcrux-ml-dsa`, and pure ML-KEM KEMs via `hpke-rs-libcrux`'s `draft-ietf-hpke-pq`, so the ML-DSA ciphersuites from `draft-ietf-mls-pq-ciphersuites` are now supported by the libcrux provider (behind the `draft-ietf-mls-pq-ciphersuites` feature flag). Key and signature encodings match the RustCrypto provider.

- [#2274](https://github.com/openmls/openmls/pull/2274): The libcrux provider now also advertises `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`, `MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519`, `MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519` and `MLS_128_MLKEM768_AES256GCM_SHA384_P256` from `draft-ietf-mls-pq-ciphersuites` in `supported_ciphersuites()` (all already accepted by `supports()`).
- [#2274](https://github.com/openmls/openmls/pull/2274): New `legacy-pq-key-derivation` feature flag: derives HPKE key pairs for the legacy `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (0x004D) ciphersuite the way 0.4.0 did, to interoperate with existing groups on that ciphersuite. See below.

### Changed

- [#2306](https://github.com/openmls/openmls/pull/2306): All randomness of the provider now comes from its single HMAC-DRBG, which is seeded and reseeded from a configurable entropy source. `CryptoProvider::with_entropy_source` and `Provider::with_entropy_source` take a `rand` 0.10 `TryCryptoRng` (`Send + 'static`) to use instead of the operating system's RNG. `CryptoProvider` and `Provider` gain a type parameter for the source, defaulting to `rand::rngs::SysRng`, so existing uses of `CryptoProvider::new()`, `Provider::new()` and `Provider::default()` are unchanged. The `TryCryptoRng` and `TryRng` traits are re-exported for implementing a source.
  - HPKE encapsulation (`hpke_seal`, `hpke_setup_sender_and_export` and `hpke_seal_psk`) draws from the provider's DRBG; previously `hpke-rs` seeded its own PRNG from the operating system on every call. The receiver side of HPKE and HPKE key derivation draw no randomness, and no longer read the operating system's RNG either.
  - The DRBG is reseeded from the entropy source after every 2^16 requests. Previously it was reseeded only at the SP 800-90A limit of 2^48 requests, which is not reached in practice.
  - If the entropy source fails on a reseed, the `OpenMlsCrypto` operations that need randomness (signature key generation, ECDSA P-256 and ML-DSA signing, HPKE encapsulation) return `CryptoError::InsufficientRandomness`; ECDSA P-256 previously returned `CryptoError::SigningError`. `OpenMlsRand` returns `RandError::UnableToGenerate`.
- [#2274](https://github.com/openmls/openmls/pull/2274): HPKE key derivation (`derive_hpke_keypair`) for the ML-KEM and X-Wing KEMs now follows `draft-ietf-hpke-pq` (`SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", Nsk)`) instead of the unlabeled `SHAKE256(ikm, Nsk)`, and ML-KEM private keys are now the 64-byte seed instead of the expanded decapsulation key. This is a breaking change for groups created with 0.4.0 on PQ ciphersuites:
  - `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (0x004D): keys derived from path secrets no longer match those of 0.4.0 peers, so mixed-version groups fail on commits with an update path. Stored keys keep working. Enable `legacy-pq-key-derivation` to keep the 0.4.0 derivation for this ciphersuite (all other ciphersuites are unaffected), and migrate such groups (e.g. via ReInit) to a `draft-ietf-mls-pq-ciphersuites` ciphersuite.
  - `MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519` (0xF042) is the provisional code point of the draft's TBD6 and uses the new derivation. Groups created with 0.4.0 on it cannot be carried over: the derivation differs and stored ML-KEM private keys are in the old expanded format.

## 0.4.0 (2026-08-25)

### Added

- [#2046](https://github.com/openmls/openmls/pull/2046): Added PQ ciphersuite support, behind the `draft-ietf-mls-pq-ciphersuites` feature flag.
- [#2028](https://github.com/openmls/openmls/pull/2028): Added support for targeted messages, behind the `targeted-messages-draft` feature flag.

### Changed

- [#2060](https://github.com/openmls/openmls/pull/2060): Renamed the `extensions-draft-08` feature flag to `extensions-draft`. This is an unstable/draft feature that was never part of a stable release, but note it if you already depend on `extensions-draft-08` directly.

### Fixed

- [#2139](https://github.com/openmls/openmls/pull/2139): The libcrux crypto provider rejected some ciphersuites it actually supports.

## 0.3.1 (2026-02-13)

### Changed

- [#1962](https://github.com/openmls/openmls/pull/1962): update libcrux and hpke-rs dependencies

## 0.3.0 (2026-02-04)

### Changed

- [#1874](https://github.com/openmls/openmls/pull/1874): update libcrux dependencies and add AES-GCM support

## 0.2.1 (2025-09-24)
