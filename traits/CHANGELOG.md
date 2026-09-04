# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- [#2208](https://github.com/openmls/openmls/pull/2208): Added the three ciphersuites of draft-ietf-mls-pq-ciphersuites on the hybrid ML-KEM/P-curve KEMs, `MLS_128_MLKEM768P256_AES128GCM_SHA256_P256` (TBD3), `MLS_128_MLKEM768P256_AES256GCM_SHA384_P256` (TBD4) and `MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384` (TBD5), with provisional code points `0x0053` to `0x0055`, and the KEMs `HpkeKemType::MlKem768P256` (`0x0050`) and `HpkeKemType::MlKem1024P384` (`0x0051`) from draft-ietf-hpke-pq, behind `draft-ietf-mls-pq-ciphersuites`. Neither bundled crypto provider implements these KEMs; they report the ciphersuites as unsupported and their HPKE operations return `UnsupportedCiphersuite` for them.

## 0.6.0 (2026-08-25)

### Added

- [#2046](https://github.com/openmls/openmls/pull/2046), [#2118](https://github.com/openmls/openmls/pull/2118): Added P-384, ML-DSA and additional PQ ciphersuites (including the `draft-ietf-mls-pq-ciphersuites` draft v5 code points), behind the `draft-ietf-mls-pq-ciphersuites` feature flag. This includes a `MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519` ciphersuite variant, kept (renamed, same code point) from the previously custom `AIR_128_MLKEM768_AES256GCM_SHA384_Ed25519` variant.
- [#2028](https://github.com/openmls/openmls/pull/2028): Added a `targeted-messages-draft` feature flag.
- [#2017](https://github.com/openmls/openmls/pull/2017), [#2030](https://github.com/openmls/openmls/pull/2030), [#2056](https://github.com/openmls/openmls/pull/2056), [#2067](https://github.com/openmls/openmls/pull/2067), [#2119](https://github.com/openmls/openmls/pull/2119): Added a `virtual-clients-draft` feature flag (experimental, see the "Virtual Clients (draft)" book chapter).
- [#1965](https://github.com/openmls/openmls/pull/1965): Derive `TlsSerializeBytes` for `SignatureScheme`.

### Changed

- [#2146](https://github.com/openmls/openmls/pull/2146): The `Debug` output of `HpkePrivateKey` and `ExporterSecret` no longer contains the secret bytes. The new `crypto-debug` feature restores the full output for debugging.
- [#2060](https://github.com/openmls/openmls/pull/2060): Renamed the `extensions-draft-08` feature flag to `extensions-draft`. This feature (and everything gated behind it, including the ciphersuite rename above) is unstable/draft and was never part of a stable release, but note it if you already depend on `extensions-draft-08` directly.
- [#2083](https://github.com/openmls/openmls/pull/2083): Raised MSRV to Rust 1.91.

## 0.5.0 (2026-02-04)

Version bump only, to stay in lockstep with the other crates in this release train; no functional changes.

## 0.4.1 (2025-09-24)

- [#1825](https://github.com/openmls/openmls/pull/1825): Add the `hmac` method for hashing to the `OpenMlsCrypto` trait.

## 0.4.0

- [#1760](https://github.com/openmls/openmls/pull/1760): Drop support for `XWingKemDraft2` and add support for `XWingKemDraft6`

### Changed

- [#909](https://github.com/openmls/openmls/pull/909): Use thiserror crate for errors

## 0.1.0 (2022-02-28)

- initial release

_Please disregard any previous versions._
