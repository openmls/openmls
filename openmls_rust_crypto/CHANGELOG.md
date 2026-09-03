# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

- [#2208](https://github.com/openmls/openmls/pull/2208): The KEM mapping to hpke-rs is fallible; an HPKE operation with a KEM hpke-rs does not implement (`HpkeKemType::MlKem768P256`, `HpkeKemType::MlKem1024P384`) returns `UnsupportedCiphersuite`.

## 0.6.0 (2026-08-25)

### Added

- [#2046](https://github.com/openmls/openmls/pull/2046): Added P-384, ML-DSA and general PQ ciphersuite support, behind the `draft-ietf-mls-pq-ciphersuites` feature flag.
- [#2118](https://github.com/openmls/openmls/pull/2118): Added the additional PQ ciphersuites from `draft-ietf-mls-pq-ciphersuites` draft v5.
- [#2028](https://github.com/openmls/openmls/pull/2028): Added support for targeted messages, behind the `targeted-messages-draft` feature flag.
- [#2109](https://github.com/openmls/openmls/pull/2109): Added early detection of ciphersuite support via `OpenMlsCrypto::supported_ciphersuites`.
- Added `extensions-draft` and `virtual-clients-draft` feature flags, passing through to the underlying `openmls_traits`/`openmls_memory_storage` features (experimental, see the "Virtual Clients (draft)" book chapter).

These are all additive, feature-gated changes — no breaking changes.

## 0.5.1 (2026-02-13)

### Changed

- [#1962](https://github.com/openmls/openmls/pull/1962): update hpke dependencies

## 0.5.0 (2026-02-04)

### Changed

- [#1945](https://github.com/openmls/openmls/pull/1945): Bump hpke dependencies

## 0.4.1 (2025-09-24)

### Changed

- [#909](https://github.com/openmls/openmls/pull/909): Use thiserror crate for errors

## 0.1.0 (2022-02-28)

- initial release

_Please disregard any previous versions._
