# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.6.0 (2026-08-25)

### Added

- [#2046](https://github.com/openmls/openmls/pull/2046): Added ECDSA P-384 and ML-DSA (65/87) signing support, behind the `draft-ietf-mls-pq-ciphersuites` feature flag.
- [#2118](https://github.com/openmls/openmls/pull/2118): Added ML-DSA44 signing support for the `draft-ietf-mls-pq-ciphersuites` draft v5 ciphersuites.

### Fixed

- [#2000](https://github.com/openmls/openmls/pull/2000): Replaced `rand` with `rand_core`.

These are all additive, feature-gated changes — no breaking changes.

## 0.5.0 (2025-09-24)

## 0.4.1 (2025-09-24)
