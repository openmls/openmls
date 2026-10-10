# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (2026-08-25)

### Added

- [#2032](https://github.com/openmls/openmls/pull/2032): Added an `all-ciphersuites` feature: when set, every `#[openmls_test]` expands to one test per supported ciphersuite of each enabled provider (previously the default and only behavior); when unset (now the default), each enabled provider emits a single test using the mandatory-to-implement ciphersuite, to keep test runs fast.
- [#2046](https://github.com/openmls/openmls/pull/2046): Added a `draft-ietf-mls-pq-ciphersuites` feature, propagated to the underlying provider crates.

### Changed

- [#2083](https://github.com/openmls/openmls/pull/2083): Raised MSRV to Rust 1.91.

## 0.2.1 (2025-09-24)
