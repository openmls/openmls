# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.6.0 (2026-08-25)

### Added

- [#2034](https://github.com/openmls/openmls/pull/2034): Added support for the new `openmls_serialization_helpers` non-self-describing storage codecs.
- [#2046](https://github.com/openmls/openmls/pull/2046): Added storage support for the new PQ ciphersuites, behind the `draft-ietf-mls-pq-ciphersuites` feature flag.
- [#2017](https://github.com/openmls/openmls/pull/2017), [#2030](https://github.com/openmls/openmls/pull/2030), [#2056](https://github.com/openmls/openmls/pull/2056), [#2067](https://github.com/openmls/openmls/pull/2067), [#2119](https://github.com/openmls/openmls/pull/2119): Added storage support for virtual clients, behind the new `virtual-clients-draft` feature flag (experimental, see the "Virtual Clients (draft)" book chapter).

### Changed

- [#2060](https://github.com/openmls/openmls/pull/2060): Renamed the `extensions-draft-08` feature flag to `extensions-draft`. This is an unstable/draft feature that was never part of a stable release, but note it if you already depend on `extensions-draft-08` directly.
- [#2083](https://github.com/openmls/openmls/pull/2083): Raised MSRV to Rust 1.91.

### Fixed

- [#2138](https://github.com/openmls/openmls/pull/2138): Avoid constructing an error (which captures a backtrace in debug builds) on the happy path, improving performance.

## 0.5.0 (2026-02-04)

Version bump only, to stay in lockstep with `openmls_traits`; no functional changes.

## 0.4.1 (2025-09-24)

### Changed

- [#1700](https://github.com/openmls/openmls/pull/1700): Have `encryption_epoch_key_pairs` return an empty vector instead of an error if no value is found

## 0.3.3 (2024-09-04)

### Changed

- [#909](https://github.com/openmls/openmls/pull/909): Use thiserror crate for errors

## 0.1.0 (2022-02-28)

- initial release

_Please disregard any previous versions._
