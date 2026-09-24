# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (2026-08-25)

### Added

- [#2034](https://github.com/openmls/openmls/pull/2034): Added support for the new `openmls_serialization_helpers` non-self-describing storage codecs.
- [#2046](https://github.com/openmls/openmls/pull/2046): Added storage support for the new PQ ciphersuites, behind the `draft-ietf-mls-pq-ciphersuites` feature flag.
- [#2017](https://github.com/openmls/openmls/pull/2017), [#2030](https://github.com/openmls/openmls/pull/2030), [#2056](https://github.com/openmls/openmls/pull/2056), [#2067](https://github.com/openmls/openmls/pull/2067), [#2119](https://github.com/openmls/openmls/pull/2119): Added storage support for virtual clients, behind the new `virtual-clients-draft` feature flag (experimental, see the "Virtual Clients (draft)" book chapter).

### Changed

- [#2060](https://github.com/openmls/openmls/pull/2060): Renamed the `extensions-draft-08` feature flag to `extensions-draft`. This is an unstable/draft feature that was never part of a stable release, but note it if you already depend on `extensions-draft-08` directly.
- [#2083](https://github.com/openmls/openmls/pull/2083): Raised MSRV to Rust 1.91.
- [#1929](https://github.com/openmls/openmls/pull/1929): Changed `store` functions to `INSERT OR REPLACE` rather than just `INSERT`. This is in conjunction with a change to OpenMLS that disables overwriting groups by default. (Written up previously but never actually released as its own version; folded into this release.)

## 0.2.0 (2025-07-17)

### Changed

- [#1807](https://github.com/openmls/openmls/pull/1807): Deprecate `initialize` in favor of new `run_migrations` function.

### Added

- [#1807](https://github.com/openmls/openmls/pull/1807): `run_migrations` function that scopes refinery migrations in its own table.

## 0.1.0 (2025-07-17)

- initial release

_Please disregard any previous versions._
