# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.3.0 (2026-08-25)

### Added

- [#2068](https://github.com/openmls/openmls/pull/2068): Added a transactions example showing how to use `SqlxStorageProvider` within a database transaction.

### Changed

- [#2060](https://github.com/openmls/openmls/pull/2060): Renamed the `extensions-draft-08` feature flag to `extensions-draft`.

## 0.2.0 (2026-02-04)

### Fixed

- [#1872](https://github.com/openmls/openmls/pull/1872): Added `extensions-draft-08` feature support

### Changed

- [#1929](https://github.com/openmls/openmls/pull/1929): Changed `store` functions to `INSERT OR REPLACE` rather than just `INSERT`. This is in conjunction with a change to OpenMLS that disables overwriting groups by default.

## 0.1.0

- initial release

_Please disregard any previous versions._
