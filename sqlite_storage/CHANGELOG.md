# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (2026-02-04)

### Changed

- [#1929](https://github.com/openmls/openmls/pull/1929): Changed `store` functions to `INSERT OR REPLACE` rather than just `INSERT`. This is in conjunction with a change to OpenMLS that disables overwriting groups by default.

## 0.2.1 (2025-09-24)

## 0.2.0 (2025-07-17)

### Changed

- [#1807](https://github.com/openmls/openmls/pull/1807): Deprecate `initialize` in favor of new `run_migrations` function.

### Added

- [#1807](https://github.com/openmls/openmls/pull/1807): `run_migrations` function that scopes refinery migrations in its own table.

## 0.1.0 (2025-07-17)

- initial release

_Please disregard any previous versions._
