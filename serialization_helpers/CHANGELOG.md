# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (2026-08-25)

- [#2034](https://github.com/openmls/openmls/pull/2034): Initial release. Adds `serde` helpers for non-self-describing binary codecs (e.g. `bincode`) to correctly (de)serialize enums with feature-flagged variants, used by the storage-provider crates.
- [#2083](https://github.com/openmls/openmls/pull/2083): Raised MSRV to Rust 1.91.
- [#2130](https://github.com/openmls/openmls/pull/2130): Fixed enum deserialization for self-describing binary codecs.
