# Compatibility tests for `openmls`

This crate includes tests for compatibility with previous `openmls` versions.

## Usage

`test.sh` is used to run compatibility tests for several versions of `openmls`.

### Storage tag stability tests

5hese tests check that, for serialized enums, the variant index (used by `serde` non-self-describing formats) and the variant name (used by `serde` self-describing formats) are stable between `openmls` versions.

### Storage migration tests

These tests check storage compatibility for non-self-describing `serde` serializations, between `openmls=0.7.x` and the current `main`.
- Migration tests, for values that must be explicitly converted and rewritten
- Tolerant deserialization tests, for values that can be read directly from the old format

In `test.sh`, to test multiple `openmls=0.7.x` patch version, each patch version is pinned
using `cargo update --precise` before running tests.
