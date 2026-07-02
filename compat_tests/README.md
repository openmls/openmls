# Compatibility tests for `openmls`

This crate includes tests for compatibility with previous `openmls` versions.
- storage format compatibility tests for `openmls=0.7.1`, `openmls=0.8.1`, and `openmls=0.8.1` with the feature `extensions-draft` enabled

## Usage
```
cargo test -F compat_0_7_1
cargo test -F compat_0_8_1
cargo test -F compat_0_8_1_extensions
```
