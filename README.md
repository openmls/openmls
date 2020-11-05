# openmls

![build status](https://travis-ci.com/openmls/openmls.svg?branch=main)

This is a PoC Rust implementation of [Messaging Layer Security](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md) based on draft 9+.

### Supported ciphersuites

- MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 (MTI)
- MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
- MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519

## Build

- run `cargo build`

## Test

- run `cargo test`

## Benchmark

- run `cargo bench`
