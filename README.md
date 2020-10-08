# maelstrom

![build status](https://travis-ci.com/raphaelrobert/maelstrom.svg?branch=master)

This is a PoC Rust implementation of [Messaging Layer Security](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md) based on draft 9+.

### Supported ciphersuites

- MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 (MTI)
- MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519

## Build

- run `cargo build`

## Test

- run `cargo test`
