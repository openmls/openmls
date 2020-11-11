# OpenMLS

![build status](https://travis-ci.com/openmls/openmls.svg?branch=main)
[![Build & Test](https://github.com/openmls/openmls/workflows/Build%20&%20Test/badge.svg)](https://github.com/openmls/openmls/actions?query=workflow%3A%22Build+%26+Test%22)
[![Deploy Docs](https://github.com/openmls/openmls/workflows/Deploy%20Docs/badge.svg)](https://openmls.github.io/openmls/openmls/index.html)

A WIP Rust implementation of [Messaging Layer Security](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md) based on draft 9+.

### Supported ciphersuites

- MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 (MTI)
- MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
- MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519

### Supported platforms

- linux x86_64
- linux arm32
- linux arm64
- macOS x86_64

### Dependencies

OpenMLS relies on [EverCrypt](https://github.com/project-everest/hacl-star/tree/master/providers/evercrypt), a high-performance, cross-platform, formally verified modern cryptographic provider through [EverCrypt Rust bindings](https://crates.io/crates/evercrypt).

## Build

- run `cargo build`

## Test

- run `cargo test`

## Benchmark

- run `cargo bench`

## License

OpenMLS is licensed under the MIT license. The license can be found [here](https://github.com/openmls/openmls/LICENSE).

## Contributing

Open MLS welcomes contributions! Before contributing, please read the [contributing guidelines](CONTRIBUTING.md) carefully.

## Code of conduct

Open MLS adheres to the [Contributor Covenant](https://www.contributor-covenant.org/) Code of Coduct. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) carefully.
