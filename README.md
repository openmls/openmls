# OpenMLS [![OpenMLS Chat][chat-image]][chat-link]

[![Tests & Checks](https://github.com/openmls/openmls/actions/workflows/tests.yml/badge.svg)](https://github.com/openmls/openmls/actions/workflows/tests.yml)
[![ARM64 Build Status](https://cloud.drone.io/api/badges/openmls/openmls/status.svg?ref=refs/heads/main)](https://cloud.drone.io/openmls/openmls)
[![Deploy Docs](https://github.com/openmls/openmls/workflows/Deploy%20Docs/badge.svg)](https://openmls.github.io/openmls/openmls/index.html)
[![codecov](https://codecov.io/gh/openmls/openmls/branch/main/graph/badge.svg?token=5SDRDRTZI0)](https://codecov.io/gh/openmls/openmls)
[![OpenMLS List][list-image]][list-link]
[![Docs][docs-main-badge]][docs-main-link]
![Rust Version][rustc-image]

A WIP Rust implementation of [Messaging Layer Security](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md) based on draft 9+.

### Supported ciphersuites

- MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 (MTI)
- MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
- MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519

### Supported platforms

OpenMLS is built and tested on the Github CI for the following rust targets.

- x86_64-unknown-linux-gnu
- i686-unknown-linux-gnu
- x86_64-pc-windows-msvc
- i686-pc-windows-msvc
- x86_64-apple-darwin

Additionally, we're building and testing aarch64-unknown-linux-gnu on
[drone.io](https://cloud.drone.io/openmls/openmls).

The Github CI also builds (but doesn't test) the following rust targets.

- aarch64-apple-darwin
- aarch64-unknown-linux-gnu
- aarch64-linux-android
- aarch64-apple-ios
- aarch64-apple-ios-sim
- wasm32-unknown-unknown

### Dependencies

#### Cryptography

OpenMLS does not implement its own cryptographic primitives.
Instead, it relies on existing implementations of the cryptographic primitives used.
There are two different cryptography backends implemented right now.
But consumers can bring their own implementation.
See [traits](./traits/Readme.md) for more details.

## Development

OpenMLS requires at least Rust 1.56.0.

### Build

- run `cargo build`

### Test

- run `cargo test`

### Benchmark

- run `cargo bench`

## Workspace

This repository is a cargo workspace with the OpenMLS library as the main component.

In order to use OpenMLS an implementation of the [traits](./traits/Readme.md) is required.
This repository provides two default implementations

- [Rust Crypto](./openmls_rust_crypto/Readme.md)
- [Evercrypt](./evercrypt_backend/Readme.md)

It further holds the following crates that are used for testing.

### Delivery Service

A basic [delivery service](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-delivery-service) can be found in [delivery-service/ds](./delivery-service/ds/).
To interact with the delivery service the [ds-lib](./delivery-service/ds-lib/) provides the necessary types.

### Command line Client

A basic command line client can be found in [cli](./cli).
Note that this is a PoC for testing and must not be used for anything else.

---

## License

OpenMLS is licensed under the MIT license. The license can be found [here](https://github.com/openmls/openmls/LICENSE).

## Contributing

OpenMLS welcomes contributions! Before contributing, please read the [contributing guidelines](CONTRIBUTING.md) carefully.
You can start by looking at the [open issues](https://github.com/openmls/openmls/issues) or join the discussion on [GitHub discussions](https://github.com/openmls/openmls/discussions) or [Zulip](https://openmls.zulipchat.com/).

## Code of conduct

OpenMLS adheres to the [Contributor Covenant](https://www.contributor-covenant.org/) Code of Coduct. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) carefully.

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://openmls.zulipchat.com
[list-image]: https://img.shields.io/badge/mailing-list-blue.svg
[list-link]: https://groups.google.com/u/0/g/openmls-dev
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[docs-main-badge]: https://img.shields.io/badge/docs-main-blue.svg
[docs-main-link]: https://openmls.tech/openmls/openmls/index.html
