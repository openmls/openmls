# OpenMLS [![OpenMLS Chat][chat-image]][chat-link]

[![Tests & Checks][gh-tests-image]](https://github.com/openmls/openmls/actions/workflows/tests.yml)
[![ARM64 Build Status][drone-image]](https://cloud.drone.io/openmls/openmls)
[![Deploy Docs][gh-deploy-docs-image]][docs-main-link]
[![codecov][codecov-image]](https://codecov.io/gh/openmls/openmls)
[![OpenMLS List][list-image]][list-link]
[![Docs][docs-main-badge]][docs-main-link]
![Rust Version][rustc-image]

A WIP Rust implementation of [Messaging Layer Security](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md) based on draft 12+.

### Documentation

We publish documentation both for the latest release of OpenMLS, as well as for
the current state of `main`.

A user manual detailing how basic MLS operations can be performed using OpenMLS
can be found [here (latest release)][book-release-link] or [here (`main`)][book-main-link].
More detailed documentation on OpenMLS' public API
can be found [here (latest release)][docs-release-link] or [here (`main`)][docs-main-link].

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

OpenMLS only supports 32 and 64 bit platforms.

### Dependencies

#### Cryptography

OpenMLS does not implement its own cryptographic primitives.  Instead, it relies
on existing implementations of the cryptographic primitives used by MLS.  There
are two different cryptography backends implemented right now.  But consumers
can bring their own implementation.  See [traits](./traits/Readme.md) for more
details.

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

- [Rust Crypto](./openmls_rust_crypto/README.md)
- [Evercrypt](./openmls/evercrypt_backend/README.md)

It further holds the following crates that are used for testing.

### Delivery Service

A basic [delivery service](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-delivery-service) can be found in [delivery-service/ds](./delivery-service/ds/).
To interact with the delivery service the [ds-lib](./delivery-service/ds-lib/) provides the necessary types.

### Command line Client

A basic command line client can be found in [cli](./cli).
Note that this is a PoC for testing and must not be used for anything else.

---

## License

OpenMLS is licensed under the MIT license. The license can be found [here](./LICENSE).

## Contributing

OpenMLS welcomes contributions! Before contributing, please read the [contributing guidelines](CONTRIBUTING.md) carefully.
You can start by looking at the [open issues](https://github.com/openmls/openmls/issues) or join the discussion on [GitHub discussions](https://github.com/openmls/openmls/discussions) or [Zulip](https://openmls.zulipchat.com/).

## Code of conduct

OpenMLS adheres to the [Contributor Covenant](https://www.contributor-covenant.org/) Code of Coduct. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) carefully.

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg?style=flat&logo=zulip
[chat-link]: https://openmls.zulipchat.com
[list-image]: https://img.shields.io/badge/mailing-list-blue.svg?style=flat
[list-link]: https://groups.google.com/u/0/g/openmls-dev
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg?style=flat&logo=rust
[docs-main-badge]: https://img.shields.io/badge/docs-main-blue.svg?style=flat
[docs-release-link]: https://docs.rs/crate/openmls/latest
[docs-main-link]: https://openmls.tech/openmls/doc/openmls/index.html
[book-release-link]: https://openmls.tech/book
[book-main-link]: https://openmls.tech/openmls/book
[drone-image]: https://img.shields.io/drone/build/openmls/openmls/main?label=ARM64%20Build%20Status&logo=drone
[codecov-image]: https://img.shields.io/codecov/c/github/openmls/openmls/main?logo=codecov
[gh-tests-image]: https://img.shields.io/github/workflow/status/openmls/openmls/Tests/main?label=Tests&style=flat&logo=github
[gh-deploy-docs-image]: https://img.shields.io/github/workflow/status/openmls/openmls/Deploy%20Docs/main?label=Deploy%20Docs&logo=github