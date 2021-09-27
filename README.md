# OpenMLS [![OpenMLS Chat][chat-image]][chat-link]

[![Tests & Checks](https://github.com/openmls/openmls/actions/workflows/tests.yml/badge.svg)](https://github.com/openmls/openmls/actions/workflows/tests.yml)
[![Deploy Docs](https://github.com/openmls/openmls/workflows/Deploy%20Docs/badge.svg)](https://openmls.github.io/openmls/openmls/index.html)
[![codecov](https://codecov.io/gh/openmls/openmls/branch/main/graph/badge.svg?token=5SDRDRTZI0)](https://codecov.io/gh/openmls/openmls)
[![OpenMLS List][list-image]][list-link]
![Rust Version][rustc-image]

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

#### Cryptography

OpenMLS does not implement its own cryptographic primitives.
Instead, it relies on existing implementations of the cryptographic primitives used.
There are two different cryptography backends supported right now.

##### Rust Crypto

This is the default cryptographic backend, using [hkdf], [sha2], [p256], [p384], [x25519-dalek-ng], [ed25519-dalek] [chacha20poly1305], [aes-gcm].


##### Evercrypt

[EverCrypt] provides a formally verified cryptographic backend through the through [EverCrypt Rust bindings] to OpenMLS.
The default features have to disabled and the `evercrypt-backend` feature has to be enabled.

```
cargo build --features="evercrypt-backend" --no-default-features
```

Note that using this provider restricts OpenMLS usage to the following platforms right now
* Linux x64
* Linux Arm64
* MacOS x64
* Windows x64

⚠️ Note that using this feature tests don't work out of the box.
You need to change the `openmls` dev-dependency in the `Cargo.toml` to use the evercrypt backend as well.

## Development

OpenMLS requires at least Rust 1.50.0.

### Build

- run `cargo build`

### Test

- run `cargo test`

### Benchmark

- run `cargo bench`

## Workspace

This repository is a cargo workspace with the OpenMLS library as the main component.
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
[rustc-image]: https://img.shields.io/badge/rustc-1.50+-blue.svg

[hkdf]: https://docs.rs/hkdf/
[sha2]: https://docs.rs/sha2
[p256]: https://docs.rs/p256
[p384]: https://docs.rs/p384
[x25519-dalek-ng]: https://docs.rs/x25519-dalek-ng
[ed25519-dalek]: https://docs.rs/ed25519-dalek
[chacha20poly1305]: https://docs.rs/chacha20poly1305
[aes-gcm]: https://docs.rs/aes-gcm
[Evercrypt]: https://github.com/project-everest/hacl-star/
[EverCrypt Rust bindings]: https://crates.io/crates/evercrypt
