# OpenMLS

[![OpenMLS Chat][chat-image]][chat-link]
[![OpenMLS List][list-image]][list-link]

[![Tests & Checks][gh-tests-image]](https://github.com/openmls/openmls/actions/workflows/tests.yml?branch=main)
[![codecov][codecov-image]](https://codecov.io/gh/openmls/openmls)

[![Docs][docs-release-badge]][docs-release-link]
[![Book][book-release-badge]][book-release-link]
![Rust Version][rustc-image]

*OpenMLS* is a Rust implementation of the Messaging Layer Security (MLS) protocol, as specified in [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420).
<!-- The introduction of the book imports the lines up until here (line 13), excluding the headline and separately the lines below (starting from line 19, "Supported ciphersuite"). If the line numbers change here, please modify the imported lines in the book.-->

It is a software library that can serve as a building block in applications that require end-to-end encryption of messages.
It has a safe and easy-to-use interface that hides the complexity of the underlying cryptographic operations.

## Supported ciphersuites

- MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (MTI)
- MLS_128_DHKEMP256_AES128GCM_SHA256_P256
- MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519

## Supported platforms

OpenMLS is built and tested on the Github CI for the following rust targets.

- x86_64-unknown-linux-gnu
- i686-unknown-linux-gnu
- x86_64-pc-windows-msvc
- i686-pc-windows-msvc
- x86_64-apple-darwin

### Unsupported, but built on CI

The Github CI also builds (but doesn't test) the following rust targets.

- aarch64-apple-darwin
- aarch64-unknown-linux-gnu
- aarch64-linux-android
- aarch64-apple-ios
- aarch64-apple-ios-sim
- wasm32-unknown-unknown
- armv7-linux-androideabi
- x86_64-linux-android
- i686-linux-android

OpenMLS supports 32 bit platforms and above.

## Cryptography Dependencies

OpenMLS does not implement its own cryptographic primitives. Instead, it relies
on existing implementations of the cryptographic primitives used by MLS. There
are two different cryptography providers implemented right now. But consumers
can bring their own implementation. See [traits](https://github.com/openmls/openmls/tree/main/traits) for more
details.

## Working on OpenMLS
For more details when working on OpenMLS itself please see the [Developer.md].

## Maintenance & Support
OpenMLS is maintained and developed by [Phoenix R&D] and [Cryspen].

## Acknowledgements

[Zulip] graciously provides the OpenMLS community with a "Zulip Cloud Standard" tier [Zulip instance][chat-link].

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg?style=for-the-badge&logo=zulip
[chat-link]: https://openmls.zulipchat.com
[list-image]: https://img.shields.io/badge/mailing-list-blue.svg?style=for-the-badge
[list-link]: https://groups.google.com/u/0/g/openmls-dev
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg?style=for-the-badge&logo=rust
[docs-release-badge]: https://img.shields.io/badge/docs-release-blue.svg?style=for-the-badge
[docs-release-link]: https://docs.rs/crate/openmls/latest
[book-release-badge]: https://img.shields.io/badge/book-release-blue.svg?style=for-the-badge
[book-release-link]: https://book.openmls.tech
[drone-image]: https://img.shields.io/drone/build/openmls/openmls/main?label=ARM64%20Build%20Status&logo=drone&style=for-the-badge
[codecov-image]: https://img.shields.io/codecov/c/github/openmls/openmls/main?logo=codecov&style=for-the-badge
[gh-tests-image]: https://img.shields.io/github/actions/workflow/status/openmls/openmls/tests.yml?branch=main&style=for-the-badge&logo=github
[gh-deploy-docs-image]: https://img.shields.io/github/workflow/status/openmls/openmls/Deploy%20Docs/main?label=Deploy%20Docs&logo=github&style=for-the-badge
[Developer.md]: https://github.com/openmls/openmls/blob/main/Developer.md
[Phoenix R&D]: https://phnx.im
[Cryspen]: https://cryspen.com
[Zulip]: https://zulip.com/

