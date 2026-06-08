# Rust Crypto Backend (hpke-ng)

This crate implements the [OpenMLS traits](../traits/README.md) using the following Rust crates: [hkdf], [hpke-ng], [sha2], [p256], [p384], [x25519-dalek], [ed25519-dalek], [chacha20poly1305], [aes-gcm].

It is a sibling of [`openmls_rust_crypto`](../openmls_rust_crypto/README.md) that swaps the HPKE dependency from [hpke-rs] to [hpke-ng]. The non-HPKE primitives (signatures, AEAD, hashes, HKDF, HMAC) match `openmls_rust_crypto` exactly, so the two crates are interchangeable as `OpenMlsProvider` implementations.

[hkdf]: https://docs.rs/hkdf
[hpke-ng]: https://github.com/symbolicsoft/hpke-ng
[hpke-rs]: https://docs.rs/hpke-rs
[sha2]: https://docs.rs/sha2
[p256]: https://docs.rs/p256
[p384]: https://docs.rs/p384
[x25519-dalek]: https://docs.rs/x25519-dalek
[ed25519-dalek]: https://docs.rs/ed25519-dalek
[chacha20poly1305]: https://docs.rs/chacha20poly1305
[aes-gcm]: https://docs.rs/aes-gcm
