# Developer Readme

## Documentation

The [user manual][book-main-link] and [rust docs][docs-main-link] are published for
the current state of the `main` branch as well.

## Workspace

This repository is a cargo workspace with the OpenMLS library as the main component.

In order to use OpenMLS an implementation of the [traits](https://github.com/openmls/openmls/tree/main/traits) is required.
This repository provides default implementations

- [Rust Crypto](https://github.com/openmls/openmls/tree/main/openmls_rust_crypto/)

It further holds the following crates that are used for testing.

### Linux Build
To build openmls, some additional packages may be required. 

#### Bare metal
Install rustup:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update
rustup target add x86_64-unknown-linux-gnu
```

Install needed packages:
```
sudo apt-get install -y build-essential
sudo apt-get install -y curl
sudo apt-get install -y pkg-config
sudo apt-get install -y autoconf
sudo apt-get install -y make
sudo apt-get install -y cmake
sudo apt-get install -y libssl-dev
sudo apt-get install -y protobuf-compiler
sudo apt-get install -y ninja-build
sudo apt-get install -y clang --install-suggests
```

Then inside openmls repository folder run:
```
cargo build
```

#### Using docker
It is also possible to use the provided Dockerfile.

Within openmls repository folder run:
```
docker build -t devenv/rust:1.0 .
docker run -v /path/to/openmls_repository_folder:/opt -it devenv/rust:1.0
cd /opt
cargo build
```
### Delivery Service

A basic [delivery service](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-delivery-service) can be found in [delivery-service/ds](https://github.com/openmls/openmls/tree/main//delivery-service/ds/).
To interact with the delivery service the [ds-lib](https://github.com/openmls/openmls/tree/main//delivery-service/ds-lib/) provides the necessary types.

### Command line Client

A basic command line client can be found in [cli](https://github.com/openmls/openmls/tree/main/cli).
Note that this is a PoC for testing and must not be used for anything else.

## Contributing

OpenMLS welcomes contributions! Before contributing, please read the [contributing guidelines](https://github.com/openmls/openmls/tree/main/CONTRIBUTING.md) carefully.
You can start by looking at the [open issues](https://github.com/openmls/openmls/issues) or join the discussion on [GitHub discussions](https://github.com/openmls/openmls/discussions) or [Zulip](https://openmls.zulipchat.com/).

## Code of conduct

OpenMLS adheres to the [Contributor Covenant](https://www.contributor-covenant.org/) Code of Coduct. Please read the [Code of Conduct](https://github.com/openmls/openmls/tree/main/CODE_OF_CONDUCT.md) carefully.

[book-main-link]: https://openmls.tech/openmls/book
[docs-main-link]: https://openmls.tech/openmls/doc/openmls/index.html
