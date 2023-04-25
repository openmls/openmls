# Interop Client

Interoperability between MLS implementations is tested using a [test-runner] that tells different MLS
implementations what to do, e.g., to create a group, export a group info, make a proposal, commit, etc.

To receive these actions from the test-runner, all implementations need to expose their group handling logic through
a unified gRPC interface. Technically, this interface is exposed through a gRPC server, although the idea is really that
OpenMLS acts like a member of a group.

The gRPC server for OpenMLS is provided here. The test-runner and [MLS++] -- another MLS implementation -- are provided
through Docker.

## Quickstart

As an example, we want to test if OpenMLS can interoperate with MLS++.
We need three components: the OpenMLS gRPC server, the MLS++ gRPC server, and the test-runner.

### Build & start the OpenMLS gRPC server

The OpenMLS gRPC server can be started with ...

```sh
RUST_LOG=interop=info cargo run
```

... and will listen for gRPC commands on port 50051.

You can use the `RUST_LOG` environment variable to control what is logged, e.g., `RUST_LOG=interop=trace,openmls=debug`.
Furthermore, OpenMLS provides the `crypto-debug` feature that unlocks logging of sensitive values such as private keys.

### Build & start the MLS++ gRPC server

The MLS++ gRPC server can be started by using the provided Dockerfile:

```sh
docker build --tag mlspp docker/mlspp
docker run -p 12345:12345 -it mlspp bash

# Inside interactive Docker container:
./mlspp_client -live 12345
```

Note: We use an interactive session here in case you want to debug discrepancies between OpenMLS and MLS++.

### Build & run the test-runner

The test-runner can be started by using the provided Dockerfile:

```sh
docker build --tag test-runner docker/test-runner
docker run --network host -it test-runner bash

# Inside interactive Docker container:
cd ..
./test-runner/test-runner -fail-fast -client localhost:50051 -client localhost:12345 -config=configs/welcome_join.json
```

You should now see how the test-runner orchestrated the "welcome" scenario between OpenMLS and MLS++. You can run more scenarios by specifying another config file.

## Test script

The interop client can be used to have OpenMLS perform interop testing against
itself by running the `test_with_runner.py` script.

```
USAGE:
    interop_client [OPTIONS]

OPTIONS:
    -h, --host <HOST>    [default: [::1]]
        --help           Print help information
    -p, --port <PORT>    [default: 50051]
```

The script requires

* `cargo` to compile the `interop_client`
* `git` to checkout the code of the test runner
* `go` to compile the `test-runner`

[test-runner]: https://github.com/mlswg/mls-implementations/tree/main/interop/test-runner
[MLS++]: https://github.com/cisco/mlspp
