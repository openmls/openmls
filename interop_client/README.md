## Interop Client

The interop client serves as interface between the test harness and OpenMLS such
that the `test-runner` can perform interop tests between OpenMLS and other
implementations (or indeed OpenMLS and itself).

Output of `interop_client --help`:

```
USAGE:
    interop_client [OPTIONS]

OPTIONS:
    -h, --host <HOST>    [default: [::1]]
        --help           Print help information
    -p, --port <PORT>    [default: 50051]
```

See [here](https://github.com/mlswg/mls-implementations) for more information on
MLS interop and the test harness.

## Test script

The interop client can be used to have OpenMLS perform interop testing against
itself by running the `test_with_runner.py` script.

The script requires

* `cargo` to compile the `interop_client`
* `git` to checkout the code of the test runner
* `go` to compile the `test-runner`
