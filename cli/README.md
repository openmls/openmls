# OpenMLS Proof-Of-Concept CLI Client

This directory contains source code for a proof-of-concept implementation of a
messaging client using OpenMLS. The client requires a running instance of our
proof-of-concept delivery service, which can be found in [delivery-service/ds](https://github.com/openmls/openmls/tree/main/delivery-service/ds) and can be
run from the command line using `cargo run`.

While the code should compile using `cargo build`, the CLI client is neither
very robust nor under active development.

After running the client from the command line (e.g. using `cargo run`). Type
`help` for basic usage.
