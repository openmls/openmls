cargo fmt --check
RUSTFLAGS=-D warnings cargo check --tests
cargo test
RUSTFLAGS=-D warnings cargo doc
cargo bench
