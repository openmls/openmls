//! The `openmls_test` macro reads the ciphersuite shard from the environment
//! while it expands, so cargo has to recompile this crate, and with it every
//! crate whose tests the macro expands, when that variable changes.

fn main() {
    println!("cargo::rerun-if-env-changed=OPENMLS_TEST_CIPHERSUITE_SHARD");
}
