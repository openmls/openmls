# Test macro

This crate implements a proc macro for testing in OpenMLS.

`#[openmls_test]` copies the test body once per enabled provider and
ciphersuite. Which ciphersuites those are depends on the `all-ciphersuites`
feature: with it, every ciphersuite a provider supports, without it, only the
mandatory-to-implement one.

Enabling `all-ciphersuites` makes the expansion large enough that a single
`rustc` can run out of memory. Set `OPENMLS_TEST_CIPHERSUITE_SHARD` to
`index/total` to build and run only part of the ciphersuites, for example:

```sh
OPENMLS_TEST_CIPHERSUITE_SHARD=2/3 cargo test -p openmls -F all-ciphersuites
```

Each ciphersuite belongs to exactly one shard, so running all `total` shards
covers the same tests as one unsharded run.
