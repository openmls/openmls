# OpenMLS testing proposition

The purpose of this document is to define a testing infrastructure and guidelines how to write tests.

## Current status

Here are some factual remarks about the current state of tests.

1. erratic: no clear pattern emerges. It looks like tests have been piled up at different times by different persons
   without shared, well-established rules. There are very few unit tests, some integration tests in `src/` and some
   other integration tests in `tests/`
2. too verbose: some domain are of course complex and hard to test, but some simpler ones require thousands of lines to
   get tested
3. not idiomatic: one of the recommended way to write tests in Rust is to write unit tests in the same file as the
   sources in order to have access to private members. Integration tests (in `tests/`) are more high level and
   especially
   used for verifying the public API
4. Not enough factorization: it is not uncommon to have a file redefining its own set of helpers. A lot of those helpers
   are duplicated all across the codebase
5. some tests actually test more than one thing. It makes them harder to write/understand. Also harder to debug when
   they
   fail (in which iteration am I ?). This results mostly from the test setup being verbose which incentivizes reuse

## Goals

This proposition aims at:

1. Write less test code
2. Share a common pattern for writing tests
3. Have finer grained tests and be quicker to troubleshoot the cause of a failing test
4. Be idiomatic to welcome easier external contributions

## Rules

To achieve these goals, here are the "rules"/recommendations to set up:

1. Any test expected to fail by altering a valid input SHOULD also keep this valid input and verify that, contrary to
   the tampered one, it succeeds.
2. Prefer `.unwrap()` over `.expect("...")`. The latter adds overhead and most of the time does not add enough debugging
   information. If, on the opposite, an `.expect(...)` can help a developer troubleshooting a failing test with a very
   complex setup which this `expect` message could help understanding then go for it ! Another
   argument [here](https://twitter.com/timClicks/status/1584676737572487169).
3. It is okay (recommended) to `use crate::prelude::*;` in all test mod (to debate ?)
4. Have a public test framework in each top level mod inside `src/{module}/test_utils(.rs)`. Avoid scattered utils,
   factorize them.
5. Each test SHOULD test one and only one thing. It SHOULD not iterate over multiple cases.
6. test method names SHOULD
    1. follow the template `should_{expected_behaviour}_when_{state_tested}`
       e.g. `should_succeed_when_...` & `should_fail_when_...` and use natural language
    2. not be prefixed by `test_`
   3. `ValSem` SHOULD not be in the test method name but kept in comment (will be fixed
      by [#1126](https://github.com/openmls/openmls/issues/1126))
7. There SHOULD not be a `test-utils` feature (best effort). All those helpers SHOULD be `#[cfg(test)]` instead and used
   only in unit tests
8. Utilities SHOULD NOT unwrap Results to give a chance, depending on the context, to assert an error. Hence, they should
   all start with `try_` e.g. I might sometimes expect `try_talk_to` to fail even if most of the time I don't.
9. When it comes to testing MlsGroup, the following utilities would help a lot. More to be added...
   1. `MlsGroup::try_init(case: &TestCase, client: &str) -> Result(MlsGroup, CredentialBundle)` e.g.
       ```rust
       let (mut alice_group, ..) = MlsGroup::try_init(&case, "Alice").unwrap();
       ```
   2. `MlsGroup::try_invite<const N: usize>(&mut self, case: &TestCase, others: &mut [&str ; N]) -> Result<[(MlsGroup, CredentialBundle) ; N]>` e.g.
      ```rust
      let (mut alice_group, ..) = MlsGroup::try_init(&case, "Alice").unwrap();
      let [(mut bob_group, ..), (mut charly_group, ..)] = alice_group.try_invite(&case, ["Bob", "Charly"]).unwrap();
      ```
   3. `MlsGroup::try_talk_to<const N: usize>(&mut self, case: &TestCase, others: &mut [MlsGroup ; N])` e.g.
      ```rust
      let (mut alice_group, ..) = MlsGroup::try_init(&case, "Alice").unwrap();
      let [(mut bob_group, ..), (mut charly_group, ..)] = alice_group.try_invite(&case, ["Bob", "Charly"]).unwrap();
      assert!(alice_group.try_talk_to(&case, &mut [bob_group, charly_group]).is_ok());
      ```
10. Fixtures: in order for being more flexible, they could just require a single `case` variable. It would look like
    this:
    ```rust
    pub struct TestCase<T: OpenMlsCryptoProvider = OpenMlsRustCrypto> {
        pub ciphersuite: Ciphersuite,
        pub backend: T,
        pub cfg: MlsGroupConfig,
    }

    #[apply(mls_test)]
    fn should_bla_when_blabla(case: TestCase) {
        let (mut alice_group, ..) = MlsGroup::try_init(&case, "Alice").unwrap();
        let [(mut bob_group, ..), (mut charly_group, ..)] = alice_group.try_invite(&case, ["Bob", "Charly"]).unwrap();
        assert!(alice_group.try_talk_to(&case, &mut [bob_group, charly_group]).is_ok());
    }
    ```
    1. Does it make sense to keep the backend in fixtures ? I don't see openmls supporting anything else other
       than `MemoryKeyStore`.
    2. `MlsGroupConfig` is introduced to tune the `WireFormatPolicy` to make sure everything also works
       in `PURE_CIPHERTEXT` mode.
11. Test file layout
    * Do not hesitate nesting your tests within mod. They provide better readability. They can be collapsed/expanded.
      Rule of thumb could be `1 method = 1 mod` but it can be otherwise.
    * Imports SHOULD live in the top `tests` mod to avoid duplicates. Nested mods SHOULD not have anything other
      than `use super::*;`
    * Within a nested mod you can avoid repeating the mod name e.g.
      ~~`method_a_should_bla_when_blabla`~~ -> `should_bla_when_blabla`
    ```rust
    impl MyStruct {
        pub fn method_a() {}
        // snip
        fn method_z() {}
    }
    
    // No `#[cfg(features = "test-utils")]`
    
    #[test]
    mod tests {
        use super::*;
        use crate::prelude::*; // if required
    
        mod a {
            use super::*; // <- no other imports here. 
            // If one is required, add it to tests mod. This avoids duplicates.
    
            #[test]
            fn should_bla_when_blabla_1() {}
    
            // snip
            #[test]
            fn should_bla_when_blabla_n() {}
        }
    
        // snip
    
        mod z {
            use super::*;
    
            #[test]
            fn should_bla_when_blabla_1() {}
    
            // snip
            #[test]
            fn should_bla_when_blabla_n() {}
        }
    }
    ```

12. Crate layout
    * unit tests in `src` in the file they relate to
    * a `test_utils` mod SHOULD live in each top level mod. It SHOULD be declared with `#[cfg(test)]` in parent `mod.rs`
    * Those test utils SHOULD contain all the reusable helpers to write unit tests in all the other inner files.
    * Those test utils are public and can be used by other top level mods e.g. `z` can use `a`'s utils
    ```text
    src
    ├── a
    │ ├── mod.rs <- unit tests here
    │ └── test_utils.rs <- public helpers for unit tests #[cfg(test)]
    │ -- snip --
    ├── z
    │ ├── mod.rs
    │ └── test_utils.rs
    tests <- integration tests with public api only
    ├── a.rs
    │ -- snip --
    └── z.rs
    ```

13. Integration tests live in `./tests` folder. 
    1. There SHOULD be one mod per source mod. 
    2. Integration tests SHOULD only use the public API.
    3. They could be used as examples in the book

## Bonus

* We could use mutation testing to "test out tests". A good crate available for doing that
  is [mutagen](https://github.com/llogiq/mutagen). After annotating all the methods in the [`tree` mod](src/tree) it
  gives the [following result](https://github.com/beltram/openmls/blob/mutation/openmls/MUTATION.txt) with ~= 1/3 of
  mutants surviving i.e. not rightfully tested
* If WASM is a target we could already use [wasm-bindgen-test](https://crates.io/crates/wasm-bindgen-test) macros on all
  tests methods (no async migration required at that point, only a few things to fix: rayon, time, rng)
* Use [nextest](https://crates.io/crates/cargo-nextest) to execute test in the CI because it is faster (19s vs 30s for
  cargo test)
* Implement (derive) [arbitrary](https://crates.io/crates/arbitrary) for every type and use structured fuzzing