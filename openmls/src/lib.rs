//! # OpenMLS
//!
//! OpenMLS is an implementation of the proposed [MLS protocol].
//!
//! The main entry point for most consumers should be the [MlsGroup](prelude::MlsGroup).
//! It provides an safe, opinionated API for interacting with core groups.
//!
//! More information on how to use the library can be found in the [User Manual].
//!
//! ## Error handling
//!
//! Most function calls in the library return a `Result` and can therefore surface errors to the library consumer.
//! Errors can have different sources, depending on their nature. The following list explains the different error sources and how to handle them:
//!
//! ### Errors in dependencies
//!
//! The OpenMLS library relies on external dependencies for cryptographic primitives and storage of cryptographic key material. See the traits in the [User Manual] for more details on the dependencies.
//! When an unexpected error occurs in one of those dependencies, it is usually surfaced as a `LibraryError` to the consumer.
//!
//! ### Errors induced by wrong API use
//!
//! Whenever the caller calls an OpenMLS function with invalid input, an error is returned. Examples of wrong input can be: Adding a member twice to a group, interacting with an inactive group, removing inexistent
//! members from a group, etc. The precise error message depends on the function called, and the error will typically be an `enum` with explicit variants that state the reason for the error.
//! Consumers can branch on the variants of the `enum` and take action accordingly.
//!
//! ### Errors induced by processing invalid payload
//!
//! The library processes external payload in the form of messages sent over a network, or state loaded from disk. In both cases, multi-layered checks need to be done to make sure the payload
//! is syntactically and semantically correct. The syntax checks typically all happen at the serialization level and get detected early on. Semantic validation is more complex because data needs to be evaluated
//! in context. You can find more details about validation in the validation chapter of the [User Manual].
//! These errors are surfaced to the consumer at various stages of the processing, and the processing is aborted for the payload in question. Much like errors induced by wrong API usage, these errors are `enums` that
//! contain explicit variants for every error type. Consumers can branch on these variants to take action according to the specific error.
//!
//! ### Correctness errors in the library itself
//!
//! While the library has good test coverage in the form of unit & integration tests, theoretical correctness errors cannot be completely excluded. Should such an error occur, consumers will get
//! a `LibraryError` as a return value that contains backtraces indicating where in the code the error occurred and a short string for context. These details are important for debugging the library in such a case.
//! Consumers should save this information.
//!
//! All errors derive [`thiserror::Error`](https://docs.rs/thiserror/latest/thiserror/) as well as
//! [`Debug`](`std::fmt::Debug`), [`PartialEq`](`std::cmp::PartialEq`), and [`Clone`](`std::clone::Clone`).
//!
//! See the [mod@error] module for more details.
//!
//! [MLS protocol]: https://datatracker.ietf.org/doc/draft-ietf-mls-protocol/
//! [User Manual]: https://openmls.tech/book
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(not(feature = "test-utils"), warn(missing_docs))]

// === Testing ===

/// Single place, re-exporting all structs and functions needed for integration tests
#[cfg(any(feature = "test-utils", test))]
pub mod prelude_test;

#[cfg(any(feature = "test-utils", test))]
pub use rstest_reuse;

#[cfg(any(feature = "test-utils", test))]
#[macro_use]
pub mod test_utils;

// === Modules ===

#[macro_use]
mod utils;

#[macro_use]
pub mod error;

// Public
pub mod ciphersuite;
pub mod credentials;
pub mod extensions;
pub mod framing;
pub mod group;
pub mod key_packages;
pub mod key_store;
pub mod messages;
pub mod schedule;
pub mod versions;

// Private
mod binary_tree;
mod tree;
mod treesync;

/// Single place, re-exporting the most used public functions.
pub mod prelude;
