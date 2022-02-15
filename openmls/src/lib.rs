//! # OpenMLS
//!
//! OpenMLS is an implementation of the [MLS RFC].
//!
//! The main entry point for most consumers should be the [MlsGroup](prelude::MlsGroup).
//! It provides an safe, opinionated API for interacting with core groups.
//!
//! ## Error handling
//!
//! OpenMLS is panic-free.
//! All functions that can potentially fail at some point return a [Result].
//!
//! Each module has an `errors.rs` defining module specific errors that are used
//! within the crate. This exposes some of the module errors that are publicly relevant.
//! All errors implement the [`Error`](`std::error::Error`) trait and
//! [`PartialEq`](`std::cmp::PartialEq`).
//!
//! See the [mod@error] module for more details.
//!
//! [MLS RFC]: https://datatracker.ietf.org/doc/draft-ietf-mls-protocol/
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(test), forbid(unsafe_code))]
// #![cfg_attr(not(feature = "test-utils"), warn(missing_docs))]

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
pub mod config;
pub mod credentials;
pub mod extensions;
pub mod framing;
pub mod group;
pub mod key_packages;
pub mod key_store;
pub mod messages;
pub mod schedule;

// Private
mod binary_tree;
mod tree;
mod treesync;

/// Single place, re-exporting the most used public functions.
pub mod prelude;
