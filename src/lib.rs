//! # OpenMLS
//!
//! ## High-level API
//!
//! See [ManagedGroup](`prelude::ManagedGroup`)
//!
//! ## Low-level API
//!
//! See [MlsGroup](`prelude::MlsGroup`)
//!
//! ## Errors
//!
//! Each module has an `errors.rs` defining module specific errors that are used
//! within the crate. This exposes some of the
//! module errors that are publicly relevant.
//! All errors implement the [`Error`](`std::error::Error`) trait and
//! [`PartialEq`](`std::cmp::PartialEq`).
//!
//! The high-level errors API in [`error`](`error`) are a different error
//! representation as `u16` for C FFI APIs.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

#[macro_use]
mod utils;

#[macro_use]
pub mod error;

#[cfg(any(feature = "expose-test-vectors", test))]
#[macro_use]
pub mod test_util;
pub mod binary_tree;

mod ciphersuite;
mod codec;
pub mod config;
mod credentials;
mod extensions;
pub mod framing;
pub mod group;
mod key_packages;
pub mod key_store;
pub mod messages;
#[cfg(any(feature = "expose-test-vectors", test))]
pub mod schedule;
#[cfg(not(any(feature = "expose-test-vectors", test)))]
mod schedule;
pub mod tree;

pub use crate::tree::node;

/// Single place, re-exporting the most used public functions.
pub mod prelude;
