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
//! All errors implement `Debug`, `Display`, `PartialEq`, and `description` of
//! the `Error` trait.
//!
//! The C FFI API exposes the errors represented  as u16.

#[macro_use]
mod utils;

mod ciphersuite;
mod codec;
mod config;
mod creds;
mod extensions;
mod framing;
mod fs;
mod group;
mod key_packages;
mod messages;
mod schedule;
mod tree;

/// Single place, re-exporting the most used public functions.
pub mod prelude;
