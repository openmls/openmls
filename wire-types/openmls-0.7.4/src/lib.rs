//! TODO: add documentation
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![cfg(any(target_pointer_width = "32", target_pointer_width = "64",))]

// === Testing ===

// === Modules ===

#[macro_use]
mod utils;

pub mod error;

// Public
pub mod ciphersuite;
pub mod credentials;
pub mod extensions;
pub mod framing;
pub mod group;
pub mod key_packages;
pub mod messages;
pub mod schedule;
pub mod treesync;
pub mod versions;

// implement storage traits
// public
pub mod storage;

// Private
mod binary_tree;
mod tree;

/// Single place, re-exporting the most used public functions.
pub mod prelude;
