//! # SQLite Storage
//!
//! This crate provides the [`SqliteStorageProvider`] which implements the
//! OpenMLS trait [`StorageProvider`] using the `rusqlite` crate.
//!
//! ## Usage
//!
//! Generally, the [`SqliteStorageProvider`] can be used like any other storage
//! provider. However, before first use, the tables need to be created. This can
//! be done using the [`SqliteStorageProvider::create_tables`] method.
//!
//! ### Codec
//!
//! The [`SqliteStorageProvider`] can be instantiated with any codec that make
//! use of the [`Serialize`] and [`DeserializeOwned`] traits of the `serde`
//! crate. The codec is set by implementing [`Codec`] and passing the
//! implementation as generic parameter to the [`SqliteStorageProvider`] upon
//! creation.

#[cfg(doc)]
use openmls_traits::storage::StorageProvider;

#[cfg(doc)]
use serde::{de::DeserializeOwned, Serialize};

mod codec;
mod encryption_key_pairs;
mod epoch_key_pairs;
mod group_data;
mod key_packages;
mod own_leaf_nodes;
mod proposals;
mod psks;
mod signature_key_pairs;
mod storage_provider;
mod wrappers;

pub use codec::Codec;
pub use storage_provider::SqliteStorageProvider;
