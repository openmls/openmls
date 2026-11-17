//! # SQLite Storage
//!
//! This crate provides the [`SqliteStorageProvider`] which implements the
//! OpenMLS trait [`StorageProvider`] using the `rusqlite` crate.
//!
//! ## Usage
//!
//! Generally, the [`SqliteStorageProvider`] can be used like any other storage
//! provider. However, before first use, the database needs to be initialized.
//! This is done using the [`SqliteStorageProvider::run_migrations()`] method.
//!
//! ### Codec
//!
//! The [`SqliteStorageProvider`] can be instantiated with any codec that make
//! use of the [`Serialize`] and [`DeserializeOwned`] traits of the `serde`
//! crate. The codec is set by implementing [`Codec`] and passing the
//! implementation as generic parameter to the [`SqliteStorageProvider`] upon
//! creation.
//!
//! ## Support
//!
//! The SQLite storage provider currently does not support the `wasm32` target.
//!
//! The provider exposes a sync API and needs the sync mode of `openmls_traits`.
//! No crate in the build may enable the `async` feature of `openmls` or
//! `openmls_traits`. Otherwise the crate fails to compile with a message that
//! names the problem.

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
#[cfg(feature = "virtual-clients-draft")]
mod vc_secrets;
mod wrappers;

pub use codec::Codec;
pub use rusqlite::Connection;
pub use storage_provider::SqliteStorageProvider;

openmls_traits::require_sync_mode!("openmls_sqlite_storage");

/// The version of the storage provider. If the `CURRENT_VERSION` of the OpenMLS
/// storage provider trait changes, the read/write/delete functions of the
/// affected data types must be updated and a migration file must be created to
/// migrate the database's schema and its content. Only then may this version be
/// incremented to match the `CURRENT_VERSION`.
const STORAGE_PROVIDER_VERSION: u16 = 1;
