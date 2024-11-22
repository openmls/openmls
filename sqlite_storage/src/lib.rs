//! # SQLite Storage
//!
//! This crate provides the [`SqliteStorageProvider`] which implements the
//! OpenMLS trait [`StorageProvider`] using the `rusqlite` crate.
//!
//! ## Usage
//!
//! TODO: Show how to combine with an rng and crypto provider in the context of
//! OpenMLS. Also show how data (e.g. KeyPackages) can be retrieved by the
//! application outside of OpenMLS.

#[cfg(doc)]
use openmls_traits::storage::StorageProvider;

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

pub use codec::{Codec, JsonCodec};
pub use storage_provider::SqliteStorageProvider;

trait Storable {
    const CREATE_TABLE_STATEMENT: &'static str;

    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error>
    where
        Self: Sized;
}
