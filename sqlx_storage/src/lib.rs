#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
//! # SQLx Storage Provider
//!
//! This crate implements a storage provider for OpenMLS using SQLx. The only
//! supported database is currently SQLite.
//!
//! The main struct is [`SqliteStorageProvider`], which implements the
//! [`StorageProvider`](openmls_traits::storage::StorageProvider) trait from the
//! `openmls_traits` crate.
//!
//! The crate manages its own database migrations in its own migrations table
//! with the name `_openmls_sqlx_migrations`. All tables created by this crate
//! are prefixed with `openmls_` to avoid name clashes.
//!
//! ## Transactions
//!
//! [`SqliteStorageProvider`] borrows a [`SqliteConnection`]. A
//! [`sqlx::Transaction`] dereferences to a [`SqliteConnection`], so a provider
//! can run against an open transaction by passing `&mut *transaction` to
//! [`SqliteStorageProvider::new`]. Every write the provider performs is then
//! part of that transaction and commits or rolls back together with your
//! application's own writes against the same database. The provider borrows the
//! transaction for as long as it is alive, so scope it and let it drop before
//! using the transaction directly again or committing it.
//!
//! Run [`SqliteStorageProvider::run_migrations`] on the bare connection rather
//! than inside a transaction, so the schema is not tied to the lifetime of a
//! single transaction.
//!
//! See `examples/transaction.rs` for a complete, runnable example.
//!
//! ## Runtime
//!
//! The provider exposes an async API and needs the async mode of
//! `openmls_traits`. Enable its `async` feature, or the `async` feature of
//! `openmls`, and make sure no crate in the build enables `sync`.
//!
//! Calls on one provider are serialized by an async mutex around the
//! connection, so concurrent OpenMLS operations that share a provider wait for
//! each other. The futures are `Send` and can run on a multi-threaded runtime.

use std::marker::PhantomData;

use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};
use serde::Serialize;
use sqlx::SqliteConnection;
use tokio::sync::Mutex;

pub use crate::codec::Codec;
use crate::migrator::MigratorWrapper;

openmls_traits::require_async_mode!("openmls_sqlx_storage");

mod codec;
mod group_data;
mod migrator;
mod storage_provider;
mod wrappers;

/// [`SqliteStorageProvider`] implements the
/// [`StorageProvider`](openmls_traits::storage::StorageProvider) trait and can
/// thus be used as a storage provider for OpenMLS.
///
/// It is generic over any codec `C` that implements the [`Codec`] trait.
/// The codec is used to serialize and deserialize the data stored in the
/// underlying database.
pub struct SqliteStorageProvider<'a, C> {
    connection: Mutex<&'a mut SqliteConnection>,
    codec: PhantomData<C>,
}

impl<'a, C: Codec> SqliteStorageProvider<'a, C> {
    /// Create a new [`SqliteStorageProvider`] based on the given
    /// [`SqliteConnection`].
    pub fn new(connection: &'a mut SqliteConnection) -> Self {
        Self {
            connection: Mutex::new(connection),
            codec: PhantomData,
        }
    }

    /// Run the migrations for the storage provider using sqlx's built-in
    /// migration support.
    pub async fn run_migrations(&mut self) -> Result<(), sqlx::migrate::MigrateError> {
        let connection = self.connection.get_mut();
        sqlx::migrate!("./migrations")
            .run_direct(&mut MigratorWrapper(connection))
            .await?;
        Ok(())
    }

    fn wrap_storable_group_id_ref<'b, GroupId: Key<CURRENT_VERSION>>(
        &self,
        group_id: &'b GroupId,
    ) -> StorableGroupIdRef<'b, GroupId, C> {
        StorableGroupIdRef(group_id, PhantomData)
    }
}

#[derive(Debug, Serialize)]
struct KeyRefWrapper<'a, T: Key<CURRENT_VERSION>, C: Codec>(&'a T, PhantomData<C>);

impl<'a, T: Key<CURRENT_VERSION>, C: Codec> KeyRefWrapper<'a, T, C> {
    fn new(value: &'a T) -> Self {
        Self(value, PhantomData)
    }
}

struct EntityRefWrapper<'a, T: Entity<CURRENT_VERSION>, C: Codec>(&'a T, PhantomData<C>);

impl<'a, T: Entity<CURRENT_VERSION>, C: Codec> EntityRefWrapper<'a, T, C> {
    fn new(value: &'a T) -> Self {
        Self(value, PhantomData)
    }
}

struct EntitySliceWrapper<'a, T: Entity<CURRENT_VERSION>, C: Codec>(&'a [T], PhantomData<C>);

struct StorableGroupIdRef<'a, GroupId: Key<CURRENT_VERSION>, C: Codec>(&'a GroupId, PhantomData<C>);
