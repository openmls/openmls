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
//! The provider exposes a synchronous API and drives the underlying async
//! `sqlx` calls internally with [`tokio::task::block_in_place`]. It therefore
//! has to run on a multi-threaded tokio runtime.

use std::{cell::RefCell, marker::PhantomData};

use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};
use serde::Serialize;
use sqlx::SqliteConnection;

pub use crate::codec::Codec;
use crate::{migrator::MigratorWrapper, storage_provider::block_async_in_place};

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
    connection: RefCell<&'a mut SqliteConnection>,
    codec: PhantomData<C>,
}

impl<'a, C: Codec> SqliteStorageProvider<'a, C> {
    /// Create a new [`SqliteStorageProvider`] based on the given
    /// [`SqliteConnection`].
    pub fn new(connection: &'a mut SqliteConnection) -> Self {
        Self {
            connection: RefCell::new(connection),
            codec: PhantomData,
        }
    }

    /// Run the migrations for the storage provider. Uses sqlx's built-in
    /// migration support.
    pub fn run_migrations(&mut self) -> Result<(), sqlx::migrate::MigrateError> {
        let mut conn = self.connection.borrow_mut();
        block_async_in_place(
            sqlx::migrate!("./migrations").run_direct(&mut MigratorWrapper(*conn)),
        )?;
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
