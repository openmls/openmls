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

use std::marker::PhantomData;

use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};
use serde::Serialize;

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
pub struct SqliteStorageProvider<C> {
    pool: sqlx::SqlitePool,
    codec: PhantomData<C>,
}

/// A [`StorageProvider`] implementation of a transaction wrapper, for an EXCLUSIVE transaction.
///
/// Default behavior: rolls back on drop
pub struct SqliteStorageProviderWithTransaction<'a, C> {
    transaction: std::cell::RefCell<sqlx::Transaction<'a, sqlx::Sqlite>>,
    codec: PhantomData<C>,
}

impl<C> SqliteStorageProvider<C> {
    /// Begin a transaction.
    ///
    /// This transaction is started in EXCLUSIVE mode, so it locks
    /// the database for all reads and writes.
    ///
    /// If the transaction falls out of scope without being committed,
    /// it is automatically rolled back.
    pub async fn get_transaction<'a>(
        &'a self,
    ) -> Result<SqliteStorageProviderWithTransaction<'a, C>, sqlx::Error> {
        let transaction = self.pool.begin_with("BEGIN EXCLUSIVE").await?;

        Ok(SqliteStorageProviderWithTransaction {
            transaction: transaction.into(),
            codec: Default::default(),
        })
    }

    pub(crate) fn get_connection(
        &self,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Sqlite>, sqlx::Error> {
        block_async_in_place(self.pool.acquire())
    }
}

impl<'b, 'a: 'b, C> SqliteStorageProviderWithTransaction<'a, C> {
    /// Commit the transaction.
    pub async fn commit_transaction(self) -> Result<(), sqlx::Error> {
        self.transaction.into_inner().commit().await
    }

    /// Roll back the transaction.
    pub async fn rollback_transaction(self) -> Result<(), sqlx::Error> {
        self.transaction.into_inner().rollback().await
    }

    fn borrow_mut(
        &'b self,
    ) -> Result<std::cell::RefMut<'b, sqlx::SqliteTransaction<'a>>, sqlx::Error> {
        Ok(self.transaction.borrow_mut())
    }
}

impl<C: Codec> Default for SqliteStorageProvider<C> {
    /// Set up a default sqlite provider
    fn default() -> Self {
        let pool =
            block_async_in_place(sqlx::sqlite::SqlitePoolOptions::new().connect("sqlite::memory:"))
                .unwrap();

        Self::new(pool)
    }
}

impl<C: Codec> SqliteStorageProvider<C> {
    /// Create a new [`SqliteStorageProvider`] based on the given
    /// [`SqlitePool`].
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self {
            pool,
            codec: PhantomData,
        }
    }

    /// Run the migrations for the storage provider. Uses sqlx's built-in
    /// migration support.
    pub fn run_migrations(&mut self) -> Result<(), sqlx::migrate::MigrateError> {
        let task = async {
            let mut connection = self.pool.acquire().await.unwrap();

            sqlx::migrate!("./migrations")
                .run_direct(&mut MigratorWrapper(&mut connection))
                .await?;
            Ok(())
        };

        block_async_in_place(task)
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

/// helper trait for implementing the `StorageProvider` trait for
/// both `SqliteStorageProvider` and `SqliteStorageProviderWithTransaction`
trait SqlxProvider {
    type Codec: Codec;

    fn wrap_storable_group_id_ref<'b, GroupId: Key<CURRENT_VERSION>>(
        &self,
        group_id: &'b GroupId,
    ) -> StorableGroupIdRef<'b, GroupId, Self::Codec> {
        StorableGroupIdRef(group_id, PhantomData)
    }
}

impl<C: Codec> SqlxProvider for SqliteStorageProvider<C> {
    type Codec = C;
}

impl<C: Codec> SqlxProvider for SqliteStorageProviderWithTransaction<'_, C> {
    type Codec = C;
}
