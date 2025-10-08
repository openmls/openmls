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

use std::{cell::RefCell, marker::PhantomData};

use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};
use serde::Serialize;
use sqlx::SqliteConnection;

pub use crate::codec::Codec;
use crate::{migrator::MigratorWrapper, storage_provider::block_async_in_place};

pub(crate) mod codec;
pub(crate) mod encryption_key_pairs;
pub(crate) mod epoch_key_pairs;
pub(crate) mod group_data;
pub(crate) mod key_packages;
mod migrator;
pub(crate) mod own_leaf_nodes;
pub(crate) mod proposals;
pub(crate) mod psks;
pub(crate) mod signature_key_pairs;
pub(crate) mod storage_provider;

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
            sqlx::migrate!("./migrations").run_direct(&mut MigratorWrapper(&mut *conn)),
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
