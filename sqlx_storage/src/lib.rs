// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{cell::RefCell, marker::PhantomData};

use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};
use serde::Serialize;
use sqlx::SqliteConnection;

pub use crate::codec::Codec;

pub(crate) mod codec;
pub(crate) mod encryption_key_pairs;
pub(crate) mod epoch_key_pairs;
pub(crate) mod group_data;
pub(crate) mod key_packages;
pub(crate) mod own_leaf_nodes;
pub(crate) mod proposals;
pub(crate) mod psks;
pub(crate) mod signature_key_pairs;
pub(crate) mod storage_provider;

pub struct SqliteStorageProvider<'a, C> {
    connection: RefCell<&'a mut SqliteConnection>,
    codec: PhantomData<C>,
}

impl<'a, C: Codec> SqliteStorageProvider<'a, C> {
    pub fn new(connection: &'a mut SqliteConnection) -> Self {
        Self {
            connection: RefCell::new(connection),
            codec: PhantomData,
        }
    }

    pub async fn run_migrations(&mut self) -> Result<(), sqlx::migrate::MigrateError> {
        let mut conn = self.connection.borrow_mut();
        sqlx::migrate!("./migrations").run(&mut **conn).await
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

struct EntityWrapper<T: Entity<CURRENT_VERSION>, C: Codec>(T, PhantomData<C>);

struct EntityRefWrapper<'a, T: Entity<CURRENT_VERSION>, C: Codec>(&'a T, PhantomData<C>);

struct EntitySliceWrapper<'a, T: Entity<CURRENT_VERSION>, C: Codec>(&'a [T], PhantomData<C>);

struct EntityVecWrapper<T: Entity<CURRENT_VERSION>, C: Codec>(pub Vec<T>, PhantomData<C>);

struct StorableGroupIdRef<'a, GroupId: Key<CURRENT_VERSION>, C: Codec>(
    pub &'a GroupId,
    PhantomData<C>,
);
