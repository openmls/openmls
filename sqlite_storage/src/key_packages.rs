// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key, CURRENT_VERSION};
use rusqlite::{params, OptionalExtension};

use crate::{
    codec::Codec,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    Storable,
};

pub(crate) struct StorableKeyPackage<KeyPackage: Entity<CURRENT_VERSION>>(pub KeyPackage);

impl<KeyPackage: Entity<CURRENT_VERSION>> Storable for StorableKeyPackage<KeyPackage> {
    const CREATE_TABLE_STATEMENT: &'static str = "CREATE TABLE IF NOT EXISTS key_packages (
        key_package_ref BLOB PRIMARY KEY,
        key_package BLOB NOT NULL
    );";

    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(key_package, ..) = row.get(0)?;
        Ok(Self(key_package))
    }
}

impl<KeyPackage: Entity<CURRENT_VERSION>> StorableKeyPackage<KeyPackage> {
    pub(super) fn load<C: Codec, KeyPackageRef: Key<CURRENT_VERSION>>(
        connection: &rusqlite::Connection,
        key_package_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, rusqlite::Error> {
        connection
            .query_row(
                "SELECT key_package FROM key_packages WHERE key_package_ref = ?1",
                params![KeyRefWrapper::<C, _>(key_package_ref, PhantomData)],
                |row| Self::from_row::<C>(row).map(|x| x.0),
            )
            .optional()
    }
}

pub(super) struct StorableKeyPackageRef<'a, KeyPackage: Entity<CURRENT_VERSION>>(
    pub &'a KeyPackage,
);

impl<'a, KeyPackage: Entity<CURRENT_VERSION>> StorableKeyPackageRef<'a, KeyPackage> {
    pub(super) fn store<C: Codec, KeyPackageRef: Key<CURRENT_VERSION>>(
        &self,
        connection: &rusqlite::Connection,
        key_package_ref: &KeyPackageRef,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO key_packages (key_package_ref, key_package) VALUES (?1, ?2)",
            params![
                KeyRefWrapper::<C, _>(key_package_ref, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

pub(super) struct StorableHashRef<'a, KeyPackageRef: Key<CURRENT_VERSION>>(pub &'a KeyPackageRef);

impl<'a, KeyPackageRef: Key<CURRENT_VERSION>> StorableHashRef<'a, KeyPackageRef> {
    pub(super) fn delete_key_package<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM key_packages WHERE key_package_ref = ?1",
            params![KeyRefWrapper::<C, _>(self.0, PhantomData)],
        )?;
        Ok(())
    }
}
