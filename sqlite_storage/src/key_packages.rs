use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key};
use rusqlite::{Connection, OptionalExtension, params};

use crate::{
    STORAGE_PROVIDER_VERSION,
    codec::Codec,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
};

pub(crate) struct StorableKeyPackage<KeyPackage: Entity<STORAGE_PROVIDER_VERSION>>(pub KeyPackage);

impl<KeyPackage: Entity<STORAGE_PROVIDER_VERSION>> StorableKeyPackage<KeyPackage> {
    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(key_package, ..) = row.get(0)?;
        Ok(Self(key_package))
    }

    pub(super) fn load<C: Codec, KeyPackageRef: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &Connection,
        key_package_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, rusqlite::Error> {
        connection
            .query_row(
                "SELECT key_package
                FROM openmls_key_packages
                WHERE key_package_ref = ?1
                    AND provider_version = ?2",
                params![
                    KeyRefWrapper::<C, _>(key_package_ref, PhantomData),
                    STORAGE_PROVIDER_VERSION
                ],
                |row| Self::from_row::<C>(row).map(|x| x.0),
            )
            .optional()
    }

    pub(super) fn load_in_tx<C: Codec, KeyPackageRef: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        key_package_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "SELECT key_package
                FROM openmls_key_packages
                WHERE key_package_ref = ?1
                    AND provider_version = ?2",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, _>(key_package_ref, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            |row| Self::from_row::<C>(row).map(|x| x.0),
        )
        .optional()
    }
}

pub(super) struct StorableKeyPackageRef<'a, KeyPackage: Entity<STORAGE_PROVIDER_VERSION>>(
    pub &'a KeyPackage,
);

impl<KeyPackage: Entity<STORAGE_PROVIDER_VERSION>> StorableKeyPackageRef<'_, KeyPackage> {
    pub(super) fn store<C: Codec, KeyPackageRef: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        connection: &Connection,
        key_package_ref: &KeyPackageRef,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "INSERT OR REPLACE INTO openmls_key_packages (key_package_ref, key_package, provider_version)
            VALUES (?1, ?2, ?3)",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(key_package_ref, PhantomData),
            EntityRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }

    pub(super) fn store_in_tx<C: Codec, KeyPackageRef: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        tx: &rusqlite::Transaction<'_>,
        key_package_ref: &KeyPackageRef,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO openmls_key_packages (key_package_ref, key_package, provider_version)
            VALUES (?1, ?2, ?3)",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(key_package_ref, PhantomData),
            EntityRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }
}

pub(super) struct StorableHashRef<'a, KeyPackageRef: Key<STORAGE_PROVIDER_VERSION>>(
    pub &'a KeyPackageRef,
);

impl<KeyPackageRef: Key<STORAGE_PROVIDER_VERSION>> StorableHashRef<'_, KeyPackageRef> {
    pub(super) fn delete_key_package<C: Codec>(
        &self,
        connection: &Connection,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "DELETE FROM openmls_key_packages
            WHERE key_package_ref = ?1
                AND provider_version = ?2",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }

    pub(super) fn delete_key_package_in_tx<C: Codec>(
        &self,
        tx: &rusqlite::Transaction<'_>,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "DELETE FROM openmls_key_packages
            WHERE key_package_ref = ?1
                AND provider_version = ?2",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }
}
