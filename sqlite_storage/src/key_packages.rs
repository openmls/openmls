use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key};
use rusqlite::{params, OptionalExtension};

use crate::{
    codec::Codec,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
};

pub(crate) struct StorableKeyPackage<KeyPackage: Entity<1>>(pub KeyPackage);

impl<KeyPackage: Entity<1>> StorableKeyPackage<KeyPackage> {
    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(key_package, ..) = row.get(0)?;
        Ok(Self(key_package))
    }

    pub(super) fn load<C: Codec, KeyPackageRef: Key<1>>(
        connection: &rusqlite::Connection,
        key_package_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, rusqlite::Error> {
        connection
            .query_row(
                "SELECT key_package FROM openmls_key_packages WHERE key_package_ref = ?1",
                params![KeyRefWrapper::<C, _>(key_package_ref, PhantomData)],
                |row| Self::from_row::<C>(row).map(|x| x.0),
            )
            .optional()
    }
}

pub(super) struct StorableKeyPackageRef<'a, KeyPackage: Entity<1>>(pub &'a KeyPackage);

impl<'a, KeyPackage: Entity<1>> StorableKeyPackageRef<'a, KeyPackage> {
    pub(super) fn store<C: Codec, KeyPackageRef: Key<1>>(
        &self,
        connection: &rusqlite::Connection,
        key_package_ref: &KeyPackageRef,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO openmls_key_packages (key_package_ref, key_package) VALUES (?1, ?2)",
            params![
                KeyRefWrapper::<C, _>(key_package_ref, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

pub(super) struct StorableHashRef<'a, KeyPackageRef: Key<1>>(pub &'a KeyPackageRef);

impl<'a, KeyPackageRef: Key<1>> StorableHashRef<'a, KeyPackageRef> {
    pub(super) fn delete_key_package<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM openmls_key_packages WHERE key_package_ref = ?1",
            params![KeyRefWrapper::<C, _>(self.0, PhantomData)],
        )?;
        Ok(())
    }
}
