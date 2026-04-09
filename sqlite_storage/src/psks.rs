use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key};
use rusqlite::{params, OptionalExtension};

use crate::{
    codec::Codec,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    STORAGE_PROVIDER_VERSION,
};

pub(crate) struct StorablePskBundle<PskBundle: Entity<STORAGE_PROVIDER_VERSION>>(PskBundle);

impl<PskBundle: Entity<STORAGE_PROVIDER_VERSION>> StorablePskBundle<PskBundle> {
    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(psk, ..) = row.get(0)?;
        Ok(Self(psk))
    }

    pub(super) fn load<C: Codec, PskId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &rusqlite::Connection,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, rusqlite::Error> {
        let mut stmt = connection.prepare(
            "SELECT psk_bundle
                FROM openmls_psks
                WHERE psk_id = ?1
                    AND provider_version = ?2",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, _>(psk_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            Self::from_row::<C>,
        )
        .map(|x| x.0)
        .optional()
    }
}

pub(super) struct StorablePskBundleRef<'a, PskBundle: Entity<STORAGE_PROVIDER_VERSION>>(
    pub &'a PskBundle,
);

impl<PskBundle: Entity<STORAGE_PROVIDER_VERSION>> StorablePskBundleRef<'_, PskBundle> {
    pub(super) fn store<C: Codec, PskId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        connection: &rusqlite::Connection,
        psk_id: &PskId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT OR REPLACE INTO openmls_psks (psk_id, psk_bundle, provider_version)
            VALUES (?1, ?2, ?3)",
            params![
                KeyRefWrapper::<C, _>(psk_id, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        Ok(())
    }
}

pub(super) struct StorablePskIdRef<'a, PskId: Key<STORAGE_PROVIDER_VERSION>>(pub &'a PskId);

impl<PskId: Key<STORAGE_PROVIDER_VERSION>> StorablePskIdRef<'_, PskId> {
    pub(super) fn delete<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM openmls_psks
            WHERE psk_id = ?1
                AND provider_version = ?2",
            params![
                KeyRefWrapper::<C, _>(self.0, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        Ok(())
    }
}
