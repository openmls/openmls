use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key};
use rusqlite::{params, OptionalExtension};

use crate::{
    codec::Codec,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
};

pub(crate) struct StorablePskBundle<PskBundle: Entity<1>>(PskBundle);

impl<PskBundle: Entity<1>> StorablePskBundle<PskBundle> {
    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(psk, ..) = row.get(0)?;
        Ok(Self(psk))
    }

    pub(super) fn load<C: Codec, PskId: Key<1>>(
        connection: &rusqlite::Connection,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, rusqlite::Error> {
        let mut stmt =
            connection.prepare("SELECT psk_bundle FROM openmls_psks WHERE psk_id = ?1")?;
        stmt.query_row(
            params![KeyRefWrapper::<C, _>(psk_id, PhantomData)],
            Self::from_row::<C>,
        )
        .map(|x| x.0)
        .optional()
    }
}

pub(super) struct StorablePskBundleRef<'a, PskBundle: Entity<1>>(pub &'a PskBundle);

impl<PskBundle: Entity<1>> StorablePskBundleRef<'_, PskBundle> {
    pub(super) fn store<C: Codec, PskId: Key<1>>(
        &self,
        connection: &rusqlite::Connection,
        psk_id: &PskId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO openmls_psks (psk_id, psk_bundle) VALUES (?1, ?2)",
            params![
                KeyRefWrapper::<C, _>(psk_id, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

pub(super) struct StorablePskIdRef<'a, PskId: Key<1>>(pub &'a PskId);

impl<'a, PskId: Key<1>> StorablePskIdRef<'a, PskId> {
    pub(super) fn delete<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM openmls_psks WHERE psk_id = ?1",
            params![KeyRefWrapper::<C, _>(self.0, PhantomData)],
        )?;
        Ok(())
    }
}
