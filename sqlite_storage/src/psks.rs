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

pub(crate) struct StorablePskBundle<PskBundle: Entity<CURRENT_VERSION>>(PskBundle);

impl<PskBundle: Entity<CURRENT_VERSION>> Storable for StorablePskBundle<PskBundle> {
    const CREATE_TABLE_STATEMENT: &'static str = "CREATE TABLE IF NOT EXISTS psks (
        psk_id BLOB PRIMARY KEY,
        psk_bundle BLOB NOT NULL
    );";

    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(psk, ..) = row.get(0)?;
        Ok(Self(psk))
    }
}

impl<PskBundle: Entity<CURRENT_VERSION>> StorablePskBundle<PskBundle> {
    pub(super) fn load<C: Codec, PskId: Key<CURRENT_VERSION>>(
        connection: &rusqlite::Connection,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, rusqlite::Error> {
        let mut stmt = connection.prepare("SELECT psk_bundle FROM psks WHERE psk_id = ?1")?;
        stmt.query_row(
            params![KeyRefWrapper::<C, _>(psk_id, PhantomData)],
            Self::from_row::<C>,
        )
        .map(|x| x.0)
        .optional()
    }
}

pub(super) struct StorablePskBundleRef<'a, PskBundle: Entity<CURRENT_VERSION>>(pub &'a PskBundle);

impl<PskBundle: Entity<CURRENT_VERSION>> StorablePskBundleRef<'_, PskBundle> {
    pub(super) fn store<C: Codec, PskId: Key<CURRENT_VERSION>>(
        &self,
        connection: &rusqlite::Connection,
        psk_id: &PskId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO psks (psk_id, psk_bundle) VALUES (?1, ?2)",
            params![
                KeyRefWrapper::<C, _>(psk_id, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

pub(super) struct StorablePskIdRef<'a, PskId: Key<CURRENT_VERSION>>(pub &'a PskId);

impl<'a, PskId: Key<CURRENT_VERSION>> StorablePskIdRef<'a, PskId> {
    pub(super) fn delete<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM psks WHERE psk_id = ?1",
            params![KeyRefWrapper::<C, _>(self.0, PhantomData)],
        )?;
        Ok(())
    }
}
