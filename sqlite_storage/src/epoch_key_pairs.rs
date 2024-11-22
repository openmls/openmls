
use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key, CURRENT_VERSION};
use rusqlite::{params, OptionalExtension};

use crate::{
    codec::Codec,
    storage_provider::StorableGroupIdRef,
    wrappers::{EntitySliceWrapper, EntityVecWrapper, KeyRefWrapper},
    Storable,
};

impl<EpochKeyPairs: Entity<CURRENT_VERSION>> Storable for StorableEpochKeyPairs<EpochKeyPairs> {
    const CREATE_TABLE_STATEMENT: &'static str = "CREATE TABLE IF NOT EXISTS epoch_keys_pairs (
        group_id BLOB NOT NULL,
        epoch_id BLOB NOT NULL,
        leaf_index INTEGER NOT NULL,
        key_pairs BLOB NOT NULL,
        PRIMARY KEY (group_id, epoch_id, leaf_index)
    );";

    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityVecWrapper::<C, _>(key_pairs, ..) = row.get(0)?;
        Ok(Self(key_pairs))
    }
}

pub(crate) struct StorableEpochKeyPairs<EpochKeyPairs: Entity<CURRENT_VERSION>>(
    pub Vec<EpochKeyPairs>,
);

impl<EpochKeyPairs: Entity<CURRENT_VERSION>> StorableEpochKeyPairs<EpochKeyPairs> {
    pub(super) fn load<C: Codec, GroupId: Key<CURRENT_VERSION>, EpochKey: Key<CURRENT_VERSION>>(
        connection: &rusqlite::Connection,
        group_id: &GroupId,
        epoch_id: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<EpochKeyPairs>, rusqlite::Error> {
        let mut stmt = connection.prepare(
            "SELECT key_pairs FROM epoch_keys_pairs WHERE group_id = ?1 AND epoch_id = ?2 AND leaf_index = ?3",
        )?;
        let result = stmt
            .query_row(
                params![
                    KeyRefWrapper::<C, _>(group_id, PhantomData),
                    KeyRefWrapper::<C, _>(epoch_id, PhantomData),
                    leaf_index
                ],
                |row| Self::from_row::<C>(row).map(|x| x.0),
            )
            .optional()?
            .unwrap_or_default();
        Ok(result)
    }
}

pub(super) struct StorableEpochKeyPairsRef<'a, EpochKeyPairs: Entity<CURRENT_VERSION>>(
    pub &'a [EpochKeyPairs],
);

impl<'a, EpochKeyPairs: Entity<CURRENT_VERSION>> StorableEpochKeyPairsRef<'a, EpochKeyPairs> {
    pub(super) fn store<C: Codec, GroupId: Key<CURRENT_VERSION>, EpochKey: Key<CURRENT_VERSION>>(
        &self,
        connection: &rusqlite::Connection,
        group_id: &GroupId,
        epoch_id: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO epoch_keys_pairs (group_id, epoch_id, leaf_index, key_pairs) VALUES (?1, ?2, ?3, ?4)",
            params![KeyRefWrapper::<C,_>(group_id, PhantomData), KeyRefWrapper::<C,_>(epoch_id, PhantomData), leaf_index, EntitySliceWrapper::<'_, C,_>(self.0, PhantomData)],
        )?;
        Ok(())
    }
}

impl<'a, GroupId: Key<CURRENT_VERSION>> StorableGroupIdRef<'a, GroupId> {
    pub(super) fn delete_epoch_key_pair<C: Codec, EpochKey: Key<CURRENT_VERSION>>(
        &self,
        connection: &rusqlite::Connection,
        epoch_key: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM epoch_keys_pairs WHERE group_id = ?1 AND epoch_id = ?2 AND leaf_index = ?3",
            params![KeyRefWrapper::<C,_>(self.0, PhantomData), KeyRefWrapper::<C,_>(epoch_key, PhantomData), leaf_index],
        )?;
        Ok(())
    }
}
