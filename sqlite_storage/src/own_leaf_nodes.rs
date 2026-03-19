use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key};
use rusqlite::{params, Connection};

use crate::{
    codec::Codec,
    storage_provider::StorableGroupIdRef,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    STORAGE_PROVIDER_VERSION,
};

pub(crate) struct StorableLeafNode<LeafNode: Entity<STORAGE_PROVIDER_VERSION>>(pub LeafNode);

impl<LeafNode: Entity<STORAGE_PROVIDER_VERSION>> StorableLeafNode<LeafNode> {
    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(leaf_node, ..) = row.get(0)?;
        Ok(Self(leaf_node))
    }

    pub(super) fn load<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &Connection,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "SELECT leaf_node
            FROM openmls_own_leaf_nodes
            WHERE group_id = ?
                AND provider_version = ?",
        )?;
        let leaf_nodes = stmt
            .query_map(
                params![
                    KeyRefWrapper::<C, _>(group_id, PhantomData),
                    STORAGE_PROVIDER_VERSION
                ],
                |row| Self::from_row::<C>(row).map(|x| x.0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(leaf_nodes)
    }

    pub(super) fn load_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "SELECT leaf_node
            FROM openmls_own_leaf_nodes
            WHERE group_id = ?
                AND provider_version = ?",
        )?;
        let leaf_nodes = stmt
            .query_map(
                params![
                    KeyRefWrapper::<C, _>(group_id, PhantomData),
                    STORAGE_PROVIDER_VERSION
                ],
                |row| Self::from_row::<C>(row).map(|x| x.0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(leaf_nodes)
    }
}

pub(crate) struct StorableLeafNodeRef<'a, LeafNode: Entity<STORAGE_PROVIDER_VERSION>>(
    pub &'a LeafNode,
);

impl<LeafNode: Entity<STORAGE_PROVIDER_VERSION>> StorableLeafNodeRef<'_, LeafNode> {
    pub(super) fn store<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        connection: &Connection,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "INSERT OR REPLACE INTO openmls_own_leaf_nodes (group_id, leaf_node, provider_version)
            VALUES (?1, ?2, ?3)",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(group_id, PhantomData),
            EntityRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }

    pub(super) fn store_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO openmls_own_leaf_nodes (group_id, leaf_node, provider_version)
            VALUES (?1, ?2, ?3)",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(group_id, PhantomData),
            EntityRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }
}

impl<GroupId: Key<STORAGE_PROVIDER_VERSION>> StorableGroupIdRef<'_, GroupId> {
    pub(super) fn delete_leaf_nodes<C: Codec>(
        &self,
        connection: &Connection,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "DELETE FROM openmls_own_leaf_nodes
            WHERE group_id = ?
                AND provider_version = ?",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }

    pub(super) fn delete_leaf_nodes_in_tx<C: Codec>(
        &self,
        tx: &rusqlite::Transaction<'_>,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "DELETE FROM openmls_own_leaf_nodes
            WHERE group_id = ?
                AND provider_version = ?",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }
}
