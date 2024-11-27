use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key};
use rusqlite::params;

use crate::{
    codec::Codec,
    storage_provider::StorableGroupIdRef,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
};

pub(crate) struct StorableLeafNode<LeafNode: Entity<1>>(pub LeafNode);

impl<LeafNode: Entity<1>> StorableLeafNode<LeafNode> {
    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(leaf_node, ..) = row.get(0)?;
        Ok(Self(leaf_node))
    }

    pub(super) fn load<C: Codec, GroupId: Key<1>>(
        connection: &rusqlite::Connection,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, rusqlite::Error> {
        let mut stmt = connection
            .prepare("SELECT leaf_node FROM openmls_own_leaf_nodes WHERE group_id = ?")?;
        let leaf_nodes = stmt
            .query_map(
                params![KeyRefWrapper::<C, _>(group_id, PhantomData)],
                |row| Self::from_row::<C>(row).map(|x| x.0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(leaf_nodes)
    }
}

pub(crate) struct StorableLeafNodeRef<'a, LeafNode: Entity<1>>(pub &'a LeafNode);

impl<'a, LeafNode: Entity<1>> StorableLeafNodeRef<'a, LeafNode> {
    pub(super) fn store<C: Codec, GroupId: Key<1>>(
        &self,
        connection: &rusqlite::Connection,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO openmls_own_leaf_nodes (group_id, leaf_node) VALUES (?1, ?2)",
            params![
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

impl<'a, GroupId: Key<1>> StorableGroupIdRef<'a, GroupId> {
    pub(super) fn delete_leaf_nodes<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM openmls_own_leaf_nodes WHERE group_id = ?",
            params![KeyRefWrapper::<C, _>(self.0, PhantomData)],
        )?;
        Ok(())
    }
}
