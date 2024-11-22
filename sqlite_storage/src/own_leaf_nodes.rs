// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key, CURRENT_VERSION};
use rusqlite::params;

use crate::{
    codec::Codec,
    storage_provider::StorableGroupIdRef,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    Storable,
};

pub(crate) struct StorableLeafNode<LeafNode: Entity<CURRENT_VERSION>>(pub LeafNode);

impl<LeafNode: Entity<CURRENT_VERSION>> Storable for StorableLeafNode<LeafNode> {
    const CREATE_TABLE_STATEMENT: &'static str = "CREATE TABLE IF NOT EXISTS own_leaf_nodes (
        group_id BLOB PRIMARY KEY,
        leaf_node BLOB NOT NULL
    );";

    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(leaf_node, ..) = row.get(0)?;
        Ok(Self(leaf_node))
    }
}

impl<LeafNode: Entity<CURRENT_VERSION>> StorableLeafNode<LeafNode> {
    pub(super) fn load<C: Codec, GroupId: Key<CURRENT_VERSION>>(
        connection: &rusqlite::Connection,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, rusqlite::Error> {
        let mut stmt =
            connection.prepare("SELECT leaf_node FROM own_leaf_nodes WHERE group_id = ?")?;
        let leaf_nodes = stmt
            .query_map(
                params![KeyRefWrapper::<C, _>(group_id, PhantomData)],
                |row| Self::from_row::<C>(row).map(|x| x.0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(leaf_nodes)
    }
}

pub(crate) struct StorableLeafNodeRef<'a, LeafNode: Entity<CURRENT_VERSION>>(pub &'a LeafNode);

impl<'a, LeafNode: Entity<CURRENT_VERSION>> StorableLeafNodeRef<'a, LeafNode> {
    pub(super) fn store<C: Codec, GroupId: Key<CURRENT_VERSION>>(
        &self,
        connection: &rusqlite::Connection,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO own_leaf_nodes (group_id, leaf_node) VALUES (?1, ?2)",
            params![
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

impl<'a, GroupId: Key<CURRENT_VERSION>> StorableGroupIdRef<'a, GroupId> {
    pub(super) fn delete_leaf_nodes<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM own_leaf_nodes WHERE group_id = ?",
            params![KeyRefWrapper::<C, _>(self.0, PhantomData)],
        )?;
        Ok(())
    }
}
