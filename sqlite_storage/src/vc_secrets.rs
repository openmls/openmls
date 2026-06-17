use std::marker::PhantomData;

use openmls_traits::storage::{
    traits::GroupId as GroupIdTrait, traits::VcEmulationEpochState as VcEmulationEpochStateTrait,
    traits::VcEpochId as VcEpochIdTrait, Entity as EntityTrait, Key,
};
use rusqlite::{params, OptionalExtension as _, ToSql};

use crate::{
    storage_provider::StorableKeyRef,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    Codec, STORAGE_PROVIDER_VERSION,
};

enum SecretType {
    EmulationEpochState,
}

impl ToSql for SecretType {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let secret_type_str = match self {
            SecretType::EmulationEpochState => "emulation_epoch_state",
        };
        Ok(rusqlite::types::ToSqlOutput::Borrowed(
            rusqlite::types::ValueRef::Text(secret_type_str.as_bytes()),
        ))
    }
}

pub(super) struct StorableEntityRef<'a, Entity: EntityTrait<STORAGE_PROVIDER_VERSION>>(
    pub &'a Entity,
);

impl<'a, VcEmulationEpochState: VcEmulationEpochStateTrait<STORAGE_PROVIDER_VERSION>>
    StorableEntityRef<'a, VcEmulationEpochState>
{
    pub(super) fn store_vc_emulation_epoch_state<
        C: Codec,
        EpochId: Key<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        epoch_id: &EpochId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO vc_emulation_group_secrets (provider_version, epoch_id, secret_type, vc_secret)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(epoch_id, secret_type) DO UPDATE SET
                vc_secret = excluded.vc_secret",
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(epoch_id, PhantomData),
                SecretType::EmulationEpochState,
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

impl<VcEpochId: VcEpochIdTrait<STORAGE_PROVIDER_VERSION>> StorableKeyRef<'_, VcEpochId> {
    pub(super) fn load_vc_emulation_epoch_state<
        C: Codec,
        VcEmulationEpochState: VcEmulationEpochStateTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Option<VcEmulationEpochState>, rusqlite::Error> {
        let Self(epoch_id) = self;
        let mut stmt = connection.prepare(
            "SELECT vc_secret
            FROM vc_emulation_group_secrets
            WHERE epoch_id = ?1
                AND provider_version = ?2
                AND secret_type = ?3",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, VcEpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION,
                SecretType::EmulationEpochState
            ],
            |row| {
                let EntityWrapper::<C, VcEmulationEpochState>(state, ..) = row.get(0)?;
                Ok(state)
            },
        )
        .optional()
    }

    pub(super) fn delete_vc_emulation_epoch_state<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        let Self(epoch_id) = self;
        connection.execute(
            "DELETE FROM vc_emulation_group_secrets
            WHERE epoch_id = ?1
                AND provider_version = ?2
                AND secret_type = ?3",
            params![
                KeyRefWrapper::<C, VcEpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION,
                SecretType::EmulationEpochState
            ],
        )?;
        Ok(())
    }

    pub(super) fn load_vc_operation_tree<
        C: Codec,
        VcOperationTree: EntityTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Option<VcOperationTree>, rusqlite::Error> {
        let Self(epoch_id) = self;
        let mut stmt = connection.prepare(
            "SELECT operation_tree
            FROM vc_operation_trees
            WHERE epoch_id = ?1
                AND provider_version = ?2",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, VcEpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            |row| {
                let EntityWrapper::<C, VcOperationTree>(tree, ..) = row.get(0)?;
                Ok(tree)
            },
        )
        .optional()
    }

    pub(super) fn delete_vc_operation_tree<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        let Self(epoch_id) = self;
        connection.execute(
            "DELETE FROM vc_operation_trees
            WHERE epoch_id = ?1
                AND provider_version = ?2",
            params![
                KeyRefWrapper::<C, VcEpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        Ok(())
    }
}

/// Per-epoch bindings from a higher-level group to emulation epochs. One row
/// per higher-level group, holding the serialized binding record. Written on
/// every commit merge.
pub(super) struct StorableEmulationBindingRef<
    'a,
    VcEmulationBindings: EntityTrait<STORAGE_PROVIDER_VERSION>,
>(pub &'a VcEmulationBindings);

impl<'a, VcEmulationBindings: EntityTrait<STORAGE_PROVIDER_VERSION>>
    StorableEmulationBindingRef<'a, VcEmulationBindings>
{
    pub(super) fn store_vc_emulation_bindings<
        C: Codec,
        GroupId: GroupIdTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO vc_emulation_bindings (provider_version, group_id, bindings)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(group_id) DO UPDATE SET
                bindings = excluded.bindings,
                provider_version = excluded.provider_version",
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

impl<GroupId: GroupIdTrait<STORAGE_PROVIDER_VERSION>> StorableKeyRef<'_, GroupId> {
    pub(super) fn load_vc_emulation_bindings<
        C: Codec,
        VcEmulationBindings: EntityTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Option<VcEmulationBindings>, rusqlite::Error> {
        let Self(group_id) = self;
        let mut stmt = connection.prepare(
            "SELECT bindings
            FROM vc_emulation_bindings
            WHERE group_id = ?1
                AND provider_version = ?2",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, GroupId>(group_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            |row| {
                let EntityWrapper::<C, VcEmulationBindings>(bindings, ..) = row.get(0)?;
                Ok(bindings)
            },
        )
        .optional()
    }

    pub(super) fn delete_vc_emulation_bindings<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        let Self(group_id) = self;
        connection.execute(
            "DELETE FROM vc_emulation_bindings
            WHERE group_id = ?1
                AND provider_version = ?2",
            params![
                KeyRefWrapper::<C, GroupId>(group_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        Ok(())
    }
}

/// Per-emulation-epoch Virtual Client Operation Secret Tree. One row per
/// emulation epoch, holding the serialized tree (node secrets plus per-leaf
/// operation ratchets). Written back after every ratchet advance.
pub(super) struct StorableOperationTreeRef<
    'a,
    VcOperationTree: EntityTrait<STORAGE_PROVIDER_VERSION>,
>(pub &'a VcOperationTree);

impl<'a, VcOperationTree: EntityTrait<STORAGE_PROVIDER_VERSION>>
    StorableOperationTreeRef<'a, VcOperationTree>
{
    pub(super) fn store_vc_operation_tree<
        C: Codec,
        EpochId: VcEpochIdTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        epoch_id: &EpochId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO vc_operation_trees (provider_version, epoch_id, operation_tree)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(epoch_id) DO UPDATE SET
                operation_tree = excluded.operation_tree,
                provider_version = excluded.provider_version",
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(epoch_id, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}
