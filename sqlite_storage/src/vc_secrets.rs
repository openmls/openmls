use std::marker::PhantomData;

use openmls_traits::storage::{
    traits::EpochKey as EpochKeyTrait, traits::GroupId as GroupIdTrait,
    traits::HashReference as HashReferenceTrait,
    traits::VcDerivationEpochState as VcDerivationEpochStateTrait,
    traits::VcEpochId as VcEpochIdTrait, Entity as EntityTrait, Key,
};
use rusqlite::{params, OptionalExtension as _, ToSql};

use crate::{
    storage_provider::StorableKeyRef,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    Codec, STORAGE_PROVIDER_VERSION,
};

enum SecretType {
    DerivationEpochState,
}

impl ToSql for SecretType {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let secret_type_str = match self {
            SecretType::DerivationEpochState => "derivation_epoch_state",
        };
        Ok(rusqlite::types::ToSqlOutput::Borrowed(
            rusqlite::types::ValueRef::Text(secret_type_str.as_bytes()),
        ))
    }
}

pub(super) struct StorableEntityRef<'a, Entity: EntityTrait<STORAGE_PROVIDER_VERSION>>(
    pub &'a Entity,
);

impl<'a, VcDerivationEpochState: VcDerivationEpochStateTrait<STORAGE_PROVIDER_VERSION>>
    StorableEntityRef<'a, VcDerivationEpochState>
{
    pub(super) fn store_vc_derivation_epoch_state<
        C: Codec,
        EpochId: Key<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        epoch_id: &EpochId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO vc_derivation_epoch_secrets (provider_version, epoch_id, secret_type, vc_secret)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(epoch_id, secret_type) DO UPDATE SET
                vc_secret = excluded.vc_secret",
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(epoch_id, PhantomData),
                SecretType::DerivationEpochState,
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

impl<VcEpochId: VcEpochIdTrait<STORAGE_PROVIDER_VERSION>> StorableKeyRef<'_, VcEpochId> {
    pub(super) fn load_vc_derivation_epoch_state<
        C: Codec,
        VcDerivationEpochState: VcDerivationEpochStateTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Option<VcDerivationEpochState>, rusqlite::Error> {
        let Self(epoch_id) = self;
        let mut stmt = connection.prepare(
            "SELECT vc_secret
            FROM vc_derivation_epoch_secrets
            WHERE epoch_id = ?1
                AND provider_version = ?2
                AND secret_type = ?3",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, VcEpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION,
                SecretType::DerivationEpochState
            ],
            |row| {
                let EntityWrapper::<C, VcDerivationEpochState>(state, ..) = row.get(0)?;
                Ok(state)
            },
        )
        .optional()
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
}

/// The sweep behind `StorageProvider::delete_unreferenced_vc_derivation_epoch_states`.
/// The reference checks and the deletions are separate statements, so the
/// caller must run it within a transaction.
pub(super) fn delete_unreferenced_vc_derivation_epoch_states<
    C: Codec,
    VcEpochId: VcEpochIdTrait<STORAGE_PROVIDER_VERSION>,
>(
    connection: &rusqlite::Connection,
) -> Result<Vec<VcEpochId>, rusqlite::Error> {
    let mut stmt = connection.prepare(
        "SELECT DISTINCT epoch_id FROM (
            SELECT epoch_id, provider_version FROM vc_derivation_epoch_secrets
            UNION ALL
            SELECT epoch_id, provider_version FROM vc_operation_trees
        ) AS candidates
        WHERE provider_version = ?1
            AND NOT EXISTS (
                SELECT 1 FROM vc_derivation_epoch_log_entries entries
                WHERE entries.epoch_id = candidates.epoch_id
                    AND entries.provider_version = ?1
            )
            AND NOT EXISTS (
                SELECT 1 FROM vc_emulation_bindings bindings
                WHERE bindings.epoch_id = candidates.epoch_id
                    AND bindings.provider_version = ?1
            )
            AND NOT EXISTS (
                SELECT 1 FROM vc_retained_key_package_material material
                WHERE material.epoch_id = candidates.epoch_id
                    AND material.provider_version = ?1
            )",
    )?;
    let rows = stmt.query_map(params![STORAGE_PROVIDER_VERSION], |row| {
        let serialized: Vec<u8> = row.get(0)?;
        let EntityWrapper::<C, VcEpochId>(epoch_id, ..) = row.get(0)?;
        Ok((serialized, epoch_id))
    })?;
    let unreferenced: Vec<(Vec<u8>, VcEpochId)> = rows.collect::<Result<_, _>>()?;
    let mut delete_state = connection.prepare(
        "DELETE FROM vc_derivation_epoch_secrets
        WHERE epoch_id = ?1
            AND provider_version = ?2",
    )?;
    let mut delete_tree = connection.prepare(
        "DELETE FROM vc_operation_trees
        WHERE epoch_id = ?1
            AND provider_version = ?2",
    )?;
    let mut deleted = Vec::with_capacity(unreferenced.len());
    for (serialized, epoch_id) in unreferenced {
        delete_state.execute(params![serialized, STORAGE_PROVIDER_VERSION])?;
        delete_tree.execute(params![serialized, STORAGE_PROVIDER_VERSION])?;
        deleted.push(epoch_id);
    }
    Ok(deleted)
}

/// A row of `vc_emulation_bindings`: one per (higher-level group, group
/// epoch), holding the opaque binding next to the derivation epoch id it names
/// so the sweep can query by epoch.
pub(super) struct StorableEmulationBindingRef<
    'a,
    VcEmulationBinding: EntityTrait<STORAGE_PROVIDER_VERSION>,
>(pub &'a VcEmulationBinding);

impl<'a, VcEmulationBinding: EntityTrait<STORAGE_PROVIDER_VERSION>>
    StorableEmulationBindingRef<'a, VcEmulationBinding>
{
    pub(super) fn store_vc_emulation_binding<
        C: Codec,
        GroupId: GroupIdTrait<STORAGE_PROVIDER_VERSION>,
        EpochKey: EpochKeyTrait<STORAGE_PROVIDER_VERSION>,
        EpochId: VcEpochIdTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        group_id: &GroupId,
        group_epoch: &EpochKey,
        epoch_id: &EpochId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO vc_emulation_bindings
                (provider_version, group_id, group_epoch, epoch_id, binding)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(group_id, group_epoch) DO UPDATE SET
                epoch_id = excluded.epoch_id,
                binding = excluded.binding,
                provider_version = excluded.provider_version",
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                KeyRefWrapper::<C, _>(group_epoch, PhantomData),
                KeyRefWrapper::<C, _>(epoch_id, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

impl<GroupId: GroupIdTrait<STORAGE_PROVIDER_VERSION>> StorableKeyRef<'_, GroupId> {
    pub(super) fn load_vc_emulation_binding<
        C: Codec,
        EpochKey: EpochKeyTrait<STORAGE_PROVIDER_VERSION>,
        VcEmulationBinding: EntityTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        group_epoch: &EpochKey,
    ) -> Result<Option<VcEmulationBinding>, rusqlite::Error> {
        let Self(group_id) = self;
        let mut stmt = connection.prepare(
            "SELECT binding
            FROM vc_emulation_bindings
            WHERE group_id = ?1
                AND group_epoch = ?2
                AND provider_version = ?3",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, GroupId>(group_id, PhantomData),
                KeyRefWrapper::<C, EpochKey>(group_epoch, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            |row| {
                let EntityWrapper::<C, VcEmulationBinding>(binding, ..) = row.get(0)?;
                Ok(binding)
            },
        )
        .optional()
    }

    pub(super) fn load_vc_emulation_bindings<
        C: Codec,
        VcEmulationBinding: EntityTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Vec<VcEmulationBinding>, rusqlite::Error> {
        let Self(group_id) = self;
        let mut stmt = connection.prepare(
            "SELECT binding
            FROM vc_emulation_bindings
            WHERE group_id = ?1
                AND provider_version = ?2",
        )?;
        let rows = stmt.query_map(
            params![
                KeyRefWrapper::<C, GroupId>(group_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            |row| {
                let EntityWrapper::<C, VcEmulationBinding>(binding, ..) = row.get(0)?;
                Ok(binding)
            },
        )?;
        rows.collect()
    }

    pub(super) fn delete_vc_emulation_bindings<
        C: Codec,
        EpochKey: EpochKeyTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        group_epochs: &[EpochKey],
    ) -> Result<(), rusqlite::Error> {
        let Self(group_id) = self;
        let mut stmt = connection.prepare(
            "DELETE FROM vc_emulation_bindings
            WHERE group_id = ?1
                AND group_epoch = ?2
                AND provider_version = ?3",
        )?;
        for group_epoch in group_epochs {
            stmt.execute(params![
                KeyRefWrapper::<C, GroupId>(group_id, PhantomData),
                KeyRefWrapper::<C, EpochKey>(group_epoch, PhantomData),
                STORAGE_PROVIDER_VERSION
            ])?;
        }
        Ok(())
    }

    pub(super) fn delete_all_vc_emulation_bindings<C: Codec>(
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

/// A row of `vc_derivation_epoch_log_entries`: one per (emulation group,
/// derivation epoch), holding the opaque log entry keyed by the epoch id it
/// names so the sweep can query by epoch.
pub(super) struct StorableVcDerivationEpochLogEntryRef<
    'a,
    VcDerivationEpochLogEntry: EntityTrait<STORAGE_PROVIDER_VERSION>,
>(pub &'a VcDerivationEpochLogEntry);

impl<'a, VcDerivationEpochLogEntry: EntityTrait<STORAGE_PROVIDER_VERSION>>
    StorableVcDerivationEpochLogEntryRef<'a, VcDerivationEpochLogEntry>
{
    pub(super) fn store_vc_derivation_epoch_log_entry<
        C: Codec,
        GroupId: GroupIdTrait<STORAGE_PROVIDER_VERSION>,
        EpochId: VcEpochIdTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        group_id: &GroupId,
        epoch_id: &EpochId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO vc_derivation_epoch_log_entries
                (provider_version, group_id, epoch_id, entry)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(group_id, epoch_id) DO UPDATE SET
                entry = excluded.entry,
                provider_version = excluded.provider_version",
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                KeyRefWrapper::<C, _>(epoch_id, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

impl<GroupId: GroupIdTrait<STORAGE_PROVIDER_VERSION>> StorableKeyRef<'_, GroupId> {
    pub(super) fn load_vc_derivation_epoch_log_entries<
        C: Codec,
        VcDerivationEpochLogEntry: EntityTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Vec<VcDerivationEpochLogEntry>, rusqlite::Error> {
        let Self(group_id) = self;
        let mut stmt = connection.prepare(
            "SELECT entry
            FROM vc_derivation_epoch_log_entries
            WHERE group_id = ?1
                AND provider_version = ?2",
        )?;
        let rows = stmt.query_map(
            params![
                KeyRefWrapper::<C, GroupId>(group_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            |row| {
                let EntityWrapper::<C, VcDerivationEpochLogEntry>(entry, ..) = row.get(0)?;
                Ok(entry)
            },
        )?;
        rows.collect()
    }

    pub(super) fn delete_vc_derivation_epoch_log_entries<
        C: Codec,
        EpochId: VcEpochIdTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        epoch_ids: &[EpochId],
    ) -> Result<(), rusqlite::Error> {
        let Self(group_id) = self;
        let mut stmt = connection.prepare(
            "DELETE FROM vc_derivation_epoch_log_entries
            WHERE group_id = ?1
                AND epoch_id = ?2
                AND provider_version = ?3",
        )?;
        for epoch_id in epoch_ids {
            stmt.execute(params![
                KeyRefWrapper::<C, GroupId>(group_id, PhantomData),
                KeyRefWrapper::<C, EpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ])?;
        }
        Ok(())
    }

    pub(super) fn delete_vc_derivation_epoch_log<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        let Self(group_id) = self;
        connection.execute(
            "DELETE FROM vc_derivation_epoch_log_entries
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

/// Per-derivation-epoch Virtual Client Operation Secret Tree. One row per
/// derivation epoch, holding the serialized tree (node secrets plus per-leaf
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

/// Per-KeyPackage material a sibling retains when it processes a
/// KeyPackageUpload. One row per KeyPackage reference, holding the derivation
/// epoch and the per-KeyPackage seed secret needed to rederive the
/// KeyPackage's keys.
pub(super) struct StorableRetainedKeyPackageMaterialRef<
    'a,
    RetainedKeyPackageMaterial: EntityTrait<STORAGE_PROVIDER_VERSION>,
>(pub &'a RetainedKeyPackageMaterial);

impl<'a, RetainedKeyPackageMaterial: EntityTrait<STORAGE_PROVIDER_VERSION>>
    StorableRetainedKeyPackageMaterialRef<'a, RetainedKeyPackageMaterial>
{
    pub(super) fn store_retained_key_package_material<
        C: Codec,
        EpochId: VcEpochIdTrait<STORAGE_PROVIDER_VERSION>,
        KeyPackageRef: HashReferenceTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        epoch_id: &EpochId,
        key_package_ref: &KeyPackageRef,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO vc_retained_key_package_material (provider_version, key_package_ref, epoch_id, record)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(key_package_ref) DO UPDATE SET
                epoch_id = excluded.epoch_id,
                record = excluded.record,
                provider_version = excluded.provider_version",
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(key_package_ref, PhantomData),
                KeyRefWrapper::<C, _>(epoch_id, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData)
            ],
        )?;
        Ok(())
    }
}

impl<KeyPackageRef: HashReferenceTrait<STORAGE_PROVIDER_VERSION>>
    StorableKeyRef<'_, KeyPackageRef>
{
    pub(super) fn load_retained_key_package_material<
        C: Codec,
        RetainedKeyPackageMaterial: EntityTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Option<RetainedKeyPackageMaterial>, rusqlite::Error> {
        let Self(key_package_ref) = self;
        let mut stmt = connection.prepare(
            "SELECT record
            FROM vc_retained_key_package_material
            WHERE key_package_ref = ?1
                AND provider_version = ?2",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, KeyPackageRef>(key_package_ref, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            |row| {
                let EntityWrapper::<C, RetainedKeyPackageMaterial>(record, ..) = row.get(0)?;
                Ok(record)
            },
        )
        .optional()
    }

    pub(super) fn delete_retained_key_package_material<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        let Self(key_package_ref) = self;
        connection.execute(
            "DELETE FROM vc_retained_key_package_material
            WHERE key_package_ref = ?1
                AND provider_version = ?2",
            params![
                KeyRefWrapper::<C, KeyPackageRef>(key_package_ref, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        Ok(())
    }
}
