use std::marker::PhantomData;

use openmls_traits::storage::{
    traits::GroupId as GroupIdTrait, traits::HashReference as HashReferenceTrait,
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

    pub(super) fn delete_vc_derivation_epoch_state<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        let Self(epoch_id) = self;
        connection.execute(
            "DELETE FROM vc_derivation_epoch_secrets
            WHERE epoch_id = ?1
                AND provider_version = ?2
                AND secret_type = ?3",
            params![
                KeyRefWrapper::<C, VcEpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION,
                SecretType::DerivationEpochState
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

    /// Runs an `EXISTS` query that takes this epoch id as `?1` and the
    /// provider version as `?2`.
    fn epoch_reference_exists<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
        exists_query: &str,
    ) -> Result<bool, rusqlite::Error> {
        let Self(epoch_id) = self;
        let mut stmt = connection.prepare(exists_query)?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, VcEpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            |row| row.get::<_, bool>(0),
        )
    }

    pub(super) fn has_retained_key_package_material_for_epoch<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<bool, rusqlite::Error> {
        self.epoch_reference_exists::<C>(
            connection,
            "SELECT EXISTS(
                SELECT 1 FROM vc_retained_key_package_material
                WHERE epoch_id = ?1
                    AND provider_version = ?2
            )",
        )
    }

    pub(super) fn has_vc_emulation_binding_for_epoch<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<bool, rusqlite::Error> {
        self.epoch_reference_exists::<C>(
            connection,
            "SELECT EXISTS(
                SELECT 1 FROM vc_emulation_binding_epochs
                WHERE epoch_id = ?1
                    AND provider_version = ?2
            )",
        )
    }

    pub(super) fn has_registered_vc_derivation_epoch_for_epoch<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<bool, rusqlite::Error> {
        self.epoch_reference_exists::<C>(
            connection,
            "SELECT EXISTS(
                SELECT 1 FROM registered_vc_derivation_epochs
                WHERE epoch_id = ?1
                    AND provider_version = ?2
            )",
        )
    }
}

/// Per-epoch bindings from a higher-level group to derivation epochs. One row
/// per higher-level group, holding the serialized binding record, plus one row
/// per bound derivation epoch in `vc_emulation_binding_epochs` so the record
/// can be queried by epoch. Written on every commit merge.
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
        EpochId: VcEpochIdTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        group_id: &GroupId,
        bound_epochs: &[EpochId],
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
        // The record above replaces the previous one wholesale, so the
        // projection is rebuilt rather than added to. That also drops the
        // epochs whose bindings aged out of the record.
        connection.execute(
            "DELETE FROM vc_emulation_binding_epochs
            WHERE group_id = ?1
                AND provider_version = ?2",
            params![
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        let mut stmt = connection.prepare(
            "INSERT INTO vc_emulation_binding_epochs (provider_version, group_id, epoch_id)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(group_id, epoch_id) DO UPDATE SET
                provider_version = excluded.provider_version",
        )?;
        for epoch_id in bound_epochs {
            stmt.execute(params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                KeyRefWrapper::<C, _>(epoch_id, PhantomData)
            ])?;
        }
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
        connection.execute(
            "DELETE FROM vc_emulation_binding_epochs
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

/// The derivation epoch an emulation group registered for its current group
/// epoch. One row per emulation group, holding the serialized registration
/// record plus the epoch id it names so the record can be queried by epoch.
/// Written when a derivation epoch is registered.
pub(super) struct StorableRegisteredVcDerivationEpochRef<
    'a,
    RegisteredVcDerivationEpoch: EntityTrait<STORAGE_PROVIDER_VERSION>,
>(pub &'a RegisteredVcDerivationEpoch);

impl<'a, RegisteredVcDerivationEpoch: EntityTrait<STORAGE_PROVIDER_VERSION>>
    StorableRegisteredVcDerivationEpochRef<'a, RegisteredVcDerivationEpoch>
{
    pub(super) fn store_registered_vc_derivation_epoch<
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
            "INSERT INTO registered_vc_derivation_epochs
                (provider_version, group_id, registration, epoch_id)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(group_id) DO UPDATE SET
                registration = excluded.registration,
                epoch_id = excluded.epoch_id,
                provider_version = excluded.provider_version",
            params![
                STORAGE_PROVIDER_VERSION,
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData),
                KeyRefWrapper::<C, _>(epoch_id, PhantomData)
            ],
        )?;
        Ok(())
    }
}

impl<GroupId: GroupIdTrait<STORAGE_PROVIDER_VERSION>> StorableKeyRef<'_, GroupId> {
    pub(super) fn load_registered_vc_derivation_epoch<
        C: Codec,
        RegisteredVcDerivationEpoch: EntityTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Option<RegisteredVcDerivationEpoch>, rusqlite::Error> {
        let Self(group_id) = self;
        let mut stmt = connection.prepare(
            "SELECT registration
            FROM registered_vc_derivation_epochs
            WHERE group_id = ?1
                AND provider_version = ?2",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, GroupId>(group_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            |row| {
                let EntityWrapper::<C, RegisteredVcDerivationEpoch>(registration, ..) =
                    row.get(0)?;
                Ok(registration)
            },
        )
        .optional()
    }

    pub(super) fn delete_registered_vc_derivation_epoch<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        let Self(group_id) = self;
        connection.execute(
            "DELETE FROM registered_vc_derivation_epochs
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
