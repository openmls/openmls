use std::marker::PhantomData;

use openmls_traits::storage::{
    traits::GroupId as GroupIdTrait, traits::VcEpochId as VcEpochIdTrait, Entity as EntityTrait,
};
use rusqlite::{params, OptionalExtension as _};

use crate::{
    storage_provider::StorableKeyRef,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    Codec, STORAGE_PROVIDER_VERSION,
};

/// Virtual-clients retention state of an emulation group. One row per emulation
/// group, holding the serialized retention state. Written whenever a derivation
/// epoch is recorded, a declaration is applied, membership changes, or the
/// application adds or removes a reference.
pub(super) struct StorableRetentionStateRef<
    'a,
    VcRetentionState: EntityTrait<STORAGE_PROVIDER_VERSION>,
>(pub &'a VcRetentionState);

impl<'a, VcRetentionState: EntityTrait<STORAGE_PROVIDER_VERSION>>
    StorableRetentionStateRef<'a, VcRetentionState>
{
    pub(super) fn store_vc_retention_state<
        C: Codec,
        GroupId: GroupIdTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO vc_retention_states (provider_version, group_id, retention_state)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(group_id) DO UPDATE SET
                retention_state = excluded.retention_state,
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

/// Reverse reference index of a derivation epoch. One row per derivation epoch,
/// holding the serialized set of higher-level groups that hold the epoch.
/// Written when a reference is taken or released.
pub(super) struct StorableEpochRefsRef<'a, VcEpochRefs: EntityTrait<STORAGE_PROVIDER_VERSION>>(
    pub &'a VcEpochRefs,
);

impl<'a, VcEpochRefs: EntityTrait<STORAGE_PROVIDER_VERSION>> StorableEpochRefsRef<'a, VcEpochRefs> {
    pub(super) fn store_vc_epoch_refs<
        C: Codec,
        EpochId: VcEpochIdTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        epoch_id: &EpochId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO vc_epoch_refs (provider_version, epoch_id, epoch_refs)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(epoch_id) DO UPDATE SET
                epoch_refs = excluded.epoch_refs,
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

/// Creation tracking of a higher-level group. One row per higher-level group,
/// holding the derivation epoch the group was created from and the
/// emulation-group members that have not been seen committing in it yet.
pub(super) struct StorableCreationTrackingRef<
    'a,
    VcCreationTracking: EntityTrait<STORAGE_PROVIDER_VERSION>,
>(pub &'a VcCreationTracking);

impl<'a, VcCreationTracking: EntityTrait<STORAGE_PROVIDER_VERSION>>
    StorableCreationTrackingRef<'a, VcCreationTracking>
{
    pub(super) fn store_vc_creation_tracking<
        C: Codec,
        GroupId: GroupIdTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO vc_creation_tracking (provider_version, group_id, creation_tracking)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(group_id) DO UPDATE SET
                creation_tracking = excluded.creation_tracking,
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
    pub(super) fn load_vc_retention_state<
        C: Codec,
        VcRetentionState: EntityTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Option<VcRetentionState>, rusqlite::Error> {
        let Self(group_id) = self;
        let mut stmt = connection.prepare(
            "SELECT retention_state
            FROM vc_retention_states
            WHERE group_id = ?1
                AND provider_version = ?2",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, GroupId>(group_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            |row| {
                let EntityWrapper::<C, VcRetentionState>(retention_state, ..) = row.get(0)?;
                Ok(retention_state)
            },
        )
        .optional()
    }

    pub(super) fn delete_vc_retention_state<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        let Self(group_id) = self;
        connection.execute(
            "DELETE FROM vc_retention_states
            WHERE group_id = ?1
                AND provider_version = ?2",
            params![
                KeyRefWrapper::<C, GroupId>(group_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        Ok(())
    }

    pub(super) fn load_vc_creation_tracking<
        C: Codec,
        VcCreationTracking: EntityTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Option<VcCreationTracking>, rusqlite::Error> {
        let Self(group_id) = self;
        let mut stmt = connection.prepare(
            "SELECT creation_tracking
            FROM vc_creation_tracking
            WHERE group_id = ?1
                AND provider_version = ?2",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, GroupId>(group_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            |row| {
                let EntityWrapper::<C, VcCreationTracking>(creation_tracking, ..) = row.get(0)?;
                Ok(creation_tracking)
            },
        )
        .optional()
    }

    pub(super) fn delete_vc_creation_tracking<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        let Self(group_id) = self;
        connection.execute(
            "DELETE FROM vc_creation_tracking
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

impl<VcEpochId: VcEpochIdTrait<STORAGE_PROVIDER_VERSION>> StorableKeyRef<'_, VcEpochId> {
    pub(super) fn load_vc_epoch_refs<
        C: Codec,
        VcEpochRefs: EntityTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Option<VcEpochRefs>, rusqlite::Error> {
        let Self(epoch_id) = self;
        let mut stmt = connection.prepare(
            "SELECT epoch_refs
            FROM vc_epoch_refs
            WHERE epoch_id = ?1
                AND provider_version = ?2",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, VcEpochId>(epoch_id, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
            |row| {
                let EntityWrapper::<C, VcEpochRefs>(epoch_refs, ..) = row.get(0)?;
                Ok(epoch_refs)
            },
        )
        .optional()
    }

    pub(super) fn delete_vc_epoch_refs<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        let Self(epoch_id) = self;
        connection.execute(
            "DELETE FROM vc_epoch_refs
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
