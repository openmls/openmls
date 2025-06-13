use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key};
use rusqlite::{params, types::FromSql, Connection, OptionalExtension, ToSql};

use crate::{
    codec::Codec,
    storage_provider::StorableGroupIdRef,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    STORAGE_PROVIDER_VERSION,
};

#[derive(Debug, Clone, Copy)]
pub(super) enum GroupDataType {
    JoinGroupConfig,
    Tree,
    InterimTranscriptHash,
    Context,
    ConfirmationTag,
    GroupState,
    MessageSecrets,
    ResumptionPskStore,
    OwnLeafIndex,
    UseRatchetTreeExtension,
    GroupEpochSecrets,
}

impl ToSql for GroupDataType {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        match self {
            GroupDataType::JoinGroupConfig => "join_group_config".to_sql(),
            GroupDataType::Tree => "tree".to_sql(),
            GroupDataType::InterimTranscriptHash => "interim_transcript_hash".to_sql(),
            GroupDataType::Context => "context".to_sql(),
            GroupDataType::ConfirmationTag => "confirmation_tag".to_sql(),
            GroupDataType::GroupState => "group_state".to_sql(),
            GroupDataType::MessageSecrets => "message_secrets".to_sql(),
            GroupDataType::ResumptionPskStore => "resumption_psk_store".to_sql(),
            GroupDataType::OwnLeafIndex => "own_leaf_index".to_sql(),
            GroupDataType::UseRatchetTreeExtension => "use_ratchet_tree_extension".to_sql(),
            GroupDataType::GroupEpochSecrets => "group_epoch_secrets".to_sql(),
        }
    }
}

impl FromSql for GroupDataType {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let value = String::column_result(value)?;
        match value.as_str() {
            "join_group_config" => Ok(GroupDataType::JoinGroupConfig),
            "tree" => Ok(GroupDataType::Tree),
            "interim_transcript_hash" => Ok(GroupDataType::InterimTranscriptHash),
            "context" => Ok(GroupDataType::Context),
            "confirmation_tag" => Ok(GroupDataType::ConfirmationTag),
            "group_state" => Ok(GroupDataType::GroupState),
            "message_secrets" => Ok(GroupDataType::MessageSecrets),
            "resumption_psk_store" => Ok(GroupDataType::ResumptionPskStore),
            "own_leaf_index" => Ok(GroupDataType::OwnLeafIndex),
            "use_ratchet_tree_extension" => Ok(GroupDataType::UseRatchetTreeExtension),
            "group_epoch_secrets" => Ok(GroupDataType::GroupEpochSecrets),
            _ => Err(rusqlite::types::FromSqlError::InvalidType),
        }
    }
}

pub(crate) struct StorableGroupData<GroupData: Entity<STORAGE_PROVIDER_VERSION>>(pub GroupData);

impl<GroupData: Entity<STORAGE_PROVIDER_VERSION>> StorableGroupData<GroupData> {
    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(payload, ..) = row.get(0)?;
        Ok(Self(payload))
    }

    pub(super) fn load<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &Connection,
        group_id: &GroupId,
        data_type: GroupDataType,
    ) -> Result<Option<GroupData>, rusqlite::Error> {
        let mut stmt = connection.prepare(
            "SELECT group_data 
            FROM openmls_group_data 
            WHERE group_id = ? 
                AND data_type = ?
                AND provider_version = ?",
        )?;
        stmt.query_row(
            params![
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                data_type,
                STORAGE_PROVIDER_VERSION
            ],
            Self::from_row::<C>,
        )
        .map(|x| x.0)
        .optional()
    }
}

pub(super) struct StorableGroupDataRef<'a, GroupData: Entity<STORAGE_PROVIDER_VERSION>>(
    pub &'a GroupData,
);

impl<GroupData: Entity<STORAGE_PROVIDER_VERSION>> StorableGroupDataRef<'_, GroupData> {
    pub(super) fn store<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        connection: &Connection,
        group_id: &GroupId,
        data_type: GroupDataType,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT OR REPLACE INTO openmls_group_data (group_id, data_type, group_data, provider_version) 
            VALUES (?, ?, ?, ?)",
            params![
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                data_type,
                EntityRefWrapper::<C, _>(self.0, PhantomData),
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        Ok(())
    }
}

impl<GroupId: Key<STORAGE_PROVIDER_VERSION>> StorableGroupIdRef<'_, GroupId> {
    pub(super) fn delete_group_data<C: Codec>(
        &self,
        connection: &Connection,
        data_type: GroupDataType,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM openmls_group_data 
            WHERE group_id = ? 
                AND data_type = ?
                AND provider_version = ?",
            params![
                KeyRefWrapper::<C, _>(self.0, PhantomData),
                data_type,
                STORAGE_PROVIDER_VERSION
            ],
        )?;
        Ok(())
    }
}
