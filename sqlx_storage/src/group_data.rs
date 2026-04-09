use openmls_traits::storage::{CURRENT_VERSION, Entity};
use sqlx::{
    Database, Decode, Encode, Sqlite, encode::IsNull, error::BoxDynError, sqlite::SqliteTypeInfo,
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
    #[cfg(feature = "extensions-draft-08")]
    ApplicationExportTree,
}

impl GroupDataType {
    fn to_str(self) -> &'static str {
        match self {
            GroupDataType::JoinGroupConfig => "join_group_config",
            GroupDataType::Tree => "tree",
            GroupDataType::InterimTranscriptHash => "interim_transcript_hash",
            GroupDataType::Context => "context",
            GroupDataType::ConfirmationTag => "confirmation_tag",
            GroupDataType::GroupState => "group_state",
            GroupDataType::MessageSecrets => "message_secrets",
            GroupDataType::ResumptionPskStore => "resumption_psk_store",
            GroupDataType::OwnLeafIndex => "own_leaf_index",
            GroupDataType::UseRatchetTreeExtension => "use_ratchet_tree_extension",
            GroupDataType::GroupEpochSecrets => "group_epoch_secrets",
            #[cfg(feature = "extensions-draft-08")]
            GroupDataType::ApplicationExportTree => "application_export_tree",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "join_group_config" => Some(GroupDataType::JoinGroupConfig),
            "tree" => Some(GroupDataType::Tree),
            "interim_transcript_hash" => Some(GroupDataType::InterimTranscriptHash),
            "context" => Some(GroupDataType::Context),
            "confirmation_tag" => Some(GroupDataType::ConfirmationTag),
            "group_state" => Some(GroupDataType::GroupState),
            "message_secrets" => Some(GroupDataType::MessageSecrets),
            "resumption_psk_store" => Some(GroupDataType::ResumptionPskStore),
            "own_leaf_index" => Some(GroupDataType::OwnLeafIndex),
            "use_ratchet_tree_extension" => Some(GroupDataType::UseRatchetTreeExtension),
            "group_epoch_secrets" => Some(GroupDataType::GroupEpochSecrets),
            #[cfg(feature = "extensions-draft-08")]
            "application_export_tree" => Some(GroupDataType::ApplicationExportTree),
            _ => None,
        }
    }
}

impl sqlx::Type<Sqlite> for GroupDataType {
    fn type_info() -> SqliteTypeInfo {
        <String as sqlx::Type<Sqlite>>::type_info()
    }
}

impl<'q> Encode<'q, Sqlite> for GroupDataType {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as Database>::ArgumentBuffer<'q>,
    ) -> Result<IsNull, BoxDynError> {
        Encode::<Sqlite>::encode(self.to_str(), buf)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid group data type: {value}")]
struct InvalidGroupDataTypeError {
    value: String,
}

impl<'r> Decode<'r, Sqlite> for GroupDataType {
    fn decode(value: <Sqlite as Database>::ValueRef<'r>) -> Result<Self, BoxDynError> {
        let value: &str = Decode::<Sqlite>::decode(value)?;
        Self::from_str(value).ok_or_else(|| {
            InvalidGroupDataTypeError {
                value: value.to_string(),
            }
            .into()
        })
    }
}

pub(crate) struct StorableGroupData<GroupData: Entity<CURRENT_VERSION>>(pub GroupData);

pub(super) struct StorableGroupDataRef<'a, GroupData: Entity<CURRENT_VERSION>>(pub &'a GroupData);
