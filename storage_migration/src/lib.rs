use openmls_traits::storage::{CURRENT_VERSION as VERSION, traits};

pub trait StorageMigrationHelper: openmls_traits::storage::StorageProvider<VERSION> {
    /// Iterate over all GroupIds in the storage provider
    fn group_ids<GroupId: traits::GroupId<VERSION>>(&self) -> Result<Vec<GroupId>, Self::Error>;

    fn migrate_records<Current: From<Legacy>, Legacy, Key>(
        &self,
        keys: impl Fn(&Self) -> Result<Vec<Key>, Self::Error>,
        read_current: impl Fn(&Self, &Key) -> Result<Option<Current>, Self::Error>,
        read_legacy: impl Fn(&Self, &Key) -> Result<Option<Legacy>, Self::Error>,
        write: impl Fn(&Self, &Key, &Current) -> Result<(), Self::Error>,
    ) -> Result<(), Self::Error> {
        for key in keys(self)? {
            match read_current(self, &key) {
                Ok(Some(_)) => {}
                Ok(None) => {}
                Err(_) => {
                    // try reading as legacy
                    if let Some(legacy) = read_legacy(self, &key)? {
                        // write if available
                        write(self, &key, &legacy.into())?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Migrates the storage format for the [`GroupState`] for each [`GroupId`] available
    /// in the storage provider.
    fn migrate_group_state<
        GroupState: traits::GroupState<VERSION> + From<GroupStateCompat>,
        GroupStateCompat: traits::GroupState<VERSION>,
        GroupId: traits::GroupId<VERSION>,
    >(
        &self,
    ) -> Result<(), Self::Error> {
        self.migrate_records::<GroupState, GroupStateCompat, GroupId>(
            Self::group_ids,
            Self::group_state,
            Self::group_state,
            Self::write_group_state,
        )
    }

    /// Migrates the storage format for the [`MessageSecrets`] for each [`GroupId`] available
    /// in the storage provider.
    fn migrate_message_secrets<
        MessageSecrets: traits::MessageSecrets<VERSION> + From<MessageSecretsCompat>,
        MessageSecretsCompat: traits::MessageSecrets<VERSION>,
        GroupId: traits::GroupId<VERSION>,
    >(
        &self,
    ) -> Result<(), Self::Error> {
        self.migrate_records::<MessageSecrets, MessageSecretsCompat, GroupId>(
            Self::group_ids,
            Self::message_secrets,
            Self::message_secrets,
            Self::write_message_secrets,
        )
    }
}
