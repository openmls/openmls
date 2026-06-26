use openmls_traits::storage::{CURRENT_VERSION, StorageProvider, traits};

#[derive(Debug, thiserror::Error)]
pub enum StorageMigrationError<LegacyError, CurrentError> {
    #[error(transparent)]
    Legacy(LegacyError),
    #[error(transparent)]
    Current(CurrentError),
}

pub trait StorageMigrationHelper<const PREVIOUS_VERSION: u16>:
    StorageProvider<PREVIOUS_VERSION> + StorageProvider<CURRENT_VERSION>
{
    /// Iterate over all GroupIds in the storage provider
    fn group_ids<GroupId: traits::GroupId<PREVIOUS_VERSION>>(
        &self,
    ) -> Result<Vec<GroupId>, <Self as StorageProvider<PREVIOUS_VERSION>>::Error>;

    /// Helper function to migrate records
    fn migrate_records<Current: From<Legacy>, Legacy, Key>(
        &self,
        keys: impl Fn(&Self) -> Result<Vec<Key>, <Self as StorageProvider<PREVIOUS_VERSION>>::Error>,
        read_current: impl Fn(
            &Self,
            &Key,
        ) -> Result<
            Option<Current>,
            <Self as StorageProvider<CURRENT_VERSION>>::Error,
        >,
        read_legacy: impl Fn(
            &Self,
            &Key,
        ) -> Result<
            Option<Legacy>,
            <Self as StorageProvider<PREVIOUS_VERSION>>::Error,
        >,
        write: impl Fn(
            &Self,
            &Key,
            &Current,
        ) -> Result<(), <Self as StorageProvider<CURRENT_VERSION>>::Error>,
    ) -> Result<
        (),
        StorageMigrationError<
            <Self as StorageProvider<PREVIOUS_VERSION>>::Error,
            <Self as StorageProvider<CURRENT_VERSION>>::Error,
        >,
    > {
        for key in keys(self).map_err(StorageMigrationError::Legacy)? {
            match read_current(self, &key) {
                Ok(Some(_)) => {}
                Ok(None) => {}
                Err(_) => {
                    // try reading as legacy
                    if let Some(legacy) =
                        read_legacy(self, &key).map_err(StorageMigrationError::Legacy)?
                    {
                        // write if available
                        write(self, &key, &legacy.into())
                            .map_err(StorageMigrationError::Current)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Migrates the storage format for the [`GroupState`] for each [`GroupId`] available
    /// in the storage provider.
    fn migrate_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION> + From<GroupStateCompat>,
        GroupStateCompat: traits::GroupState<PREVIOUS_VERSION>,
        GroupId: traits::GroupId<PREVIOUS_VERSION> + traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
    ) -> Result<
        (),
        StorageMigrationError<
            <Self as StorageProvider<PREVIOUS_VERSION>>::Error,
            <Self as StorageProvider<CURRENT_VERSION>>::Error,
        >,
    > {
        self.migrate_records::<GroupState, GroupStateCompat, GroupId>(
            Self::group_ids,
            Self::group_state,
            Self::group_state,
            Self::write_group_state,
        )
    }
}
