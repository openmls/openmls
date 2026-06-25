//! Migration helpers for `openmls`

use openmls_storage_migration::*;

/// Migrate all stored `MessageSecretsStore`s values for each `GroupId` key
pub fn migrate_message_secrets<S: StorageMigrationHelper>(storage: &S) -> Result<(), S::Error> {
    S::migrate_message_secrets::<
        crate::group::past_secrets::MessageSecretsStore,
        crate::group::past_secrets::MessageSecretsStoreCompat,
        crate::group::GroupId,
    >(storage)
}

/// Migrate all stored `MlsGroupState`s  for each `GroupId` key
pub fn migrate_group_state<S: StorageMigrationHelper>(storage: &S) -> Result<(), S::Error> {
    S::migrate_group_state::<
        crate::group::MlsGroupState,
        crate::group::MlsGroupStateCompat,
        crate::group::GroupId,
    >(storage)
}
