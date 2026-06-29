//! Migration helpers for `openmls`

use openmls_storage_migration::*;
use openmls_traits::storage::{traits, Entity, StorageProvider, CURRENT_VERSION};

/// Migrate all stored `MlsGroupState`s  for each `GroupId` key
///
/// NOTE: This migration helper is intended for upgrades from `openmls=0.7.0` -> the current version,
/// with non-self-describing `serde` storage formats.
pub fn migrate_group_state<S: StorageMigrationHelper<CURRENT_VERSION, CURRENT_VERSION>>(
    storage: &S,
) -> Result<
    (),
    StorageMigrationError<
        <S as StorageProvider<CURRENT_VERSION>>::Error,
        <S as StorageProvider<CURRENT_VERSION>>::Error,
    >,
> {
    S::migrate_group_state::<
        crate::group::MlsGroupState,
        crate::group::MlsGroupStateCompat,
        crate::group::GroupId,
    >(storage)
}

/// Public wrapper for MessageSecretsStore
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct MessageSecretsStore(crate::group::past_secrets::MessageSecretsStore);

/// Public wrapper for MessageSecretsStoreCompat
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct MessageSecretsStoreCompat(crate::group::past_secrets::MessageSecretsStoreCompat);

impl Entity<CURRENT_VERSION> for MessageSecretsStore {}
impl traits::MessageSecrets<CURRENT_VERSION> for MessageSecretsStore {}
impl Entity<CURRENT_VERSION> for MessageSecretsStoreCompat {}
impl traits::MessageSecrets<CURRENT_VERSION> for MessageSecretsStoreCompat {}
