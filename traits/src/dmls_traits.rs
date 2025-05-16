use crate::{
    storage::{StorageProvider, CURRENT_VERSION},
    OpenMlsProvider,
};

pub trait DmlsStorageProvider<const VERSION: u16>: StorageProvider<VERSION> {
    /// Returns the providers epoch.
    fn epoch(&self) -> &[u8];

    /// Returns a storage provider that serves group states for the given epoch.
    fn storage_provider_for_epoch(&self, epoch: Vec<u8>) -> Self;

    /// Clones the data from this provider's epoch to the destination epoch.
    fn clone_epoch_data(&self, destination_epoch: &[u8]) -> Result<(), Self::Error>;

    /// Deletes the data of this provider's epoch.
    fn delete_epoch_data(&self) -> Result<(), Self::Error>;
}

pub trait OpenDmlsProvider:
    OpenMlsProvider<StorageProvider: DmlsStorageProvider<{ CURRENT_VERSION }>>
{
    fn provider_for_epoch(&self, epoch: Vec<u8>) -> Self;
}
