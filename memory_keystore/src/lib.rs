use openmls_traits::key_store::{FromKeyStoreValue, OpenMlsKeyStore, ToKeyStoreValue};
use std::{collections::HashMap, sync::RwLock};

type EpochStoreIndex = (Vec<u8>, u64); // GroupId and GroupEpoch

#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    epoch_values: RwLock<HashMap<EpochStoreIndex, Vec<Vec<u8>>>>,
}

impl OpenMlsKeyStore for MemoryKeyStore {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error = MemoryKeyStoreError;

    /// Store a value `v` that implements the [`KeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<V: ToKeyStoreValue>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        let value = v
            .to_key_store_value()
            .map_err(|_| MemoryKeyStoreError::SerializationError)?;
        // We unwrap here, because this is the only function claiming a write
        // lock on `credential_bundles`. It only holds the lock very briefly and
        // should not panic during that period.
        let mut values = self.values.write().unwrap();
        values.insert(k.to_vec(), value);
        Ok(())
    }

    /// Read and return a value stored for ID `k` that implements the
    /// [`KeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<V: FromKeyStoreValue>(&self, k: &[u8]) -> Option<V> {
        // We unwrap here, because the two functions claiming a write lock on
        // `init_key_package_bundles` (this one and `generate_key_package_bundle`) only
        // hold the lock very briefly and should not panic during that period.
        let values = self.values.read().unwrap();
        if let Some(value) = values.get(k) {
            V::from_key_store_value(value).ok()
        } else {
            None
        }
    }

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete(&self, k: &[u8]) -> Result<(), Self::Error> {
        // We just delete both ...
        let mut values = self.values.write().unwrap();
        values.remove(k);
        Ok(())
    }

    fn read_epoch_keys<V: FromKeyStoreValue>(&self, group_id: &[u8], epoch: u64) -> Option<Vec<V>> {
        let epoch_store = self.epoch_values.read().unwrap();
        if let Some(values) = epoch_store.get(&(group_id.to_vec(), epoch)) {
            values
                .iter()
                .map(|value| V::from_key_store_value(value))
                .collect::<Result<Vec<V>, V::Error>>()
                .map(Some)
                .unwrap_or(None)
        } else {
            None
        }
    }

    fn delete_epoch_keys(&self, group_id: &[u8], epoch: u64) -> Result<(), Self::Error> {
        let mut epoch_store = self.epoch_values.write().unwrap();
        epoch_store.remove(&(group_id.to_vec(), epoch));
        Ok(())
    }

    fn store_epoch_keys<V: ToKeyStoreValue>(
        &self,
        group_id: &[u8],
        epoch: u64,
        encryption_keys: &[&V],
    ) -> Result<(), Self::Error> {
        let mut epoch_store = self.epoch_values.write().unwrap();
        epoch_store.insert(
            (group_id.to_vec(), epoch),
            encryption_keys
                .iter()
                .map(|&bytes| {
                    V::to_key_store_value(bytes)
                        .map_err(|_| MemoryKeyStoreError::SerializationError)
                })
                .collect::<Result<Vec<Vec<u8>>, Self::Error>>()?,
        );
        Ok(())
    }
}

/// Errors thrown by the key store.
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryKeyStoreError {
    #[error("The key store does not allow storing serialized values.")]
    UnsupportedValueTypeBytes,
    #[error("Updating is not supported by this key store.")]
    UnsupportedMethod,
    #[error("Error serializing value.")]
    SerializationError,
}
