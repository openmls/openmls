use openmls_traits::key_store::{FromKeyStoreValue, OpenMlsKeyStore, ToKeyStoreValue};
use std::{collections::HashMap, sync::RwLock};

#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl OpenMlsKeyStore for MemoryKeyStore {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error = Error;

    /// Store a value `v` that implements the [`KeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<V: ToKeyStoreValue>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        let value = v
            .to_key_store_value()
            .map_err(|_| Error::SerializationError)?;
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
}

/// Errors thrown by the key store.
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("The key store does not allow storing serialized values.")]
    UnsupportedValueTypeBytes,
    #[error("Updating is not supported by this key store.")]
    UnsupportedMethod,
    #[error("Error serializing value.")]
    SerializationError,
}
