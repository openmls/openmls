use openmls_traits::key_store::{FromKeyStoreValue, OpenMlsKeyStore, ToKeyStoreValue};
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::RwLock,
};

#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    values: RwLock<HashMap<u64, Vec<u8>>>,
}

impl OpenMlsKeyStore for MemoryKeyStore {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error = Error;

    /// Store a value `v` that implements the [`KeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<K: Hash, V: ToKeyStoreValue>(&self, k: &K, v: &V) -> Result<(), Self::Error> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut hasher);
        let k = hasher.finish();
        let value = v
            .to_key_store_value()
            .map_err(|_| Error::SerializationError)?;
        // We unwrap here, because this is the only function claiming a write
        // lock on `credential_bundles`. It only holds the lock very briefly and
        // should not panic during that period.
        let mut values = self.values.write().unwrap();
        values.insert(k, value);
        Ok(())
    }

    /// Read and return a value stored for ID `k` that implements the
    /// [`KeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<K: Hash, V: FromKeyStoreValue>(&self, k: &K) -> Option<V> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut hasher);
        let k = hasher.finish();

        // We unwrap here, because the two functions claiming a write lock on
        // `init_key_package_bundles` (this one and `generate_key_package_bundle`) only
        // hold the lock very briefly and should not panic during that period.
        let values = self.values.read().unwrap();
        if let Some(value) = values.get(&k) {
            V::from_key_store_value(value).ok()
        } else {
            None
        }
    }

    /// Not supported.
    fn update<K: Hash, V: FromKeyStoreValue>(&self, _k: &K, _v: &V) -> Result<(), Self::Error> {
        Err(Error::UnsupportedMethod)
    }

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete<K: Hash>(&self, k: &K) -> Result<(), Self::Error> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut hasher);
        let k = hasher.finish();

        // We just delete both ...
        let mut values = self.values.write().unwrap();
        values.remove(&k);
        Ok(())
    }
}

/// Errors thrown by the key store.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Error {
    UnsupportedValueTypeBytes,
    UnsupportedMethod,
    SerializationError,
}

impl Into<String> for Error {
    fn into(self) -> String {
        match self {
            Error::UnsupportedValueTypeBytes => {
                "The key store does not allow storing serialized values.".to_string()
            }
            Error::UnsupportedMethod => "Updating is not supported by this key store.".to_string(),
            Error::SerializationError => "Error serializing value.".to_string(),
        }
    }
}
