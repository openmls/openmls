use openmls_traits::key_store::{MlsEntity, MlsEntityId, OpenMlsKeyStore};
use std::{collections::HashMap, sync::RwLock};
use tls_codec::{Deserialize, Serialize, TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

/// This is a dummy that is used to (de)serialize values.
#[derive(Debug, TlsSize, TlsSerialize, TlsDeserialize)]
struct Value {
    id: MlsEntityId,
    v: u16,
    value: VLBytes,
}

impl OpenMlsKeyStore for MemoryKeyStore {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error = MemoryKeyStoreError;

    /// Store a value `v` that implements the [`ToKeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<const VERSION: u16, V: MlsEntity<VERSION> + core::fmt::Debug>(
        &self,
        k: &[u8],
        v: &V,
    ) -> Result<(), Self::Error> {
        let value = Value {
            id: V::ID,
            v: VERSION,
            value: serde_json::to_vec(v)
                .map_err(|_| MemoryKeyStoreError::SerializationError)?
                .into(),
        };
        let value = value.tls_serialize_detached().unwrap();

        // We unwrap here, because this is the only function claiming a write
        // lock on `credential_bundles`. It only holds the lock very briefly and
        // should not panic during that period.
        let mut values = self.values.write().unwrap();
        values.insert(k.to_vec(), value);
        Ok(())
    }

    /// Read and return a value stored for ID `k` that implements the
    /// [`FromKeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<const VERSION: u16, V: MlsEntity<VERSION>>(&self, k: &[u8]) -> Option<V> {
        // We unwrap here, because the two functions claiming a write lock on
        // `init_key_package_bundles` (this one and `generate_key_package_bundle`) only
        // hold the lock very briefly and should not panic during that period.
        let values = self.values.read().unwrap();
        if let Some(value) = values.get(k) {
            let value = Value::tls_deserialize_exact(value).unwrap();
            serde_json::from_slice(value.value.as_slice()).ok()
        } else {
            None
        }
    }

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete<const VERSION: u16, V: MlsEntity<VERSION>>(
        &self,
        k: &[u8],
    ) -> Result<(), Self::Error> {
        // We just delete both ...
        let mut values = self.values.write().unwrap();
        values.remove(k);
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
