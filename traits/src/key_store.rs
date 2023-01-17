//! # OpenMLS Key Store Trait

use std::{convert::Infallible, fmt::Debug};

pub trait FromKeyStoreValue: Sized {
    type Error: std::error::Error + Debug;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error>;
}

pub trait ToKeyStoreValue {
    type Error: std::error::Error + Debug;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error>;
}

/// The Key Store trait
pub trait OpenMlsKeyStore: Send + Sync + Debug {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error: std::error::Error + Debug + PartialEq + Clone;

    /// Load all encryption keys associated with the given identity, epoch and group ID from the key store.
    fn read_epoch_keys<V: FromKeyStoreValue>(
        &self,
        identity: &[u8],
        group_id: &[u8],
        epoch: u64,
    ) -> Option<Vec<V>>;

    /// Store all encryption keys associated with the given identity, epoch and
    /// group ID in the key store.
    fn store_epoch_keys<V: ToKeyStoreValue>(
        &self,
        identity: &[u8],
        group_id: &[u8],
        epoch: u64,
        encryption_keys: &[&V],
    ) -> Result<(), Self::Error>;

    /// Delete all encryption keys associated with the given identity, epoch and
    /// group ID from the key store.
    fn delete_epoch_keys(
        &self,
        identity: &[u8],
        group_id: &[u8],
        epoch: u64,
    ) -> Result<(), Self::Error>;

    /// Store a value `v` that implements the [`ToKeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<V: ToKeyStoreValue>(&self, k: &[u8], v: &V) -> Result<(), Self::Error>
    where
        Self: Sized;

    /// Read and return a value stored for ID `k` that implements the
    /// [`FromKeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<V: FromKeyStoreValue>(&self, k: &[u8]) -> Option<V>
    where
        Self: Sized;

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete(&self, k: &[u8]) -> Result<(), Self::Error>;
}

impl ToKeyStoreValue for Vec<u8> {
    type Error = Infallible;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.clone())
    }
}

impl FromKeyStoreValue for Vec<u8> {
    type Error = Infallible;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error> {
        Ok(ksv.to_vec())
    }
}
