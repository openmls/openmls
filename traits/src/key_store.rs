//! # OpenMLS Key Store Trait

use std::fmt::Debug;
use std::hash::Hash;

pub trait FromKeyStoreValue: Sized {
    type Error: Debug + Clone + PartialEq + Into<String>;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error>;
}

pub trait ToKeyStoreValue {
    type Error: Debug + Clone + PartialEq + Into<String>;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error>;
}

/// The Key Store trait
pub trait OpenMlsKeyStore: Send + Sync {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error: Debug + Clone + PartialEq + Into<String>;

    /// Store a value `v` that implements the [`KeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<K: Hash, V: ToKeyStoreValue>(&self, k: &K, v: &V) -> Result<(), Self::Error>
    where
        Self: Sized;

    /// Read and return a value stored for ID `k` that implements the
    /// [`KeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<K: Hash, V: FromKeyStoreValue>(&self, k: &K) -> Option<V>
    where
        Self: Sized;

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete<K: Hash>(&self, k: &K) -> Result<(), Self::Error>;
}
