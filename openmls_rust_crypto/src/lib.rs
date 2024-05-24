//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsProvider`] trait to use with
//! OpenMLS.

pub use openmls_memory_storage::{MemoryStorage, MemoryStorageError};
use openmls_traits::OpenMlsProvider;

mod provider;
pub use provider::*;

#[derive(Default, Debug)]
pub struct OpenMlsRustCrypto {
    crypto: RustCrypto,
    key_store: MemoryStorage,
}

impl serde::ser::Serialize for OpenMlsRustCrypto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.key_store.serialize(serializer)
    }
}

impl<'de> serde::de::Deserialize<'de> for OpenMlsRustCrypto {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let key_store = MemoryStorage::deserialize(deserializer)?;
        let crypto = RustCrypto::default();

        Ok(Self { crypto, key_store })
    }
}

impl OpenMlsProvider for OpenMlsRustCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.key_store
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
