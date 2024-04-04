//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsProvider`] trait to use with
//! OpenMLS.

pub use openmls_memory_keystore::{MemoryKeyStore, MemoryKeyStoreError};
use openmls_traits::OpenMlsProvider;

use openmls_memory_storage::{kv::HashMapKV, KvStoreStorage};

mod provider;
pub use provider::*;

#[derive(Default, Debug)]
pub struct OpenMlsRustCrypto {
    crypto: RustCrypto,
    key_store: MemoryKeyStore,
    storage: KvStoreStorage<HashMapKV>,
}

impl OpenMlsProvider for OpenMlsRustCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = MemoryKeyStore;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }

    type Platform = HashMapKV;

    type StorageProvider = KvStoreStorage<HashMapKV>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}
