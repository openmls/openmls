//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsProvider`] trait to use with
//! OpenMLS.

pub use openmls_memory_keystore::{MemoryKeyStore, MemoryKeyStoreError};
use openmls_traits::OpenMlsProvider;

use openmls_storage_kv::{mem_kv_store::HashMapKv, KvStoreStorage};

mod provider;
pub use provider::*;

#[derive(Default, Debug)]
pub struct OpenMlsRustCrypto<Types: openmls_traits::storage::Types<1>> {
    crypto: RustCrypto,
    key_store: MemoryKeyStore,
    storage: KvStoreStorage<HashMapKv, Types>,
}

impl<Types: openmls_traits::storage::Types<1>> OpenMlsProvider for OpenMlsRustCrypto<Types> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = MemoryKeyStore;
    type StorageProvider = KvStoreStorage<HashMapKv, Types>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn storage_mut(&mut self) -> &mut Self::StorageProvider {
        &mut self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }
}
