// use openmls_storage_kv::{mem_kv_store::HashMapKv, KvStoreStorage};
use openmls_traits::OpenMlsProvider;

mod crypto;
mod rand;

pub use crypto::CryptoProvider;
pub use rand::RandError;
pub use rand::RandProvider;

/// The libcrux-backed provider for OpenMLS.
#[derive(Default)]
pub struct Provider {
    crypto: crypto::CryptoProvider,
    rand: rand::RandProvider,
    key_store: openmls_rust_crypto::MemoryKeyStore,
    // storage: KvStoreStorage<HashMapKv, Types>,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = CryptoProvider;
    type RandProvider = RandProvider;
    type KeyStoreProvider = openmls_rust_crypto::MemoryKeyStore;
    type StorageProvider = openmls_rust_crypto::MemoryKeyStore;

    fn storage(&self) -> &Self::StorageProvider {
        &self.key_store
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }
}
