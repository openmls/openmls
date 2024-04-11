use openmls_storage_kv::{mem_kv_store::HashMapKv, KvStoreStorage};
use openmls_traits::OpenMlsProvider;

mod crypto;
mod rand;

pub use crypto::CryptoProvider;
pub use rand::RandError;
pub use rand::RandProvider;

/// The libcrux-backed provider for OpenMLS.
#[derive(Default)]
pub struct Provider<Types: openmls_traits::storage::Types<1>> {
    crypto: crypto::CryptoProvider,
    rand: rand::RandProvider,
    key_store: openmls_rust_crypto::MemoryKeyStore,
    storage: KvStoreStorage<HashMapKv, Types>,
}

impl<Types: openmls_traits::storage::Types<1>> OpenMlsProvider for Provider<Types> {
    type CryptoProvider = CryptoProvider;

    type RandProvider = RandProvider;

    type KeyStoreProvider = openmls_rust_crypto::MemoryKeyStore;

    type StorageProvider = KvStoreStorage<HashMapKv, Types>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
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
