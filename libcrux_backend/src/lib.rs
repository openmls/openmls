use openmls_memory_keystore::MemoryKeyStore;
use openmls_traits::OpenMlsCryptoProvider;

mod provider;
pub use provider::*;

pub use openmls_traits;

#[derive(Default)]
pub struct OpenMlsLibcrux {
    crypto: LibcruxProvider,
    key_store: MemoryKeyStore,
}

impl OpenMlsCryptoProvider for OpenMlsLibcrux {
    type CryptoProvider = LibcruxProvider;
    type RandProvider = LibcruxProvider;
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
}
