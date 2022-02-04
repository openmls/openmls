use openmls_memory_keystore::MemoryKeyStore;
use openmls_traits::OpenMlsCryptoProvider;

mod provider;
pub use provider::*;

#[derive(Default, Debug)]
pub struct OpenMlsEvercrypt {
    crypto: EvercryptProvider,
    key_store: MemoryKeyStore,
}

impl OpenMlsCryptoProvider for OpenMlsEvercrypt {
    type CryptoProvider = EvercryptProvider;
    type RandProvider = EvercryptProvider;
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
