use openmls_traits::OpenMlsProvider;

mod crypto;
mod rand;

pub use crypto::CryptoProvider;
pub use rand::RandError;
pub use rand::RandProvider;

/// The libcrux-backed provider for OpenMLS.
pub struct Provider {
    crypto: crypto::CryptoProvider,
    rand: rand::RandProvider,
    key_store: openmls_rust_crypto::MemoryKeyStore,
}

impl Default for Provider {
    fn default() -> Self {
        Self {
            crypto: Default::default(),
            rand: Default::default(),
            key_store: Default::default(),
        }
    }
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = CryptoProvider;

    type RandProvider = RandProvider;

    type KeyStoreProvider = openmls_rust_crypto::MemoryKeyStore;

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
