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
    key_store: openmls_rust_crypto::MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = CryptoProvider;
    type RandProvider = RandProvider;
    type StorageProvider = openmls_rust_crypto::MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.key_store
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }
}
