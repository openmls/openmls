use openmls_traits::{types::CryptoError, OpenMlsProvider};

mod crypto;
mod rand;

pub use crypto::CryptoProvider;
pub use rand::RandError;
pub use rand::RandProvider;

/// The libcrux-backed provider for OpenMLS.
pub struct Provider {
    crypto: crypto::CryptoProvider,
    rand: rand::RandProvider,
    storage: openmls_memory_storage::MemoryStorage,
}

impl Provider {
    pub fn new() -> Result<Self, CryptoError> {
        let crypto = crypto::CryptoProvider::new()?;
        let rand = todo!();
        let storage = openmls_memory_storage::MemoryStorage::default();

        Ok(Self {
            crypto,
            rand,
            storage,
        })
    }
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = CryptoProvider;
    type RandProvider = RandProvider;
    type StorageProvider = openmls_memory_storage::MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }
}
