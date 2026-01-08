use openmls_traits::{types::CryptoError, OpenMlsProvider};

mod crypto;
mod rand;

pub use crypto::CryptoProvider;
pub use rand::RandError;

/// The libcrux-backed provider for OpenMLS.
pub struct Provider {
    // The CryptoProvider serves as both the Rand and Crypto provider
    crypto: crypto::CryptoProvider,
    storage: openmls_memory_storage::MemoryStorageManager,
}

impl Provider {
    /// Instantiate a libcrux-based Provider
    /// This method uses non-panicking instantiation of the underlying CryptoProvider,
    /// and should be preferred to `Provider::default()`.
    pub fn new() -> Result<Self, CryptoError> {
        let crypto = crypto::CryptoProvider::new()?;
        let storage = openmls_memory_storage::MemoryStorageManager::default();

        Ok(Self { crypto, storage })
    }
}

impl Default for Provider {
    fn default() -> Self {
        let crypto = crypto::CryptoProvider::new().unwrap();
        let storage = openmls_memory_storage::MemoryStorageManager::default();

        Self { crypto, storage }
    }
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = CryptoProvider;
    type RandProvider = CryptoProvider;
    type StorageProviderManager = openmls_memory_storage::MemoryStorageManager;

    fn storage_manager(&self) -> &Self::StorageProviderManager {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
