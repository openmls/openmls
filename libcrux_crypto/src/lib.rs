use openmls_traits::{types::CryptoError, OpenMlsProvider};

mod crypto;
mod rand;

pub use crypto::CryptoProvider;
pub use rand::RandError;

/// The libcrux-backed provider for OpenMLS.
pub struct Provider {
    // The CryptoProvider serves as both the Rand and Crypto provider
    crypto: crypto::CryptoProvider,
    storage: openmls_memory_storage::MemoryStorage,
}

impl Provider {
    /// Instantiate a libcrux-based Provider
    /// This method uses non-panicking instantiation of the underlying CryptoProvider,
    /// and should be preferred to `Provider::default()`.
    pub fn new() -> Result<Self, CryptoError> {
        let crypto = crypto::CryptoProvider::new()?;
        let storage = openmls_memory_storage::MemoryStorage::default();

        Ok(Self { crypto, storage })
    }
}

impl Default for Provider {
    fn default() -> Self {
        let crypto = crypto::CryptoProvider::new().unwrap();
        let storage = openmls_memory_storage::MemoryStorage::default();

        Self { crypto, storage }
    }
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = CryptoProvider;
    type RandProvider = CryptoProvider;
    type StorageProvider = openmls_memory_storage::MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
