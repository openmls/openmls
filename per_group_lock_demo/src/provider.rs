//! A sample OpenMlsProvider.

/// A sample OpenMlsProvider.
pub struct Provider {
    crypto: openmls_libcrux_crypto::CryptoProvider,
    storage: crate::data_lock_handler::DataLockHandler,
}

impl Default for Provider {
    fn default() -> Self {
        let crypto = openmls_libcrux_crypto::CryptoProvider::new().unwrap();

        // TODO: initialize
        let storage = Default::default();

        Self { crypto, storage }
    }
}

impl crate::traits::OpenMlsProvider for Provider {
    type CryptoProvider = openmls_libcrux_crypto::CryptoProvider;
    type RandProvider = openmls_libcrux_crypto::CryptoProvider;

    // replace the `StorageProvider` type
    type StorageProviderManager = crate::data_lock_handler::DataLockHandler;

    /// Get the storage provider manager.
    fn storage_manager(&self) -> &Self::StorageProviderManager {
        &self.storage
    }

    /// Get the crypto provider.
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    /// Get the randomness provider.
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

#[cfg(test)]
/// (For test purposes) Non-locking implementation of OpenMlsProvider for test provider
impl openmls_traits::OpenMlsProvider for Provider {
    type CryptoProvider = openmls_libcrux_crypto::CryptoProvider;
    type RandProvider = openmls_libcrux_crypto::CryptoProvider;

    // replace the `StorageProvider` type with the `StorageProviderManager`
    type StorageProvider = openmls_memory_storage::MemoryStorage;

    /// XXX: unsafe. For testing purposes only
    fn storage(&self) -> &Self::StorageProvider {
        self.storage.memory_storage()
    }

    /// Get the crypto provider.
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    /// Get the randomness provider.
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
