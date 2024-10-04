//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsProvider`] trait to use with
//! OpenMLS.

use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;

#[derive(Default, Debug)]
pub struct OpenMlsRustPersistentCrypto {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for OpenMlsRustPersistentCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}

impl OpenMlsRustPersistentCrypto {
    pub fn save_keystore(&self, user_name: String) -> Result<(), String> {
        self.storage.save(user_name)
    }

    pub fn load_keystore(&mut self, user_name: String) -> Result<(), String> {
        self.storage.load(user_name)
    }
}
