//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsCryptoProvider`] trait to use with
//! OpenMLS.

use super::persistent_key_store::PersistentStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;

#[derive(Default, Debug)]
pub struct OpenMlsRustPersistentCrypto {
    crypto: RustCrypto,
    storage: PersistentStorage,
}

impl OpenMlsProvider for OpenMlsRustPersistentCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    type StorageProvider = PersistentStorage;

    fn storage(&self) -> &Self::StorageProvider {
        todo!()
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
