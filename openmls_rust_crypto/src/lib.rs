//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsCryptoProvider`] trait to use with
//! OpenMLS.

use memory_keystore::MemoryKeyStore;
use openmls_traits::OpenMlsCryptoProvider;
use rust_crypto::RustCrypto;

#[derive(Default, Debug)]
pub struct OpenMlsRustCrypto {
    crypto: RustCrypto,
    key_store: MemoryKeyStore,
}

impl OpenMlsCryptoProvider for OpenMlsRustCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = MemoryKeyStore;

    fn crypto_provider(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand_provider(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store_provider(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }
}
