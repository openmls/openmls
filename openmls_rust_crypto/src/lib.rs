//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsCryptoProvider`] trait to use with
//! OpenMLS.

pub use openmls_memory_keystore::{MemoryKeyStore, MemoryKeyStoreError};
use openmls_traits::OpenMlsCryptoProvider;

mod provider;
pub use provider::*;

pub use openmls_traits;

#[derive(Default, Debug)]
pub struct OpenMlsRustCrypto {
    crypto: RustCrypto,
    key_store: MemoryKeyStore,
}

impl OpenMlsCryptoProvider for OpenMlsRustCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
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
