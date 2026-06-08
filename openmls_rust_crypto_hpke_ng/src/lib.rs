//! # OpenMLS Default Crypto Provider (hpke-ng)
//!
//! This is an implementation of the [`OpenMlsProvider`] trait to use with
//! OpenMLS, identical to [`openmls_rust_crypto`] except that HPKE is provided
//! by [`hpke-ng`](https://github.com/symbolicsoft/hpke-ng) rather than
//! [`hpke-rs`](https://docs.rs/hpke-rs).

pub use openmls_memory_storage::{MemoryStorage, MemoryStorageError};
use openmls_traits::OpenMlsProvider;

mod provider;
pub use provider::*;

mod hmac;

#[derive(Default, Debug)]
#[cfg_attr(feature = "test-utils", derive(Clone))]
pub struct OpenMlsRustCrypto {
    crypto: RustCrypto,
    key_store: MemoryStorage,
}

impl OpenMlsProvider for OpenMlsRustCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.key_store
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
