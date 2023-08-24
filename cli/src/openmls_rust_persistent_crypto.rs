//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsCryptoProvider`] trait to use with
//! OpenMLS.

use std::borrow::BorrowMut;

use openmls_traits::OpenMlsCryptoProvider;
use openmls_rust_crypto::RustCrypto;
use serde::{Serialize,Deserialize};
use super::persistent_key_store::PersistentKeyStore;

#[derive(Default, Debug)]
pub struct OpenMlsRustPersistentCrypto {
    crypto: RustCrypto,
    key_store: PersistentKeyStore,
}

impl OpenMlsCryptoProvider for OpenMlsRustPersistentCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = PersistentKeyStore;

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

impl OpenMlsRustPersistentCrypto {
    pub fn persist_keystore(&self, user_name: String) {
        self.key_store.persist(user_name);
       
    }

    pub fn recover_keystore(&mut self, user_name: String) {
        self.key_store.recover(user_name);
       
    }
}