//! # OpenMLS Traits
//!
//! This module defines a number of traits that are used by the public
//! API of OpenMLS.

pub mod crypto;
pub mod key_store;
pub mod random;
pub mod types;

/// The OpenMLS Crypto Provider Trait
/// 
/// An implementation of this trait must be passed in to the public OpenMLS API
/// to perform randomness generation, cryptographic operations, and key storage.
pub trait OpenMlsCryptoProvider: Send + Sync {
    type CryptoProvider: crypto::OpenMlsCrypto;
    type RandProvider: random::OpenMlsRand;
    type KeyStoreProvider: key_store::OpenMlsKeyStore;

    fn crypto_provider(&self) -> &Self::CryptoProvider;
    fn rand_provider(&self) -> &Self::RandProvider;
    fn key_store_provider(&self) -> &Self::KeyStoreProvider;
}
