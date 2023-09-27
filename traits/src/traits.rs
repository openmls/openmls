//! # OpenMLS Traits
//!
//! This module defines a number of traits that are used by the public
//! API of OpenMLS.

pub mod crypto;
pub mod key_store;
pub mod random;
pub mod signatures;
pub mod types;

/// The OpenMLS Crypto Provider Trait
///
/// An implementation of this trait must be passed in to the public OpenMLS API
/// to perform randomness generation, cryptographic operations, and key storage.
pub trait OpenMlsProvider {
    type CryptoProvider: crypto::OpenMlsCrypto;
    type RandProvider: random::OpenMlsRand;
    type KeyStoreProvider: key_store::OpenMlsKeyStore;

    /// Get the crypto provider.
    fn crypto(&self) -> &Self::CryptoProvider;

    /// Get the randomness provider.
    fn rand(&self) -> &Self::RandProvider;

    /// Get the key store provider.
    fn key_store(&self) -> &Self::KeyStoreProvider;
}
