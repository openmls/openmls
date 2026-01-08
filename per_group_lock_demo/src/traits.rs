//! Adapted versions of the OpenMLS provider traits, to illustrate proposed API changes

use crate::Error;

// Import here for conciseness
pub(crate) use openmls_traits::storage::CURRENT_VERSION;

// TODO: `StorageProviderGuard` and `StorageProvider` should not be separate traits
/// A lock guard for a storage provider
pub trait StorageProviderGuard<const CURRENT_VERSION: u16> {
    type Provider: openmls_traits::storage::StorageProvider<CURRENT_VERSION>;

    fn provider(&self) -> &Self::Provider;
}

/// A locking handler for a provider, tied to a specific GroupId
pub trait StorageProviderHandle<const CURRENT_VERSION: u16> {
    // TODO: combine with the Provider type above
    type Guard<'lock, 'a: 'lock>: StorageProviderGuard<CURRENT_VERSION>
    where
        Self: 'a;

    // NOTE: this syntax is used instead of `async fn`, since `async fn` in public traits is
    // discouraged
    // see lint `async-fn-in-trait`
    fn lock(&self) -> impl std::future::Future<Output = Self::Guard<'_, '_>>;
}

/// A trait for managing storage providers
pub trait StorageProviderManager<const CURRENT_VERSION: u16> {
    type Handle<'a>: StorageProviderHandle<CURRENT_VERSION>
    where
        Self: 'a;

    fn get_handle<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        id: &GroupId,
    ) -> Result<Self::Handle<'_>, Error>;
}

pub trait OpenMlsProvider {
    type CryptoProvider: openmls_traits::crypto::OpenMlsCrypto;
    type RandProvider: openmls_traits::random::OpenMlsRand;

    // replace the `StorageProvider` type with the `StorageProviderManager`
    type StorageProviderManager: StorageProviderManager<{ CURRENT_VERSION }>;

    /// Get the storage provider manager.
    fn storage_manager(&self) -> &Self::StorageProviderManager;

    /// Get the crypto provider.
    fn crypto(&self) -> &Self::CryptoProvider;

    /// Get the randomness provider.
    fn rand(&self) -> &Self::RandProvider;
}
