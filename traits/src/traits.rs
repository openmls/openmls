//! # OpenMLS Traits
//!
//! This module defines a number of traits that are used by the public
//! API of OpenMLS.
//!
//! ## Sync and async mode
//!
//! The storage traits come in a sync and an async flavor. The crate builds the
//! async flavor when the `async` feature is enabled and the `sync` feature is
//! not. Every other combination builds the sync flavor. `sync` takes
//! precedence so that `--all-features` builds keep the sync API.
//!
//! Crates that implement or call the storage traits mark their code with
//! [`maybe_async`](macro@crate::maybe_async) and follow the mode of this
//! crate. Functions and inherent `impl` blocks use
//! `#[openmls_traits::maybe_async]`. Trait declarations and trait `impl`
//! blocks use `#[openmls_traits::maybe_async(AFIT)]`.
//!
//! In async mode, storage futures are `Send`. Storage providers and the keys
//! and entities they handle must be `Sync` there, which [`MaybeSync`]
//! expresses. Storage errors must be `Send`, which [`MaybeSend`] expresses.

pub mod crypto;
pub mod grease;
pub mod public_storage;
pub mod random;
pub mod signatures;
pub mod storage;
pub mod types;

#[cfg(all(feature = "async", not(feature = "sync")))]
mod mode {
    /// Marks code that is written as async and follows the mode of
    /// `openmls_traits`. In async mode it leaves the code unchanged.
    pub use maybe_async::must_be_async as maybe_async;

    /// Requires `Sync` in async mode and is implemented by every type in sync
    /// mode. A future can only be `Send` if everything it borrows is `Sync`.
    pub trait MaybeSync: Sync {}
    impl<T: Sync + ?Sized> MaybeSync for T {}

    /// Requires `Send` in async mode and is implemented by every type in sync
    /// mode. OpenMLS futures can hold a storage error across an await.
    pub trait MaybeSend: Send {}
    impl<T: Send + ?Sized> MaybeSend for T {}
}

#[cfg(not(all(feature = "async", not(feature = "sync"))))]
mod mode {
    /// Marks code that is written as async and follows the mode of
    /// `openmls_traits`. In sync mode it removes `async` and `.await`.
    pub use maybe_async::must_be_sync as maybe_async;

    /// Requires `Sync` in async mode and is implemented by every type in sync
    /// mode. A future can only be `Send` if everything it borrows is `Sync`.
    pub trait MaybeSync {}
    impl<T: ?Sized> MaybeSync for T {}

    /// Requires `Send` in async mode and is implemented by every type in sync
    /// mode. OpenMLS futures can hold a storage error across an await.
    pub trait MaybeSend {}
    impl<T: ?Sized> MaybeSend for T {}
}

pub use mode::{maybe_async, MaybeSend, MaybeSync};

/// Stops compilation with a message naming `$crate_name` unless
/// `openmls_traits` is in async mode. Crates that only work in async mode use
/// it to report a feature mix-up before the trait mismatch errors.
#[cfg(all(feature = "async", not(feature = "sync")))]
#[macro_export]
macro_rules! require_async_mode {
    ($crate_name:literal) => {};
}

/// Stops compilation with a message naming `$crate_name` unless
/// `openmls_traits` is in async mode. Crates that only work in async mode use
/// it to report a feature mix-up before the trait mismatch errors.
#[cfg(not(all(feature = "async", not(feature = "sync"))))]
#[macro_export]
macro_rules! require_async_mode {
    ($crate_name:literal) => {
        compile_error!(concat!(
            $crate_name,
            " needs the async mode of openmls_traits, but the build uses the sync mode. ",
            "Enable the `async` feature and make sure no crate enables `sync`. ",
            "`cargo tree -e features -i openmls_traits` shows which crates enable it."
        ));
    };
}

/// A prelude to include to get all traits in scope and expose `openmls_types`.
pub mod prelude {
    pub use super::crypto::OpenMlsCrypto as _;
    pub use super::random::OpenMlsRand as _;
    pub use super::signatures::Signer as _;
    pub use super::storage::StorageProvider as _;
    pub use super::types as openmls_types;
    pub use super::OpenMlsProvider as _;
}

/// The OpenMLS Crypto Provider Trait
///
/// An implementation of this trait must be passed in to the public OpenMLS API
/// to perform randomness generation, cryptographic operations, and key storage.
// ANCHOR: openmls_provider
pub trait OpenMlsProvider {
    type CryptoProvider: crypto::OpenMlsCrypto;
    type RandProvider: random::OpenMlsRand;
    type StorageProvider: storage::StorageProvider<{ storage::CURRENT_VERSION }>;

    // Get the storage provider.
    fn storage(&self) -> &Self::StorageProvider;

    /// Get the crypto provider.
    fn crypto(&self) -> &Self::CryptoProvider;

    /// Get the randomness provider.
    fn rand(&self) -> &Self::RandProvider;
}
// ANCHOR_END: openmls_provider
