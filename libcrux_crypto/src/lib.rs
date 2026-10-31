use openmls_traits::{types::CryptoError, OpenMlsProvider};

mod crypto;
#[cfg(feature = "virtual-clients-draft")]
mod ff1;
mod rand;

/// The `rand` traits an entropy source passed to
/// [`CryptoProvider::with_entropy_source`] must implement, re-exported so that
/// callers implement the version this crate uses.
pub use ::rand::{TryCryptoRng, TryRng};
pub use crypto::CryptoProvider;
pub use rand::RandError;

/// The libcrux-backed provider for OpenMLS.
///
/// The randomness for both [`OpenMlsProvider::rand`] and
/// [`OpenMlsProvider::crypto`] comes from the entropy source `R`; see
/// [`CryptoProvider`].
pub struct Provider<R = ::rand::rngs::SysRng> {
    // The CryptoProvider serves as both the Rand and Crypto provider
    crypto: crypto::CryptoProvider<R>,
    storage: openmls_memory_storage::MemoryStorage,
}

impl Provider {
    /// Instantiate a libcrux-based Provider
    /// This method uses non-panicking instantiation of the underlying CryptoProvider,
    /// and should be preferred to `Provider::default()`.
    pub fn new() -> Result<Self, CryptoError> {
        let crypto = crypto::CryptoProvider::new()?;
        let storage = openmls_memory_storage::MemoryStorage::default();

        Ok(Self { crypto, storage })
    }
}

impl<R: ::rand::TryCryptoRng + Send + 'static> Provider<R> {
    /// Instantiate a libcrux-based Provider whose randomness is seeded and
    /// reseeded from `source`. See [`CryptoProvider::with_entropy_source`].
    pub fn with_entropy_source(source: R) -> Result<Self, CryptoError> {
        let crypto = crypto::CryptoProvider::with_entropy_source(source)?;
        let storage = openmls_memory_storage::MemoryStorage::default();

        Ok(Self { crypto, storage })
    }
}

impl Default for Provider {
    fn default() -> Self {
        let crypto = crypto::CryptoProvider::new().unwrap();
        let storage = openmls_memory_storage::MemoryStorage::default();

        Self { crypto, storage }
    }
}

impl<R: ::rand::TryCryptoRng + Send + 'static> OpenMlsProvider for Provider<R> {
    type CryptoProvider = CryptoProvider<R>;
    type RandProvider = CryptoProvider<R>;
    type StorageProvider = openmls_memory_storage::MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
