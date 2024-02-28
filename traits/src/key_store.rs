//! # OpenMLS Key Store Trait

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// Sealed list of struct openmls manages (create/read/delete) through [OpenMlsKeyStore]
#[derive(Debug, TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(u16)]
pub enum MlsEntityId {
    SignatureKeyPair,
    HpkePrivateKey,
    KeyPackage,
    PskBundle,
    EncryptionKeyPair,
    GroupState,
}

pub trait MlsEntity<const VERSION: u16>: serde::Serialize + serde::de::DeserializeOwned {
    /// Identifier used to downcast the actual entity within an [OpenMlsKeyStore] method.
    /// In case for example you need to select a SQL table depending on the entity type
    const ID: MlsEntityId;
}

/// Blanket impl for when you have to lookup a list of entities from the keystore
impl<T, const VERSION: u16> MlsEntity<VERSION> for Vec<T>
where
    T: MlsEntity<VERSION> + std::fmt::Debug,
{
    const ID: MlsEntityId = T::ID;
}

/// The Key Store trait
pub trait OpenMlsKeyStore {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error: std::error::Error + std::fmt::Debug + PartialEq;

    /// Store a value `v` that implements the [`MlsEntity`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<const VERSION: u16, V: MlsEntity<VERSION> + core::fmt::Debug>(
        &self,
        k: &[u8],
        v: &V,
    ) -> Result<(), Self::Error>
    where
        Self: Sized;

    /// Read and return a value stored for ID `k` that implements the
    /// [`MlsEntity`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<const VERSION: u16, V: MlsEntity<VERSION>>(&self, k: &[u8]) -> Option<V>
    where
        Self: Sized;

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete<const VERSION: u16, V: MlsEntity<VERSION>>(
        &self,
        k: &[u8],
    ) -> Result<(), Self::Error>;
}
