use serde::Serialize;
use sqlx::error::BoxDynError;

/// A codec is used to serialize and deserialize OpenMLS data.
pub trait Codec: Default {
    /// The error type used by the codec.
    type Error: std::error::Error + std::fmt::Debug + Send + Sync + 'static;

    /// Serialize a value to a byte vector.
    fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Self::Error>;

    /// Deserialize a value from a byte slice.
    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error>;
}

/// An internal trait that extends `Codec` with a convenience method for
/// deserializing from a byte vector.
pub(crate) trait CodecInternal: Codec {
    /// Deserialize a value from a byte vector. This is just a convenience
    /// method for internal use that calls `from_slice`.
    fn from_bytes<T: serde::de::DeserializeOwned>(bytes: Vec<u8>) -> Result<T, sqlx::Error> {
        let value =
            Self::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(BoxDynError::from(e)))?;
        Ok(value)
    }
}

impl<T: Codec> CodecInternal for T {}
