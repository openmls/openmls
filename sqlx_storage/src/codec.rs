use serde::Serialize;
use sqlx::error::BoxDynError;

pub trait Codec: Default {
    type Error: std::error::Error + std::fmt::Debug + Send + Sync + 'static;

    fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Self::Error>;
    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error>;

    fn from_bytes<T: serde::de::DeserializeOwned>(bytes: Vec<u8>) -> Result<T, sqlx::Error> {
        let value =
            Self::from_slice(&bytes).map_err(|e| sqlx::Error::Decode(BoxDynError::from(e)))?;
        Ok(value)
    }
}
