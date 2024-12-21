use serde::Serialize;

pub trait Codec: Default {
    type Error: std::error::Error + std::fmt::Debug + Send + Sync + 'static;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error>;
    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error>;
}
