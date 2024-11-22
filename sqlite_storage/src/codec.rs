use serde::Serialize;

pub trait CodecError: std::error::Error + std::fmt::Debug + Send + Sync + 'static {}

impl CodecError for serde_json::Error {}

pub trait Codec: Default {
    type Error: CodecError;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error>;
    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error>;
}

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}
