use std::cell::Cell;

mod arrays;
#[cfg(feature = "hpke")]
mod hpke;
mod primitives;
mod tls_vec;
pub use tls_vec::{TlsVecU16, TlsVecU32, TlsVecU8};

#[cfg(feature = "derive")]
pub use tls_codec_derive::{TlsDeserialize, TlsSerialize};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Error {
    EncodingError,
    InvalidVectorLength,
    InvalidInput,
    DecodingError,
}

pub trait Serialize {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error>;

    fn serialize_detached(&self) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::new();
        self.tls_serialize(&mut buffer)?;
        Ok(buffer)
    }
}

pub trait Deserialize {
    fn tls_deserialize(cursor: &Cursor) -> Result<Self, Error>
    where
        Self: Sized;

    fn deserialize_detached(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Self::tls_deserialize(&Cursor::new(bytes))
    }
}

#[derive(Debug)]
pub struct Cursor {
    bytes: Vec<u8>,
    position: Cell<usize>,
}

impl Cursor {
    pub fn new(bytes: &[u8]) -> Cursor {
        Cursor {
            bytes: bytes.to_vec(),
            position: Cell::new(0),
        }
    }

    pub(crate) fn read(&self, length: usize) -> Result<&[u8], Error> {
        let unread_bytes = self.bytes.len() - self.position.get();
        if unread_bytes < length {
            return Err(Error::InvalidInput);
        }

        let position = self.position.get();
        self.position.replace(self.position.get() + length);
        Ok(&self.bytes[position..position + length])
    }

    pub(crate) fn sub_cursor(&self, length: usize) -> Result<Cursor, Error> {
        self.read(length).map(|buffer| Cursor::new(buffer))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.position.get() >= self.bytes.len()
    }

    pub(crate) fn has_more(&self) -> bool {
        !self.is_empty()
    }
}
