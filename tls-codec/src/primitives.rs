//! Codec implementations for unsigned integer primitives.

use super::{Cursor, Deserialize, Error, Serialize, TlsSize};

use std::convert::TryInto;

impl Serialize for u8 {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        buffer.push(*self);
        Ok(())
    }
}

impl TlsSize for u8 {
    #[inline]
    fn serialized_len(&self) -> usize {
        1
    }
}

impl Serialize for u16 {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        buffer.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl TlsSize for u16 {
    #[inline]
    fn serialized_len(&self) -> usize {
        2
    }
}

impl Serialize for u32 {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        buffer.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl TlsSize for u32 {
    #[inline]
    fn serialized_len(&self) -> usize {
        4
    }
}

impl Serialize for u64 {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        buffer.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl TlsSize for u64 {
    #[inline]
    fn serialized_len(&self) -> usize {
        8
    }
}

impl<T: TlsSize> TlsSize for Option<T> {
    #[inline]
    fn serialized_len(&self) -> usize {
        1 + match self {
            Some(v) => v.serialized_len(),
            None => 0,
        }
    }
}

impl Deserialize for u8 {
    fn tls_deserialize(cursor: &Cursor) -> Result<Self, Error> {
        cursor.read(1).map(|b| b[0])
    }
}

impl Deserialize for u16 {
    fn tls_deserialize(cursor: &Cursor) -> Result<Self, Error> {
        match cursor.read(2) {
            Ok(bytes) => Ok(u16::from_be_bytes(bytes.try_into()?)),
            Err(e) => Err(e),
        }
    }
}

impl Deserialize for u32 {
    fn tls_deserialize(cursor: &Cursor) -> Result<Self, Error> {
        match cursor.read(4) {
            Ok(bytes) => Ok(u32::from_be_bytes(bytes.try_into()?)),
            Err(e) => Err(e),
        }
    }
}

impl Deserialize for u64 {
    fn tls_deserialize(cursor: &Cursor) -> Result<Self, Error> {
        match cursor.read(8) {
            Ok(bytes) => Ok(u64::from_be_bytes(bytes.try_into()?)),
            Err(e) => Err(e),
        }
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(_e: std::array::TryFromSliceError) -> Self {
        Self::InvalidInput
    }
}
