use super::{Cursor, Deserialize, Error, Serialize};

use std::convert::TryInto;

impl Serialize for u8 {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        buffer.push(*self);
        Ok(())
    }
}

impl Serialize for u16 {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        buffer.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl Serialize for u32 {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        buffer.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl Serialize for u64 {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        buffer.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl Deserialize for u8 {
    fn tls_deserialize(cursor: &Cursor) -> Result<Self, Error> {
        match cursor.read(1) {
            Ok(bytes) => Ok(bytes[0]),
            Err(e) => Err(e),
        }
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
