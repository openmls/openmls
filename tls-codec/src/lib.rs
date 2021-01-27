//! # TLS Codec
//!
//! This crate implements the TLS codec as defined in [RFC 8446](https://tools.ietf.org/html/rfc8446)
//! as well as some extensions required by MLS.
//!
//! With the feature `derive` `TlsSerialize` and `TlsDeserialize` can be derived.
//!
//! Tis crate provides the following data structures that implement TLS serialization
//! * `u8`, `u16`, `u32`, `u64`
//! * `TlsVecU8`, `TlsVecU16`, `TlsVecU32`
//! * `[u8; 2]`, `[u8; 4]`, `[u8; 8]`, `[u8; 16]`, `[u8; 32]`, `[u8; 64]`
//! * If the `hpke` features is enabled, the TLS codec is implemented for
//!  `HPKEPublicKeys` from [hpke-rs](https://github.com/franziskuskiefer/hpke-rs).

use std::cell::Cell;

mod arrays;
#[cfg(feature = "hpke")]
mod hpke;
mod primitives;
mod tls_vec;
pub use tls_vec::{TlsVecU16, TlsVecU32, TlsVecU8};

#[cfg(feature = "derive")]
pub use tls_codec_derive::{TlsDeserialize, TlsSerialize};

/// Errors that are thrown by this crate.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Error {
    /// An error occurred during encoding.
    EncodingError,

    /// The length of a vector is invalid.
    InvalidVectorLength,

    /// Invalid input when trying to decode a primitive integer.
    InvalidInput,

    /// An error occurred during decoding.
    DecodingError,
}

/// The `Serialize` trait provides functions to serialize a struct or enum.
///
/// The trait provides two functions:
/// * `tls_serialize` that takes a buffer to write the serialization to
/// * `tls_serialize_detached` that returns a byte vector
pub trait Serialize {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error>;

    fn tls_serialize_detached(&self) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::new();
        self.tls_serialize(&mut buffer)?;
        Ok(buffer)
    }
}

/// The `Deserialize` trait provides functions to deserialize a byte slice to a
/// struct or enum.
///
/// The trait provides two functions:
/// * `tls_deserialize` that takes a [`Cursor`] to read from
/// * `tls_deserialize_detached` that takes a byte slice
pub trait Deserialize {
    fn tls_deserialize(cursor: &Cursor) -> Result<Self, Error>
    where
        Self: Sized;

    fn tls_deserialize_detached(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Self::tls_deserialize(&Cursor::new(bytes))
    }
}

/// The `Cursor` is a helper used to read byte slices when deserializing.
/// Note that this shouldn't be needed in most cases and `tls_deserialize_detached`
/// can be used instead.
#[derive(Debug)]
pub struct Cursor {
    bytes: Vec<u8>,
    position: Cell<usize>,
}

impl Cursor {
    /// Create a new `Cursor` from a byte slice.
    /// This function copies the content of `bytes`.
    pub fn new(bytes: &[u8]) -> Cursor {
        Cursor {
            bytes: bytes.to_vec(),
            position: Cell::new(0),
        }
    }

    // Read `length` bytes from the cursor and return the slice.
    pub(crate) fn read(&self, length: usize) -> Result<&[u8], Error> {
        let unread_bytes = self.bytes.len() - self.position.get();
        if unread_bytes < length {
            return Err(Error::InvalidInput);
        }

        let position = self.position.get();
        self.position.replace(self.position.get() + length);
        Ok(&self.bytes[position..position + length])
    }

    // Create a new cursor with the given `length`.
    pub(crate) fn sub_cursor(&self, length: usize) -> Result<Cursor, Error> {
        self.read(length).map(|buffer| Cursor::new(buffer))
    }

    // Check if the cursor is empty/fully read.
    pub(crate) fn is_empty(&self) -> bool {
        self.position.get() >= self.bytes.len()
    }

    // Check if there are more bytes that can be read.
    pub(crate) fn has_more(&self) -> bool {
        !self.is_empty()
    }
}
