//! Implement the TLS codec for some byte arrays.

use super::{Cursor, Deserialize, Error, Serialize, TlsSize};
use std::convert::TryInto;

macro_rules! impl_array {
    ($len:literal) => {
        impl Serialize for [u8; $len] {
            fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
                buffer.extend_from_slice(self);
                Ok(())
            }
        }

        impl Deserialize for [u8; $len] {
            fn tls_deserialize(cursor: &Cursor) -> Result<Self, Error> {
                Ok(cursor.read($len)?.try_into()?)
            }
        }

        impl TlsSize for [u8; $len] {
            #[inline]
            fn serialized_len(&self) -> usize {
                $len
            }
        }
    };
}

impl_array!(2);
impl_array!(4);
impl_array!(8);
impl_array!(16);
impl_array!(32);
impl_array!(64);
