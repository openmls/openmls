//! Tls serialization implementations for the ciphersuites.
//! Provides encoding and decoding functionality.

use std::io::{Read, Write};

use ::tls_codec::Error;
use tls_codec::{Deserialize, DeserializeBytes, Serialize, Size};

use crate::ciphersuite::*;

impl Size for Secret {
    fn tls_serialized_len(&self) -> usize {
        self.value.tls_serialized_len()
    }
}

impl Serialize for Secret {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.value.tls_serialize(writer)
    }
}

impl Deserialize for Secret {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        let value = Vec::tls_deserialize(bytes)?;
        Ok(Secret {
            value: value.into(),
        })
    }
}

impl DeserializeBytes for Secret {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let secret = Secret::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[secret.tls_serialized_len()..];
        Ok((secret, remainder))
    }
}
