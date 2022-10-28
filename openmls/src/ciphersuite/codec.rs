//! Tls serialization implementations for the ciphersuites.
//! Provides encoding and decoding functionality.

use crate::ciphersuite::*;
use std::io::{Read, Write};

impl tls_codec::Serialize for SignaturePublicKey {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.value.tls_serialize(writer)
    }
}

impl tls_codec::Size for SignaturePublicKey {
    fn tls_serialized_len(&self) -> usize {
        self.value.tls_serialized_len()
    }
}

impl tls_codec::Size for Secret {
    fn tls_serialized_len(&self) -> usize {
        self.value.tls_serialized_len()
    }
}

impl tls_codec::Serialize for Secret {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, ::tls_codec::Error> {
        self.value.tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for Secret {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, ::tls_codec::Error> {
        let value = Vec::tls_deserialize(bytes)?;
        Ok(Secret {
            value,
            mls_version: ProtocolVersion::default(),
            ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        })
    }
}
