//! Tls serialization implementations for the ciphersuites.
//! Provides encoding and decoding functionality.

use crate::ciphersuite::*;
use std::io::{Read, Write};
use tls_codec::{TlsSliceU16, TlsSliceU8, TlsVecU8};

impl tls_codec::Serialize for SignaturePublicKey {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        TlsSliceU16(&self.value).tls_serialize(writer)
    }
}

impl tls_codec::Size for SignaturePublicKey {
    fn tls_serialized_len(&self) -> usize {
        TlsSliceU16(&self.value).tls_serialized_len()
    }
}

impl tls_codec::Size for Secret {
    fn tls_serialized_len(&self) -> usize {
        TlsSliceU8(&self.value).tls_serialized_len()
    }
}

impl tls_codec::Serialize for Secret {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, ::tls_codec::Error> {
        TlsSliceU8(&self.value).tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for Secret {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, ::tls_codec::Error> {
        let value = TlsVecU8::tls_deserialize(bytes)?.into();
        Ok(Secret {
            value,
            mls_version: ProtocolVersion::default(),
            ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        })
    }
}
