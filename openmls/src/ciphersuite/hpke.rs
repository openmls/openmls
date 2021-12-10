//! Helper for HPKE

use super::*;

/// A simple wrapper for HPKE public keys using `Vec<u8>` for (de)serializing.
#[derive(Debug, Eq, Hash, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct HpkePublicKey {
    value: Vec<u8>,
}

impl HpkePublicKey {
    /// Get the raw byte value as slice.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
}

/// A simple wrapper for HPKE private keys using `Vec<u8>` for (de)serializing.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct HpkePrivateKey {
    value: Vec<u8>,
}

impl HpkePrivateKey {
    /// Get the raw byte value as slice.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl From<Vec<u8>> for HpkePublicKey {
    fn from(value: Vec<u8>) -> Self {
        Self { value }
    }
}

impl From<Vec<u8>> for HpkePrivateKey {
    fn from(value: Vec<u8>) -> Self {
        Self { value }
    }
}

impl tls_codec::Size for HpkePublicKey {
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        tls_codec::TlsByteSliceU16(self.value.as_slice()).tls_serialized_len()
    }
}

impl tls_codec::Serialize for HpkePublicKey {
    #[inline(always)]
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        tls_codec::TlsByteSliceU16(self.value.as_slice()).tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for HpkePublicKey {
    #[inline(always)]
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Ok(Self {
            value: tls_codec::TlsByteVecU16::tls_deserialize(bytes)?.into(),
        })
    }
}

impl tls_codec::Size for &HpkePublicKey {
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        tls_codec::TlsByteSliceU16(self.value.as_slice()).tls_serialized_len()
    }
}

impl tls_codec::Serialize for &HpkePublicKey {
    #[inline(always)]
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        tls_codec::TlsByteSliceU16(self.value.as_slice()).tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for &HpkePublicKey {
    #[inline(always)]
    fn tls_deserialize<R: std::io::Read>(_: &mut R) -> Result<Self, tls_codec::Error> {
        Err(tls_codec::Error::DecodingError(
            "Error trying to deserialize a reference.".to_string(),
        ))
    }
}

// A hopefully value independent implementation of [`PartialEq`] for HPKE private
// keys. The compiler might still introduce secret dependent branching.
impl PartialEq for HpkePrivateKey {
    fn eq(&self, other: &Self) -> bool {
        if self.value.len() != other.value.len() {
            return false;
        }

        equal_ct(self.value.as_slice(), other.value.as_slice())
    }
}

impl std::fmt::Debug for HpkePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("HpkePrivateKey")
            .field("value", &"***")
            .finish()
    }
}
