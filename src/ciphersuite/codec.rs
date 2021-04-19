//! Codec implementations for the ciphersuites.
//! Provides encoding and decoding functionality.

use crate::ciphersuite::*;
use crate::codec::*;

use super::REUSE_GUARD_BYTES;

impl Codec for CiphersuiteName {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        u16::from(self).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        CiphersuiteName::try_from(u16::decode(cursor)?)
    }
}

impl TlsSize for CiphersuiteName {
    #[inline]
    fn serialized_len(&self) -> usize {
        2
    }
}

impl TlsSize for HPKEPublicKey {
    #[inline]
    fn serialized_len(&self) -> usize {
        2 + self.as_slice().len()
    }
}

impl Codec for SignatureScheme {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u16).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        if let Ok(credential_type) = Self::try_from(u16::decode(cursor)?) {
            Ok(credential_type)
        } else {
            Err(CodecError::DecodingError)
        }
    }
}

impl Codec for SignaturePublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.value)?;
        Ok(())
    }
}

impl Codec for Signature {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.value)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Self { value })
    }
}

impl tls_codec::TlsSize for Signature {
    #[inline]
    fn serialized_len(&self) -> usize {
        VecSize::VecU16.len_len() + self.value.len()
    }
}

impl Codec for HpkePublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, self.as_slice())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let inner = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Self::new(inner))
    }
}

impl Codec for HpkeCiphertext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.kem_output)?;
        encode_vec(VecSize::VecU16, buffer, &self.ciphertext)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let kem_output = decode_vec(VecSize::VecU16, cursor)?;
        let ciphertext = decode_vec(VecSize::VecU16, cursor)?;
        Ok(HpkeCiphertext {
            kem_output,
            ciphertext,
        })
    }
}

impl Codec for ReuseGuard {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        u32::from_be_bytes(self.value).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let u32_guard: u32 = u32::decode(cursor)?;
        let guard: [u8; REUSE_GUARD_BYTES] = u32_guard.to_be_bytes();
        Ok(ReuseGuard { value: guard })
    }
}

impl Codec for Secret {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.value)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = decode_vec(VecSize::VecU8, cursor)?;
        Ok(Secret {
            value,
            mls_version: ProtocolVersion::default(),
            ciphersuite: Ciphersuite::default(),
        })
    }
}

impl Codec for KdfLabel {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (self.length as u16).encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, self.label.as_bytes())?;
        encode_vec(VecSize::VecU32, buffer, &self.context)?;
        Ok(())
    }
}
