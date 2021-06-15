//! Codec implementations for the ciphersuites.
//! Provides encoding and decoding functionality.

use crate::ciphersuite::*;
use crate::codec::*;

use super::REUSE_GUARD_BYTES;

implement_codec! {
    CiphersuiteName,
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        u16::from(self).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        CiphersuiteName::try_from(u16::decode(cursor)?)
    }
}

implement_codec! {
    SignatureScheme,
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

impl Encode for SignaturePublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.value)?;
        Ok(())
    }
}

implement_codec! {
    Signature,
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

implement_codec! {
    HpkePublicKey,
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, self.as_slice())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let inner = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Self::new(inner))
    }
}

implement_codec! {
    HpkeCiphertext,
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

implement_codec! {
    ReuseGuard,
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

implement_codec! {
    Secret,
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

impl Encode for KdfLabel {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (self.length as u16).encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, self.label.as_bytes())?;
        encode_vec(VecSize::VecU32, buffer, &self.context)?;
        Ok(())
    }
}
