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
        Ok(CiphersuiteName::try_from(u16::decode(cursor)?)?)
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

impl Codec for HPKEPublicKey {
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
        Ok(Secret { value })
    }
}
