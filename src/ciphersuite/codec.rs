// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

//! Codec implementations for the ciphersuites.
//! Provides encoding and decoding functionality.

use crate::ciphersuite::*;
use crate::codec::*;

impl Codec for CiphersuiteName {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        u16::from(self).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(CiphersuiteName::from(u16::decode(cursor)?))
    }
}

impl Codec for Ciphersuite {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (self.name as u16).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(Ciphersuite::new(CiphersuiteName::from(u16::decode(
            cursor,
        )?)))
    }
}

impl Codec for SignatureKeypair {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.ciphersuite.encode(buffer)?;
        self.private_key.encode(buffer)?;
        self.public_key.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let ciphersuite = Ciphersuite::decode(cursor)?;
        let private_key = SignaturePrivateKey::decode(cursor)?;
        let public_key = SignaturePublicKey::decode(cursor)?;
        Ok(Self {
            ciphersuite,
            private_key,
            public_key,
        })
    }
}

impl Codec for SignaturePublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.value)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Self { value })
    }
}

impl Codec for SignaturePrivateKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.value)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Self { value })
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
