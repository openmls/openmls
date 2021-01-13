use psk::*;

use super::*;

use std::convert::TryFrom;

impl Codec for PSKType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        match PSKType::try_from(u8::decode(cursor)?) {
            Ok(psk_type) => Ok(psk_type),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

impl Codec for ExternalPsk {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.psk_id)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let psk_id = decode_vec(VecSize::VecU8, cursor)?;
        Ok(Self { psk_id })
    }
}

impl Codec for ReinitPsk {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.psk_group_id)?;
        self.psk_epoch.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let psk_group_id = decode_vec(VecSize::VecU8, cursor)?;
        let psk_epoch = u64::decode(cursor)?;
        Ok(Self {
            psk_group_id,
            psk_epoch,
        })
    }
}

impl Codec for BranchPsk {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.psk_group_id)?;
        self.psk_epoch.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let psk_group_id = decode_vec(VecSize::VecU8, cursor)?;
        let psk_epoch = u64::decode(cursor)?;
        Ok(Self {
            psk_group_id,
            psk_epoch,
        })
    }
}

impl Codec for PreSharedKeyID {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.psk_type.encode(buffer)?;
        match &self.psk {
            Psk::External(external_psk) => external_psk.encode(buffer)?,
            Psk::Reinit(reinit_psk) => reinit_psk.encode(buffer)?,
            Psk::Branch(branch_psk) => branch_psk.encode(buffer)?,
        }
        encode_vec(VecSize::VecU8, buffer, &self.psk_nonce)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let psktype = PSKType::decode(cursor)?;
        let psk = match psktype {
            PSKType::External => Psk::External(ExternalPsk::decode(cursor)?),
            PSKType::Reinit => Psk::Reinit(ReinitPsk::decode(cursor)?),
            PSKType::Branch => Psk::Branch(BranchPsk::decode(cursor)?),
        };
        let psk_nonce = decode_vec(VecSize::VecU8, cursor)?;
        Ok(Self {
            psk_type: psktype,
            psk,
            psk_nonce,
        })
    }
}

impl Codec for PreSharedKeys {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.psks)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let psks = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Self { psks })
    }
}

impl Codec for JoinerSecret {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.secret.encode(buffer)
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let secret = Secret::decode(cursor)?;
        Ok(JoinerSecret { secret })
    }
}
