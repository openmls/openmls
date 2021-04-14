use psk::*;

use super::*;
use crate::group::{GroupEpoch, GroupId};

use std::convert::TryFrom;

impl Codec for PskType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        match PskType::try_from(u8::decode(cursor)?) {
            Ok(psk_type) => Ok(psk_type),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

impl Codec for ExternalPsk {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.psk_id())?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let psk_id = decode_vec(VecSize::VecU8, cursor)?;
        Ok(Self::new(psk_id))
    }
}

impl Codec for ReinitPsk {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.psk_group_id.encode(buffer)?;
        self.psk_epoch.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let psk_group_id = GroupId::decode(cursor)?;
        let psk_epoch = GroupEpoch::decode(cursor)?;
        Ok(Self {
            psk_group_id,
            psk_epoch,
        })
    }
}

impl Codec for BranchPsk {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.psk_group_id.encode(buffer)?;
        self.psk_epoch.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let psk_group_id = GroupId::decode(cursor)?;
        let psk_epoch = GroupEpoch::decode(cursor)?;
        Ok(Self {
            psk_group_id,
            psk_epoch,
        })
    }
}

impl Codec for PreSharedKeyId {
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
        let psktype = PskType::decode(cursor)?;
        let psk = match psktype {
            PskType::External => Psk::External(ExternalPsk::decode(cursor)?),
            PskType::Reinit => Psk::Reinit(ReinitPsk::decode(cursor)?),
            PskType::Branch => Psk::Branch(BranchPsk::decode(cursor)?),
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

impl<'a> Codec for PskLabel<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.id.encode(buffer)?;
        self.index.encode(buffer)?;
        self.count.encode(buffer)
    }
}
