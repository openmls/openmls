use super::*;
use crate::codec::{Cursor, Decode, Encode};

implement_codec! {
    ProtocolVersion,
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(Self::try_from(u8::decode(cursor)?)?)
    }
}
