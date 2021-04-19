use crate::codec::TlsSize;

use super::*;

impl Codec for ProtocolVersion {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(Self::try_from(u8::decode(cursor)?)?)
    }
}

impl TlsSize for ProtocolVersion {
    #[inline]
    fn serialized_len(&self) -> usize {
        1
    }
}
