//! Section  9. Message Framing
//!
//! ```text
//! enum {
//!     reserved(0),
//!     application(1),
//!     proposal(2),
//!     commit(3),
//!     (255)
//! } ContentType;
//!
//! enum {
//!     reserved(0),
//!     member(1),
//!     preconfigured(2),
//!     new_member(3),
//!     (255)
//! } SenderType;
//!
//! struct {
//!     SenderType sender_type;
//!     uint32 sender;
//! } Sender;
//! ```

use crate::codec::*;

use super::*;
use std::convert::TryFrom;

#[derive(PartialEq, Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum SenderType {
    Member = 1,
    Preconfigured = 2,
    NewMember = 3,
}

impl TryFrom<u8> for SenderType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SenderType::Member),
            2 => Ok(SenderType::Preconfigured),
            3 => Ok(SenderType::NewMember),
            _ => Err("Unknown sender type."),
        }
    }
}

impl Codec for SenderType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        match SenderType::try_from(u8::decode(cursor)?) {
            Ok(sender_type) => Ok(sender_type),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

#[derive(PartialEq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Sender {
    pub(crate) sender_type: SenderType,
    pub(crate) sender: LeafIndex,
}
// Public functions
impl Sender {
    pub fn is_member(&self) -> bool {
        self.sender_type == SenderType::Member
    }
    pub fn to_leaf_index(self) -> LeafIndex {
        LeafIndex::from(self.to_node_index())
    }
}

//Private and crate functions
impl Sender {
    pub(crate) fn member(sender: LeafIndex) -> Self {
        Sender {
            sender_type: SenderType::Member,
            sender,
        }
    }
    pub(crate) fn to_node_index(self) -> NodeIndex {
        NodeIndex::from(self.sender)
    }
}

impl Codec for Sender {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.sender_type.encode(buffer)?;
        self.sender.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let sender_type = SenderType::decode(cursor)?;
        let sender = LeafIndex::from(u32::decode(cursor)?);
        Ok(Sender {
            sender_type,
            sender,
        })
    }
}
