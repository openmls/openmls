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
use crate::tree::index::*;

#[derive(PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum SenderType {
    Invalid = 0,
    Member = 1,
    Preconfigured = 2,
    NewMember = 3,
    Default = 255,
}

impl From<u8> for SenderType {
    fn from(value: u8) -> Self {
        match value {
            0 => SenderType::Invalid,
            1 => SenderType::Member,
            2 => SenderType::Preconfigured,
            3 => SenderType::NewMember,
            _ => SenderType::Default,
        }
    }
}

impl Codec for SenderType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(SenderType::from(u8::decode(cursor)?))
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub struct Sender {
    pub(crate) sender_type: SenderType,
    pub(crate) sender: LeafIndex,
}

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
    pub fn to_leaf_index(self) -> LeafIndex {
        LeafIndex::from(self.to_node_index())
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
