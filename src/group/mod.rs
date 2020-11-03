//! Group APIs for MLS
//!
//! This file contains the API to interact with groups.
//!
//! The low-level standard API is described in the `Api` trait.\
//! The high-level API is exposed in `ManagedGroup`.

mod errors;
mod managed_group;
mod mls_group;

use crate::ciphersuite::*;
use crate::codec::*;
use crate::tree::*;
use crate::utils::*;

pub use codec::*;
pub use errors::*;
pub use managed_group::*;
pub use mls_group::*;

pub enum GroupError {
    Codec(CodecError),
}

impl From<CodecError> for GroupError {
    fn from(err: CodecError) -> GroupError {
        GroupError::Codec(err)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct GroupId {
    pub value: Vec<u8>,
}

impl GroupId {
    pub fn random() -> Self {
        Self {
            value: randombytes(16),
        }
    }
    pub fn from_slice(bytes: &[u8]) -> Self {
        GroupId {
            value: bytes.to_vec(),
        }
    }
    pub fn as_slice(&self) -> Vec<u8> {
        self.value.clone()
    }
}

impl Codec for GroupId {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.value)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = decode_vec(VecSize::VecU8, cursor)?;
        Ok(GroupId { value })
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct GroupEpoch(pub u64);

impl GroupEpoch {
    pub fn increment(&mut self) {
        self.0 += 1;
    }
}

impl Codec for GroupEpoch {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let inner = u64::decode(cursor)?;
        Ok(GroupEpoch(inner))
    }
}

#[derive(Debug, Clone)]
pub struct GroupContext {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: Vec<u8>,
}

impl GroupContext {
    pub fn serialize(&self) -> Vec<u8> {
        self.encode_detached().unwrap()
    }
}

impl Codec for GroupContext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.tree_hash)?;
        encode_vec(VecSize::VecU8, buffer, &self.confirmed_transcript_hash)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let tree_hash = decode_vec(VecSize::VecU8, cursor)?;
        let confirmed_transcript_hash = decode_vec(VecSize::VecU8, cursor)?;
        Ok(GroupContext {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
        })
    }
}

/// Configuration for an MLS group.
#[derive(Clone, Copy, Debug)]
pub struct GroupConfig {
    /// Flag whether to send the ratchet tree along with the `GroupInfo` or not.
    /// Defaults to false.
    pub add_ratchet_tree_extension: bool,
    pub padding_block_size: u32,
    pub additional_as_epochs: u32,
}

impl GroupConfig {
    /// Get the padding block size used in this config.
    pub fn get_padding_block_size(&self) -> u32 {
        self.padding_block_size
    }
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            add_ratchet_tree_extension: false,
            padding_block_size: 10,
            additional_as_epochs: 0,
        }
    }
}

impl Codec for GroupConfig {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.padding_block_size.encode(buffer)?;
        self.additional_as_epochs.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let padding_block_size = u32::decode(cursor)?;
        let additional_as_epochs = u32::decode(cursor)?;
        Ok(GroupConfig {
            add_ratchet_tree_extension: false,
            padding_block_size,
            additional_as_epochs,
        })
    }
}
