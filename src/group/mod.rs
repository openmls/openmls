//! Group APIs for MLS
//!
//! This file contains the API to interact with groups.
//!
//! The low-level standard API is described in the `Api` trait.\
//! The high-level API is exposed in `ManagedGroup`.

mod codec;
pub mod errors;
mod managed_group;
mod mls_group;

use crate::ciphersuite::*;
use crate::codec::*;
use crate::utils::*;

pub(crate) use serde::{Deserialize, Serialize};

pub use codec::*;
pub(crate) use errors::{
    ApplyCommitError, CreateCommitError, ExporterError, GroupError, WelcomeError,
};
pub use managed_group::*;
pub use mls_group::*;

#[derive(Hash, Eq, Debug, PartialEq, Clone, Serialize, Deserialize)]
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

#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub struct GroupEpoch(pub u64);

impl GroupEpoch {
    pub fn increment(&mut self) {
        self.0 += 1;
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupContext {
    group_id: GroupId,
    epoch: GroupEpoch,
    tree_hash: Vec<u8>,
    confirmed_transcript_hash: Vec<u8>,
    // The group context in serialized form for efficiency. This field is not encoded.
    serialized: Vec<u8>,
}

impl GroupContext {
    /// Create a new group context
    pub fn new(
        group_id: GroupId,
        epoch: GroupEpoch,
        tree_hash: Vec<u8>,
        confirmed_transcript_hash: Vec<u8>,
    ) -> Result<Self, CodecError> {
        let mut group_context = GroupContext {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            serialized: vec![],
        };
        let serialized = group_context.encode_detached()?;
        group_context.serialized = serialized.to_vec();
        Ok(group_context)
    }
    /// Create the `GroupContext` needed upon creation of a new group.
    pub fn create_initial_group_context(
        ciphersuite: &Ciphersuite,
        group_id: GroupId,
        tree_hash: Vec<u8>,
    ) -> Result<Self, CodecError> {
        Self::new(
            group_id,
            GroupEpoch(0),
            tree_hash,
            zero(ciphersuite.hash_length()),
        )
    }
    /// Return the serialized group context
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }
    /// Return the group ID
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }
    /// Return the epoch
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
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
    pub fn padding_block_size(&self) -> u32 {
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
