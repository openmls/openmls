//! Group APIs for MLS
//!
//! This file contains the API to interact with groups.
//!
//! The low-level standard API is described in the `Api` trait.\
//! The high-level API is exposed in `ManagedGroup`.

mod codec;
pub mod errors;
mod group_context;
mod managed_group;
mod mls_group;

#[cfg(any(feature = "expose-test-vectors", test))]
pub mod tests;

use crate::ciphersuite::*;
use crate::codec::*;
use crate::extensions::*;
use crate::utils::*;

pub(crate) use serde::{Deserialize, Serialize};

pub use codec::*;
pub use errors::{ApplyCommitError, CreateCommitError, ExporterError, MlsGroupError, WelcomeError};
pub use group_context::*;
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
    pub fn as_slice(&self) -> &[u8] {
        &self.value
    }
    pub fn to_vec(&self) -> Vec<u8> {
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
    extensions: Vec<Box<dyn Extension>>,
    // The group context in serialized form for efficiency. This field is not encoded.
    serialized: Vec<u8>,
}

#[cfg(any(feature = "expose-test-vectors", test))]
impl GroupContext {
    pub(crate) fn set_epoch(&mut self, epoch: GroupEpoch) {
        self.epoch = epoch;
    }
}

/// Configuration for an MLS group.
#[derive(Clone, Copy, Debug)]
pub struct MlsGroupConfig {
    /// Flag whether to send the ratchet tree along with the `GroupInfo` or not.
    /// Defaults to false.
    pub add_ratchet_tree_extension: bool,
    pub padding_block_size: u32,
    pub additional_as_epochs: u32,
}

impl MlsGroupConfig {
    /// Get the padding block size used in this config.
    pub fn padding_block_size(&self) -> u32 {
        self.padding_block_size
    }
}

impl Default for MlsGroupConfig {
    fn default() -> Self {
        Self {
            add_ratchet_tree_extension: false,
            padding_block_size: 10,
            additional_as_epochs: 0,
        }
    }
}
