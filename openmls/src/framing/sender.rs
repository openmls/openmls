//! # The sender of a message
//!
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

use super::*;
use mls_group::create_commit_params::CommitType;
use std::convert::TryFrom;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(
    PartialEq, Clone, Copy, Debug, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
#[repr(u8)]
pub enum SenderType {
    Member = 1,
    Preconfigured = 2,
    NewMember = 3,
}

impl From<CommitType> for SenderType {
    fn from(commit_type: CommitType) -> Self {
        match commit_type {
            CommitType::External => SenderType::NewMember,
            CommitType::Internal => SenderType::Member,
        }
    }
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

#[derive(
    PartialEq, Clone, Copy, Debug, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct Sender {
    pub(crate) sender_type: SenderType,
    // TODO: #541 replace sender with [`KeyPackageRef`] (and preconfigured/new)
    pub(crate) sender: LeafIndex,
}
// Public functions
impl Sender {
    pub fn is_member(&self) -> bool {
        self.sender_type == SenderType::Member
    }
    pub fn to_leaf_index(self) -> LeafIndex {
        self.sender
    }
}
