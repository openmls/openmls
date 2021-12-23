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
//!     switch (sender_type) {
//!         case member:        KeyPackageRef member;
//!         case preconfigured: opaque external_key_id<0..255>;
//!         case new_member:    struct{};
//!     }
//! } Sender;
//! ```

use super::*;
use crate::ciphersuite::hash_ref::KeyPackageRef;
use core_group::create_commit_params::CommitType;
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
            CommitType::Member => SenderType::Member,
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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum SenderValue {
    Member(KeyPackageRef),
    Preconfigured(TlsByteVecU8),
    NewMember,
}

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct Sender {
    pub(crate) sender_type: SenderType,
    pub(crate) sender: SenderValue,
}
// Public functions
impl Sender {
    /// Build a [`Sender`] from [`MlsSenderData`].
    pub(crate) fn from_sender_data(sender_data: MlsSenderData) -> Self {
        Self {
            sender_type: SenderType::Member,
            sender: SenderValue::Member(sender_data.sender),
        }
    }

    /// Create a member sender.
    pub(crate) fn build_member(kpr: &KeyPackageRef) -> Self {
        Self {
            sender_type: SenderType::Member,
            sender: SenderValue::Member(kpr.clone()),
        }
    }

    /// Create a new member sender.
    pub(crate) fn build_new_member() -> Self {
        Self {
            sender_type: SenderType::NewMember,
            sender: SenderValue::NewMember,
        }
    }

    /// Returns true if this [`Sender`] has [`SenderType::Member`].
    pub fn is_member(&self) -> bool {
        self.sender_type == SenderType::Member
    }

    /// Returns true if this [`Sender`] has [`SenderType::NewMember`].
    pub fn is_new_member(&self) -> bool {
        self.sender_type == SenderType::NewMember
    }

    /// Get the sender a [`KeyPackageRef`].
    ///
    /// Returns a [`SenderError`] if this [`Sender`] is not a [`SenderType::Member`].
    pub fn as_key_package_ref(&self) -> Result<&KeyPackageRef, SenderError> {
        if let SenderValue::Member(ref key_package_ref) = self.sender {
            return Ok(key_package_ref);
        }
        Err(SenderError::NotAMember)
    }

    /// Get the sender a [`TlsByteVecU8`] (pre configured).
    ///
    /// Returns a [`SenderError`] if this [`Sender`] is not a [`SenderType::Preconfigured`].
    pub fn as_pre_configured(&self) -> Result<&TlsByteVecU8, SenderError> {
        if let SenderValue::Preconfigured(ref value) = self.sender {
            return Ok(value);
        }
        Err(SenderError::NotAPreConfigured)
    }
}
