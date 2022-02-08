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
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// All possible sender types according to the MLS protocol spec.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[repr(u8)]
pub enum SenderNew {
    /// The sender is a member of the group
    #[tls_codec(discriminant = 1)]
    Member(KeyPackageRef),
    /// The sender is not a member of the group and has a preconfigured value instead
    Preconfigured(TlsByteVecU8),
    /// The sender is a new member of the group that joins through an External Commit
    NewMember,
}

impl SenderNew {
    /// Build a [`Sender`] from [`MlsSenderData`].
    pub(crate) fn from_sender_data(sender_data: MlsSenderData) -> Self {
        Self::Member(sender_data.sender)
    }

    /// Create a member sender.
    pub(crate) fn build_member(kpr: &KeyPackageRef) -> Self {
        Self::Member(*kpr)
    }

    /// Create a new member sender.
    pub(crate) fn build_new_member() -> Self {
        Self::NewMember
    }

    /// Returns true if this [`Sender`] has [`SenderType::Member`].
    pub fn is_member(&self) -> bool {
        matches!(self, SenderNew::Member(_))
    }

    /// Returns true if this [`Sender`] has [`SenderType::NewMember`].
    pub fn is_new_member(&self) -> bool {
        matches!(self, SenderNew::NewMember)
    }
}
