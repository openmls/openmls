//! # The sender of a message.

use super::*;
use crate::ciphersuite::hash_ref::KeyPackageRef;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// All possible sender types according to the MLS protocol spec.
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[repr(u8)]
pub enum Sender {
    /// The sender is a member of the group
    #[tls_codec(discriminant = 1)]
    Member(KeyPackageRef),
    /// The sender is not a member of the group and has a preconfigured value instead
    Preconfigured(TlsByteVecU8),
    /// The sender is a new member of the group that joins through an External Commit
    NewMember,
}

impl Sender {
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
    pub(crate) fn is_member(&self) -> bool {
        matches!(self, Sender::Member(_))
    }
}
