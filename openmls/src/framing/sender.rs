//! # The sender of a message.

use super::*;
use crate::ciphersuite::hash_ref::KeyPackageRef;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// All possible sender types according to the MLS protocol spec.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// enum {
///     reserved(0),
///     member(1),
///     external(2),
///     new_member_proposal(3),
///     new_member_commit(4),
///     (255)
/// } SenderType;
///
/// // draft-ietf-mls-protocol-16
/// struct {
///     SenderType sender_type;
///     select (Sender.sender_type) {
///         case member:
///             uint32 leaf_index;
///         case external:
///             uint32 sender_index;
///         case new_member_commit:
///         case new_member_proposal:
///             struct{};
///     }
/// } Sender;
/// ```
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
        Self::Member(kpr.clone())
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
