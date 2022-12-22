//! # The sender of a message.

use crate::binary_tree::array_representation::treemath::LeafNodeIndex;

use super::*;
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
    Member(LeafNodeIndex),
    /// The sender is not a member of the group and has an external value instead
    External(TlsByteVecU8),
    /// The sender is a new member of the group that joins itself through
    /// an [External Add proposal](crate::messages::external_proposals::JoinProposal)
    NewMemberProposal,
    /// The sender is a new member of the group that joins itself through
    /// an [External Commit](crate::group::mls_group::MlsGroup::join_by_external_commit)
    NewMemberCommit,
}

impl Sender {
    /// Build a [`Sender`] from [`MlsSenderData`].
    pub(crate) fn from_sender_data(sender_data: MlsSenderData) -> Self {
        Self::Member(sender_data.leaf_index)
    }

    /// Create a member sender.
    pub(crate) fn build_member(leaf_index: LeafNodeIndex) -> Self {
        Self::Member(leaf_index)
    }

    /// Returns true if this [`Sender`] has [`SenderType::Member`].
    pub(crate) fn is_member(&self) -> bool {
        matches!(self, Sender::Member(_))
    }

    /// Returns the leaf index of the [`Sender`] or [`None`] if this
    /// is not a [`Sender::Member`].
    pub(crate) fn as_member(&self) -> Option<LeafNodeIndex> {
        match self {
            Sender::Member(leaf_index) => Some(*leaf_index),
            _ => None,
        }
    }
}
