//! Sub-group branching (RFC 9420 §11.3).
//!
//! Branching a sub-group off a parent group needs a small set of values
//! from the parent's current epoch. The parent group exports metadata into a [`BranchInfo`] via
//! [`MlsGroup::branch_info`](crate::group::MlsGroup::branch_info), which is used
//! at the sender ([`MlsGroupBuilder::branch`](crate::group::MlsGroupBuilder::branch))
//! and receiver ([`StagedWelcome::build_from_branch`](crate::group::StagedWelcome::build_from_branch))
//! to initialize the new group. The resumption PSK secret is loaded from storage instead.

use crate::{
    credentials::Credential,
    group::{GroupEpoch, GroupId},
    versions::ProtocolVersion,
};
use openmls_traits::types::Ciphersuite;

/// The metadata a sub-group branch needs from its parent group.
///
/// Export this from the parent group with
/// [`MlsGroup::branch_info`](crate::group::MlsGroup::branch_info) and pass it to
/// the subgroup branch APIs: the sender uses
/// [`MlsGroupBuilder::branch`](crate::group::MlsGroupBuilder::branch) and the
/// receiver uses
/// [`StagedWelcome::build_from_branch`](crate::group::StagedWelcome::build_from_branch).
/// This carries everything except for the resumption PSK secret.
#[derive(Debug, Clone)]
pub struct BranchInfo {
    pub(crate) version: ProtocolVersion,
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) member_credentials: Vec<Credential>,
}

impl BranchInfo {
    /// The protocol version of the parent group.
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// The ciphersuite of the parent group.
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }

    /// The group ID of the parent group.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// The epoch of the parent group from which this branch is taken.
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// The credentials of the parent group's members, used by the receiver to
    /// check that every sub-group member is also a parent-group member.
    pub fn member_credentials(&self) -> &[Credential] {
        &self.member_credentials
    }
}
