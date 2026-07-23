//! Sub-group branching (RFC 9420 §11.3).
//!
//! Branching a sub-group off a parent group needs a small, fixed set of values
//! from the parent's current epoch. Rather than threading the live parent
//! [`MlsGroup`](crate::group::MlsGroup) through the branch APIs, the parent
//! exports these values once into a [`BranchInfo`] via
//! [`MlsGroup::branch_info`](crate::group::MlsGroup::branch_info), and hands the
//! owned struct to the sender ([`MlsGroupBuilder::branch`](crate::group::MlsGroupBuilder::branch))
//! and receiver ([`StagedWelcome::build_from_branch`](crate::group::StagedWelcome::build_from_branch)).

use crate::{
    credentials::Credential,
    group::{GroupEpoch, GroupId},
    schedule::ResumptionPskSecret,
    versions::ProtocolVersion,
};
use openmls_traits::types::Ciphersuite;

/// The information a sub-group branch needs from its parent group.
///
/// Export this from the parent group with
/// [`MlsGroup::branch_info`](crate::group::MlsGroup::branch_info) and pass it to
/// the branch APIs: the sender uses
/// [`MlsGroupBuilder::branch`](crate::group::MlsGroupBuilder::branch) and the
/// receiver uses
/// [`StagedWelcome::build_from_branch`](crate::group::StagedWelcome::build_from_branch).
///
/// This is an owned snapshot, so it does not borrow the parent group and can
/// outlive it.
///
/// This carries the parent's resumption PSK secret, which is sensitive key
/// material and must be handled accordingly.
#[derive(Debug, Clone)]
pub struct BranchInfo {
    pub(crate) version: ProtocolVersion,
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) resumption_psk_secret: ResumptionPskSecret,
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

    /// The parent group's resumption PSK secret for [`Self::epoch`].
    ///
    /// This is sensitive key material.
    pub(crate) fn resumption_psk_secret(&self) -> &ResumptionPskSecret {
        &self.resumption_psk_secret
    }

    /// The credentials of the parent group's members, used by the receiver to
    /// check that every sub-group member is also a parent-group member.
    pub(crate) fn member_credentials(&self) -> &[Credential] {
        &self.member_credentials
    }
}
