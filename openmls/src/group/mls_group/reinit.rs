//! Reinitialization (RFC 9420 §11.2).
//!
//! Reinitializing a group needs a small, fixed set of values
//! from the old group's final epoch after committing the ReInit proposal.
//! The old group exports these values into a [`ReInitInfo`] via
//! [`MlsGroup::reinit_info`](crate::group::MlsGroup::reinit_info), which is used during group creation with
//! [`MlsGroupBuilder::reinit`](crate::group::MlsGroupBuilder::reinit) (sender) and
//! [`StagedWelcome::build_from_reinit`](crate::group::StagedWelcome::build_from_reinit) (receiver)

use crate::{
    credentials::Credential,
    group::{GroupEpoch, GroupId},
    messages::proposals::ReInitProposal,
};
use serde::{Deserialize, Serialize};

/// The information a reinit needs from its old group.
///
/// Export this from the inactive old group with
/// [`MlsGroup::reinit_info`](crate::group::MlsGroup::reinit_info) and pass it to
/// the sender API
/// [`MlsGroupBuilder::reinit`](crate::group::MlsGroupBuilder::reinit) and
/// the receiver API
/// [`StagedWelcome::build_from_reinit`](crate::group::StagedWelcome::build_from_reinit)
/// (or [`PendingResumingWelcome::build_from_reinit`](crate::group::PendingResumingWelcome::build_from_reinit)).
///
/// This contains everything except for the old group's resumption PSK secret.
/// The old group must be kept in storage for reinitialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReInitInfo {
    pub(crate) proposal: ReInitProposal,
    pub(crate) old_group_id: GroupId,
    pub(crate) old_group_epoch: GroupEpoch,
    pub(crate) member_credentials: Vec<Credential>,
}

impl ReInitInfo {
    /// The committed reinit proposal.
    pub fn proposal(&self) -> &ReInitProposal {
        &self.proposal
    }

    /// The group_id of the old group.
    pub fn old_group_id(&self) -> &GroupId {
        &self.old_group_id
    }

    /// The final epoch of the old group.
    pub fn old_group_epoch(&self) -> GroupEpoch {
        self.old_group_epoch
    }

    /// The credentials of the old group's members, used by the receiver to
    /// check that the new group has the same members.
    pub fn member_credentials(&self) -> &[Credential] {
        &self.member_credentials
    }
}
