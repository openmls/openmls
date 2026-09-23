//! Reinitialization (RFC 9420 §11.2).
//!
//! Reinitializing a group needs a small, fixed set of values
//! from the old group's final epoch after committing the ReInit proposal.
//! The old group exports these values into a [`ReInitInfo`] via
//! [`MlsGroup::reinit_info`](crate::group::MlsGroup::reinit_info), and hands the
//! owned struct to the receiver
//! ([`StagedWelcome::build_from_reinit`](crate::group::StagedWelcome::build_from_reinit)),
//! so the old group is no longer required to join the new group.

use crate::{
    credentials::Credential,
    group::{GroupEpoch, GroupId},
    messages::proposals::ReInitProposal,
    schedule::ResumptionPskSecret,
};
use serde::{Deserialize, Serialize};

/// The information a reinit needs from its old group.
///
/// Export this from the inactive old group with
/// [`MlsGroup::reinit_info`](crate::group::MlsGroup::reinit_info) and pass it to
/// the receiver API
/// [`StagedWelcome::build_from_reinit`](crate::group::StagedWelcome::build_from_reinit)
/// (or [`PendingPskWelcome::build_from_reinit`](crate::group::PendingPskWelcome::build_from_reinit)).
///
/// This is an owned snapshot, so it does not borrow the old group and can
/// outlive it.
///
/// This carries the resumption PSK secret, which is sensitive key
/// material and must be handled accordingly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReInitInfo {
    pub(crate) proposal: ReInitProposal,
    pub(crate) old_group_id: GroupId,
    pub(crate) old_group_epoch: GroupEpoch,
    pub(crate) resumption_psk_secret: ResumptionPskSecret,
    pub(crate) member_credentials: Vec<Credential>,
}

impl ReInitInfo {
    /// The committed reinit proposal.
    pub(crate) fn proposal(&self) -> &ReInitProposal {
        &self.proposal
    }

    /// The group_id of the old group.
    pub(crate) fn old_group_id(&self) -> &GroupId {
        &self.old_group_id
    }

    /// The final epoch of the old group.
    pub(crate) fn old_group_epoch(&self) -> GroupEpoch {
        self.old_group_epoch
    }

    /// The old group's resumption PSK secret for [`Self::old_group_epoch`].
    ///
    /// This is sensitive key material.
    pub(crate) fn resumption_psk_secret(&self) -> &ResumptionPskSecret {
        &self.resumption_psk_secret
    }

    /// The credentials of the old group's members, used by the receiver to
    /// check that the new group has the same members.
    pub fn member_credentials(&self) -> &[Credential] {
        &self.member_credentials
    }
}
