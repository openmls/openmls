//! External Proposals
//!
//! Contains the types and methods to build external proposal to add/remove a client from a MLS group
//!
//! `Add` (from external sender), `Remove` & `ReInit are not yet implemented`

use crate::{
    credentials::CredentialBundle,
    framing::{mls_auth_content::MlsAuthContent, MlsMessageOut, MlsPlaintext},
    group::{mls_group::errors::ProposeAddMemberError, GroupEpoch, GroupId},
    key_packages::KeyPackage,
    messages::{AddProposal, Proposal},
};
use openmls_traits::OpenMlsCryptoProvider;

/// External Add Proposal where sender is [NewMemberProposal](crate::prelude::Sender::NewMemberProposal). A client
/// outside the group can request joining the group. This proposal should then be committed by a
/// group member. Note that this is unconstrained i.e. it works for any [MLS group](crate::group::MlsGroup).
/// This is not the case for the same external proposal with a [Preconfigured sender](crate::prelude::Sender::External)
pub struct JoinProposal;

impl JoinProposal {
    /// Creates an external Add proposal. For clients requesting to be added to a group. This
    /// proposal will have to be committed later by a group member.
    ///
    /// # Arguments
    /// * `key_package` - of the joiner
    /// * `group_id` - unique group identifier of the group to join
    /// * `epoch` - group's epoch
    /// * `credential` - of the sender to sign the message
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        key_package: KeyPackage,
        group_id: GroupId,
        epoch: GroupEpoch,
        credential: &CredentialBundle,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsMessageOut, ProposeAddMemberError> {
        MlsAuthContent::new_external_proposal(
            Proposal::Add(AddProposal { key_package }),
            credential,
            group_id,
            epoch,
            backend,
        )
        .map(MlsPlaintext::from)
        .map(MlsMessageOut::from)
        .map_err(ProposeAddMemberError::from)
    }
}
