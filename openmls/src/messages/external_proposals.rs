//! External Proposals
//!
//! Contains the types and methods to build external proposal to add/remove a client from a MLS group
//!
//! `Add` (from external sender), `Remove` & `ReInit are not yet implemented`

use crate::{
    binary_tree::LeafNodeIndex,
    framing::{mls_auth_content::AuthenticatedContent, MlsMessageOut, PublicMessage},
    group::{
        errors::ProposeRemoveMemberError, mls_group::errors::ProposeAddMemberError, GroupEpoch,
        GroupId,
    },
    key_packages::KeyPackage,
    messages::{AddProposal, Proposal},
    prelude::Sender,
};
use openmls_traits::signatures::Signer;

use super::proposals::RemoveProposal;

/// External Proposal where sender is [NewMemberProposal](crate::prelude::Sender::NewMemberProposal). A client
/// outside the group can request joining the group. This proposal should then be committed by a
/// group member. Note that this is unconstrained i.e. it works for any [MLS group](crate::group::MlsGroup).
/// This is not the case for the same external proposal with a [Preconfigured sender](crate::prelude::Sender::External)
pub struct ExternalProposal;

impl ExternalProposal {
    /// Creates an external Add proposal. For clients requesting to be added to a group. This
    /// proposal will have to be committed later by a group member.
    ///
    /// # Arguments
    /// * `key_package` - of the joiner
    /// * `group_id` - unique group identifier of the group to join
    /// * `epoch` - group's epoch
    /// * `signer` - of the sender to sign the message
    pub fn new_join(
        key_package: KeyPackage,
        group_id: GroupId,
        epoch: GroupEpoch,
        signer: &impl Signer,
    ) -> Result<MlsMessageOut, ProposeAddMemberError> {
        AuthenticatedContent::new_external_proposal(
            Proposal::Add(AddProposal { key_package }),
            group_id,
            epoch,
            signer,
            Sender::NewMemberProposal,
        )
        .map(PublicMessage::from)
        .map(MlsMessageOut::from)
        .map_err(ProposeAddMemberError::from)
    }

    /// Creates an external Remove proposal. For delivery services requesting to remove a client.
    /// This proposal will have to be committed later by a group member.
    ///
    /// # Arguments
    /// * `removed` - index of the client to remove
    /// * `group_id` - unique group identifier of the group to join
    /// * `epoch` - group's epoch
    /// * `signer` - of the sender to sign the message
    /// * `sender` - index of the sender of the proposal (in the [ExternalSendersExtension] array
    /// from the [GroupContext])
    pub fn new_remove(
        removed: LeafNodeIndex,
        group_id: GroupId,
        epoch: GroupEpoch,
        signer: &impl Signer,
        sender: u32,
    ) -> Result<MlsMessageOut, ProposeRemoveMemberError> {
        AuthenticatedContent::new_external_proposal(
            Proposal::Remove(RemoveProposal { removed }),
            group_id,
            epoch,
            signer,
            Sender::External(sender),
        )
        .map(PublicMessage::from)
        .map(MlsMessageOut::from)
        .map_err(ProposeRemoveMemberError::from)
    }
}
