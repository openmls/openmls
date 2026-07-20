//! External Proposals
//!
//! Contains the types and methods to build external proposal to add/remove a client from a MLS group
//!
//! `ReInit` is not yet implemented

/// External Add Proposal where sender is [NewMemberProposal](crate::prelude::Sender::NewMemberProposal). A client
/// outside the group can request joining the group. This proposal should then be committed by a
/// group member. Note that this is unconstrained i.e. it works for any [MLS group](crate::group::MlsGroup).
/// This is not the case for the same external proposal with a [Preconfigured sender](crate::prelude::Sender::External)
pub struct JoinProposal;

/// External Proposal where sender is [External](crate::prelude::Sender::External). A party
/// outside the group can request to add or remove a member to the group. This proposal should then
/// be committed by a group member. The sender must be pre configured within the group through the [crate::extensions::ExternalSendersExtension]
pub struct ExternalProposal;
