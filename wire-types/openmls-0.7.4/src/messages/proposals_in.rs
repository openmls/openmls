//! # Proposals
//!
//! This module defines all the different types of Proposals.

use crate::{
    ciphersuite::hash_ref::ProposalRef, key_packages::*, treesync::node::leaf_node::LeafNodeIn,
};

use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use super::{
    proposals::{
        AppAckProposal, ExternalInitProposal, GroupContextExtensionProposal, PreSharedKeyProposal,
        ProposalType, ReInitProposal, RemoveProposal,
    },
    CustomProposal,
};

/// Proposal.
///
/// This `enum` contains the different proposals in its variants.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     ProposalType msg_type;
///     select (Proposal.msg_type) {
///         case add:                      Add;
///         case update:                   Update;
///         case remove:                   Remove;
///         case psk:                      PreSharedKey;
///         case reinit:                   ReInit;
///         case external_init:            ExternalInit;
///         case group_context_extensions: GroupContextExtensions;
///     };
/// } Proposal;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
#[repr(u16)]
pub enum ProposalIn {
    Add(Box<AddProposalIn>),
    Update(Box<UpdateProposalIn>),
    Remove(Box<RemoveProposal>),
    PreSharedKey(Box<PreSharedKeyProposal>),
    ReInit(Box<ReInitProposal>),
    ExternalInit(Box<ExternalInitProposal>),
    GroupContextExtensions(Box<GroupContextExtensionProposal>),
    // # Extensions
    // TODO(#916): `AppAck` is not in draft-ietf-mls-protocol-17 but
    //             was moved to `draft-ietf-mls-extensions-00`.
    AppAck(Box<AppAckProposal>),
    // A SelfRemove proposal is an empty struct.
    SelfRemove,
    Custom(Box<CustomProposal>),
}

impl ProposalIn {
    /// Returns the proposal type.
    pub fn proposal_type(&self) -> ProposalType {
        match self {
            ProposalIn::Add(_) => ProposalType::Add,
            ProposalIn::Update(_) => ProposalType::Update,
            ProposalIn::Remove(_) => ProposalType::Remove,
            ProposalIn::PreSharedKey(_) => ProposalType::PreSharedKey,
            ProposalIn::ReInit(_) => ProposalType::Reinit,
            ProposalIn::ExternalInit(_) => ProposalType::ExternalInit,
            ProposalIn::GroupContextExtensions(_) => ProposalType::GroupContextExtensions,
            ProposalIn::AppAck(_) => ProposalType::AppAck,
            ProposalIn::SelfRemove => ProposalType::SelfRemove,
            ProposalIn::Custom(custom_proposal) => {
                ProposalType::Custom(custom_proposal.proposal_type())
            }
        }
    }
}

/// Add Proposal.
///
/// An Add proposal requests that a client with a specified [`KeyPackage`] be added to the group.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     KeyPackage key_package;
/// } Add;
/// ```
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct AddProposalIn {
    key_package: KeyPackageIn,
}

/// Update Proposal.
///
/// An Update proposal is a similar mechanism to [`AddProposalIn`] with the distinction that it
/// replaces the sender's leaf node instead of adding a new leaf to the tree.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     LeafNode leaf_node;
/// } Update;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct UpdateProposalIn {
    leaf_node: LeafNodeIn,
}

// Crate-only types

/// Type of Proposal, either by value or by reference.
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
#[repr(u8)]
#[allow(missing_docs)]
pub(crate) enum ProposalOrRefIn {
    #[tls_codec(discriminant = 1)]
    Proposal(Box<ProposalIn>),
    Reference(Box<ProposalRef>),
}
