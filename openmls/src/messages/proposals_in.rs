//! # Proposals
//!
//! This module defines all the different types of Proposals.
//!
//! To find out if a specific proposal type is supported,
//! [`ProposalType::is_supported()`] can be used.

use crate::{
    ciphersuite::hash_ref::ProposalRef, credentials::CredentialWithKey, key_packages::*,
    prelude::LeafNode,
};

use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use super::proposals::{
    AppAckProposal, ExternalInitProposal, GroupContextExtensionProposal, PreSharedKeyProposal,
    ProposalType, ReInitProposal, RemoveProposal,
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
#[allow(clippy::large_enum_variant)]
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSize, TlsSerialize, TlsDeserialize,
)]
#[allow(missing_docs)]
#[repr(u16)]
pub enum ProposalIn {
    #[tls_codec(discriminant = 1)]
    Add(AddProposalIn),
    #[tls_codec(discriminant = 2)]
    Update(UpdateProposalIn),
    #[tls_codec(discriminant = 3)]
    Remove(RemoveProposal),
    #[tls_codec(discriminant = 4)]
    PreSharedKey(PreSharedKeyProposal),
    #[tls_codec(discriminant = 5)]
    ReInit(ReInitProposal),
    #[tls_codec(discriminant = 6)]
    ExternalInit(ExternalInitProposal),
    #[tls_codec(discriminant = 7)]
    GroupContextExtensions(GroupContextExtensionProposal),
    // # Extensions
    // TODO(#916): `AppAck` is not in draft-ietf-mls-protocol-17 but
    //             was moved to `draft-ietf-mls-extensions-00`.
    #[tls_codec(discriminant = 8)]
    AppAck(AppAckProposal),
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
        }
    }

    /// Indicates whether a Commit containing this [ProposalIn] requires a path.
    pub fn is_path_required(&self) -> bool {
        self.proposal_type().is_path_required()
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
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct AddProposalIn {
    key_package: KeyPackage,
}

impl AddProposalIn {
    pub(crate) fn unverified_credential(&self) -> CredentialWithKey {
        let credential = self.key_package.leaf_node().credential().clone();
        let signature_key = self.key_package.leaf_node().signature_key().clone();
        CredentialWithKey {
            credential,
            signature_key,
        }
    }
}

/// Update Proposal.
///
/// An Update proposal is a similar mechanism to [`AddProposalIn`] with the distinction that it
/// replaces the sender's [`LeafNode`] in the tree instead of adding a new leaf to the tree.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     LeafNode leaf_node;
/// } Update;
/// ```
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct UpdateProposalIn {
    leaf_node: LeafNode,
}

// Crate-only types

/// Type of Proposal, either by value or by reference.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[repr(u8)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProposalOrRefIn {
    #[tls_codec(discriminant = 1)]
    Proposal(ProposalIn),
    Reference(ProposalRef),
}

// TODO #1186: The follwoing should be removed once the validation refactoring
// is complete.

impl From<AddProposalIn> for crate::messages::proposals::AddProposal {
    fn from(value: AddProposalIn) -> Self {
        Self {
            key_package: value.key_package,
        }
    }
}

impl From<crate::messages::proposals::AddProposal> for AddProposalIn {
    fn from(value: crate::messages::proposals::AddProposal) -> Self {
        Self {
            key_package: value.key_package,
        }
    }
}

impl From<UpdateProposalIn> for crate::messages::proposals::UpdateProposal {
    fn from(value: UpdateProposalIn) -> Self {
        Self {
            leaf_node: value.leaf_node,
        }
    }
}

impl From<crate::messages::proposals::UpdateProposal> for UpdateProposalIn {
    fn from(value: crate::messages::proposals::UpdateProposal) -> Self {
        Self {
            leaf_node: value.leaf_node,
        }
    }
}

impl From<ProposalIn> for crate::messages::proposals::Proposal {
    fn from(proposal: ProposalIn) -> Self {
        match proposal {
            ProposalIn::Add(add) => Self::Add(add.into()),
            ProposalIn::Update(update) => Self::Update(update.into()),
            ProposalIn::Remove(remove) => Self::Remove(remove),
            ProposalIn::PreSharedKey(psk) => Self::PreSharedKey(psk),
            ProposalIn::ReInit(reinit) => Self::ReInit(reinit),
            ProposalIn::ExternalInit(external_init) => Self::ExternalInit(external_init),
            ProposalIn::GroupContextExtensions(group_context_extension) => {
                Self::GroupContextExtensions(group_context_extension)
            }
            ProposalIn::AppAck(app_ack) => Self::AppAck(app_ack),
        }
    }
}

impl From<crate::messages::proposals::Proposal> for ProposalIn {
    fn from(proposal: crate::messages::proposals::Proposal) -> Self {
        use crate::messages::proposals::Proposal;

        match proposal {
            Proposal::Add(add) => Self::Add(add.into()),
            Proposal::Update(update) => Self::Update(update.into()),
            Proposal::Remove(remove) => Self::Remove(remove),
            Proposal::PreSharedKey(psk) => Self::PreSharedKey(psk),
            Proposal::ReInit(reinit) => Self::ReInit(reinit),
            Proposal::ExternalInit(external_init) => Self::ExternalInit(external_init),
            Proposal::GroupContextExtensions(group_context_extension) => {
                Self::GroupContextExtensions(group_context_extension)
            }
            Proposal::AppAck(app_ack) => Self::AppAck(app_ack),
        }
    }
}

impl From<ProposalOrRefIn> for crate::messages::proposals::ProposalOrRef {
    fn from(proposal: ProposalOrRefIn) -> Self {
        match proposal {
            ProposalOrRefIn::Proposal(proposal) => Self::Proposal(proposal.into()),
            ProposalOrRefIn::Reference(reference) => Self::Reference(reference),
        }
    }
}

impl From<crate::messages::proposals::ProposalOrRef> for ProposalOrRefIn {
    fn from(proposal: crate::messages::proposals::ProposalOrRef) -> Self {
        match proposal {
            crate::messages::proposals::ProposalOrRef::Proposal(proposal) => {
                Self::Proposal(proposal.into())
            }
            crate::messages::proposals::ProposalOrRef::Reference(reference) => {
                Self::Reference(reference)
            }
        }
    }
}
