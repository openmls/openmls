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
use std::convert::TryFrom;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use super::proposals::{
    AppAckProposal, ExternalInitProposal, GroupContextExtensionProposal, PreSharedKeyProposal,
    ReInitProposal, RemoveProposal,
};

// Public types

/// ## MLS Proposal Types
///
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// // See IANA registry for registered values
/// uint16 ProposalType;
/// ```
///
/// | Value           | Name                     | Recommended | Path Required | Reference |
/// |:================|:=========================|:============|:==============|:==========|
/// | 0x0000          | RESERVED                 | N/A         | N/A           | RFC XXXX  |
/// | 0x0001          | add                      | Y           | N             | RFC XXXX  |
/// | 0x0002          | update                   | Y           | Y             | RFC XXXX  |
/// | 0x0003          | remove                   | Y           | Y             | RFC XXXX  |
/// | 0x0004          | psk                      | Y           | N             | RFC XXXX  |
/// | 0x0005          | reinit                   | Y           | N             | RFC XXXX  |
/// | 0x0006          | external_init            | Y           | Y             | RFC XXXX  |
/// | 0x0007          | group_context_extensions | Y           | Y             | RFC XXXX  |
/// | 0xf000 - 0xffff | Reserved for Private Use | N/A         | N/A           | RFC XXXX  |
///
/// # Extensions
///
/// | Value  | Name    | Recommended | Path Required | Reference | Notes                        |
/// |:=======|:========|:============|:==============|:==========|:=============================|
/// | 0x0008 | app_ack | Y           | Y             | RFC XXXX  | draft-ietf-mls-extensions-00 |
#[derive(
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Debug,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
    Serialize,
    Deserialize,
)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum ProposalType {
    Add = 1,
    Update = 2,
    Remove = 3,
    Presharedkey = 4,
    Reinit = 5,
    ExternalInit = 6,
    GroupContextExtensions = 7,
    AppAck = 8,
}

impl ProposalType {
    /// Check whether a proposal type is supported or not. Returns `true`
    /// if a proposal is supported and `false` otherwise.
    pub fn is_supported(&self) -> bool {
        match self {
            ProposalType::Add
            | ProposalType::Update
            | ProposalType::Remove
            | ProposalType::Presharedkey
            | ProposalType::Reinit
            | ProposalType::ExternalInit
            | ProposalType::GroupContextExtensions => true,
            ProposalType::AppAck => false,
        }
    }
}

impl TryFrom<u16> for ProposalType {
    type Error = &'static str;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ProposalType::Add),
            2 => Ok(ProposalType::Update),
            3 => Ok(ProposalType::Remove),
            4 => Ok(ProposalType::Presharedkey),
            5 => Ok(ProposalType::Reinit),
            6 => Ok(ProposalType::ExternalInit),
            7 => Ok(ProposalType::GroupContextExtensions),
            8 => Ok(ProposalType::AppAck),
            _ => Err("Unknown proposal type."),
        }
    }
}

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
    /// Indicates whether a Commit containing this [ProposalIn] requires a path.
    pub fn is_path_required(&self) -> bool {
        match self {
            Self::Add(_)
            | Self::PreSharedKey(_)
            | Self::ReInit(_)
            | Self::AppAck(_)
            | Self::GroupContextExtensions(_) => false,
            Self::Update(_) | Self::Remove(_) | Self::ExternalInit(_) => true,
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
