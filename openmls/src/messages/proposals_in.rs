//! # Proposals
//!
//! This module defines all the different types of Proposals.

use crate::{
    ciphersuite::{hash_ref::ProposalRef, signable::Verifiable},
    credentials::CredentialWithKey,
    framing::SenderContext,
    group::errors::ValidationError,
    key_packages::*,
    treesync::node::leaf_node::{LeafNodeIn, TreePosition, VerifiableLeafNode},
    versions::ProtocolVersion,
};

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use super::{
    proposals::{
        AddProposal, AppAckProposal, ExternalInitProposal, GroupContextExtensionProposal,
        PreSharedKeyProposal, Proposal, ProposalOrRef, ProposalType, ReInitProposal,
        RemoveProposal, UpdateProposal,
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
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
#[repr(u16)]
pub enum ProposalIn {
    Add(AddProposalIn),
    Update(UpdateProposalIn),
    Remove(RemoveProposal),
    PreSharedKey(PreSharedKeyProposal),
    ReInit(ReInitProposal),
    ExternalInit(ExternalInitProposal),
    GroupContextExtensions(GroupContextExtensionProposal),
    // # Extensions
    // TODO(#916): `AppAck` is not in draft-ietf-mls-protocol-17 but
    //             was moved to `draft-ietf-mls-extensions-00`.
    AppAck(AppAckProposal),
    // A SelfRemove proposal is an empty struct.
    SelfRemove,
    Custom(CustomProposal),
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

    /// Indicates whether a Commit containing this [ProposalIn] requires a path.
    pub fn is_path_required(&self) -> bool {
        self.proposal_type().is_path_required()
    }

    /// Returns a [`Proposal`] after successful validation.
    pub(crate) fn validate(
        self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        sender_context: Option<SenderContext>,
        protocol_version: ProtocolVersion,
    ) -> Result<Proposal, ValidationError> {
        Ok(match self {
            ProposalIn::Add(add) => {
                Proposal::Add(add.validate(crypto, protocol_version, ciphersuite)?)
            }
            ProposalIn::Update(update) => {
                let sender_context =
                    sender_context.ok_or(ValidationError::CommitterIncludedOwnUpdate)?;
                Proposal::Update(update.validate(crypto, ciphersuite, sender_context)?)
            }
            ProposalIn::Remove(remove) => Proposal::Remove(remove),
            ProposalIn::PreSharedKey(psk) => Proposal::PreSharedKey(psk),
            ProposalIn::ReInit(reinit) => Proposal::ReInit(reinit),
            ProposalIn::ExternalInit(external_init) => Proposal::ExternalInit(external_init),
            ProposalIn::GroupContextExtensions(group_context_extension) => {
                Proposal::GroupContextExtensions(group_context_extension)
            }
            ProposalIn::AppAck(app_ack) => Proposal::AppAck(app_ack),
            ProposalIn::SelfRemove => Proposal::SelfRemove,
            ProposalIn::Custom(custom) => Proposal::Custom(custom),
        })
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

impl AddProposalIn {
    pub(crate) fn unverified_credential(&self) -> CredentialWithKey {
        self.key_package.unverified_credential()
    }

    /// Returns a [`AddProposal`] after successful validation.
    pub(crate) fn validate(
        self,
        crypto: &impl OpenMlsCrypto,
        protocol_version: ProtocolVersion,
        ciphersuite: Ciphersuite,
    ) -> Result<AddProposal, ValidationError> {
        let key_package = self.key_package.validate(crypto, protocol_version)?;
        // Verify that the ciphersuite is valid
        if key_package.ciphersuite() != ciphersuite {
            return Err(ValidationError::InvalidAddProposalCiphersuite);
        }
        Ok(AddProposal { key_package })
    }
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

impl UpdateProposalIn {
    /// Returns a [`UpdateProposal`] after successful validation.
    pub(crate) fn validate(
        self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        sender_context: SenderContext,
    ) -> Result<UpdateProposal, ValidationError> {
        let leaf_node = match self.leaf_node.into_verifiable_leaf_node() {
            VerifiableLeafNode::Update(mut leaf_node) => {
                let tree_position = match sender_context {
                    SenderContext::Member((group_id, leaf_index)) => {
                        TreePosition::new(group_id, leaf_index)
                    }
                    _ => return Err(ValidationError::InvalidSenderType),
                };
                leaf_node.add_tree_position(tree_position);
                let pk = &leaf_node
                    .signature_key()
                    .clone()
                    .into_signature_public_key_enriched(ciphersuite.signature_algorithm());

                leaf_node
                    .verify(crypto, pk)
                    .map_err(|_| ValidationError::InvalidLeafNodeSignature)?
            }
            _ => return Err(ValidationError::InvalidLeafNodeSourceType),
        };

        Ok(UpdateProposal { leaf_node })
    }
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
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProposalOrRefIn {
    #[tls_codec(discriminant = 1)]
    Proposal(ProposalIn),
    Reference(ProposalRef),
}

impl ProposalOrRefIn {
    /// Returns a [`ProposalOrRef`] after successful validation.
    pub(crate) fn validate(
        self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        protocol_version: ProtocolVersion,
    ) -> Result<ProposalOrRef, ValidationError> {
        Ok(match self {
            ProposalOrRefIn::Proposal(proposal_in) => ProposalOrRef::Proposal(
                proposal_in.validate(crypto, ciphersuite, None, protocol_version)?,
            ),
            ProposalOrRefIn::Reference(reference) => ProposalOrRef::Reference(reference),
        })
    }
}

// The following `From` implementation breaks abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
#[cfg(any(feature = "test-utils", test))]
impl From<AddProposalIn> for crate::messages::proposals::AddProposal {
    fn from(value: AddProposalIn) -> Self {
        Self {
            key_package: value.key_package.into(),
        }
    }
}

impl From<crate::messages::proposals::AddProposal> for AddProposalIn {
    fn from(value: crate::messages::proposals::AddProposal) -> Self {
        Self {
            key_package: value.key_package.into(),
        }
    }
}

// The following `From` implementation( breaks abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
#[cfg(any(feature = "test-utils", test))]
impl From<UpdateProposalIn> for crate::messages::proposals::UpdateProposal {
    fn from(value: UpdateProposalIn) -> Self {
        Self {
            leaf_node: value.leaf_node.into(),
        }
    }
}

impl From<crate::messages::proposals::UpdateProposal> for UpdateProposalIn {
    fn from(value: crate::messages::proposals::UpdateProposal) -> Self {
        Self {
            leaf_node: value.leaf_node.into(),
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
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
            ProposalIn::SelfRemove => Self::SelfRemove,
            ProposalIn::Custom(other) => Self::Custom(other),
        }
    }
}

impl From<crate::messages::proposals::Proposal> for ProposalIn {
    fn from(proposal: crate::messages::proposals::Proposal) -> Self {
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
            Proposal::SelfRemove => Self::SelfRemove,
            Proposal::Custom(other) => Self::Custom(other),
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
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
