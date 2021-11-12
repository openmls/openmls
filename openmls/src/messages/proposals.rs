use crate::{
    ciphersuite::*, config::ProtocolVersion, extensions::Extension, group::GroupId,
    key_packages::*, schedule::psk::*,
};

use openmls_traits::OpenMlsCryptoProvider;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use tls_codec::{
    Serialize as TlsSerializeTrait, Size, TlsByteVecU8, TlsDeserialize, TlsSerialize, TlsSize,
    TlsVecU32,
};

use super::errors::*;

#[derive(PartialEq, Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum ProposalType {
    Add = 1,
    Update = 2,
    Remove = 3,
    Presharedkey = 4,
    Reinit = 5,
}

impl TryFrom<u8> for ProposalType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ProposalType::Add),
            2 => Ok(ProposalType::Update),
            3 => Ok(ProposalType::Remove),
            4 => Ok(ProposalType::Presharedkey),
            5 => Ok(ProposalType::Reinit),
            _ => Err("Unknown proposal type."),
        }
    }
}

/// 11.2 Commit
///
/// enum {
///   reserved(0),
///   proposal(1)
///   reference(2),
///   (255)
/// } ProposalOrRefType;
///
/// struct {
///   ProposalOrRefType type;
///   select (ProposalOrRef.type) {
///     case proposal:  Proposal proposal;
///     case reference: opaque hash<0..255>;
///   }
/// } ProposalOrRef;
///
/// Type of Proposal, either by value or by reference
/// We only implement the values (1, 2), other values are not valid
/// and will yield `ProposalOrRefTypeError::UnknownValue` when decoded.
#[derive(
    PartialEq, Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize, Serialize, Deserialize,
)]
#[repr(u8)]
pub enum ProposalOrRefType {
    Proposal = 1,
    Reference = 2,
}

impl TryFrom<u8> for ProposalOrRefType {
    type Error = ProposalOrRefTypeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ProposalOrRefType::Proposal),
            2 => Ok(ProposalOrRefType::Reference),
            _ => Err(ProposalOrRefTypeError::UnknownValue),
        }
    }
}
/// Type of Proposal, either by value or by reference
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum ProposalOrRef {
    Proposal(Proposal),
    Reference(ProposalReference),
}

impl ProposalOrRef {
    pub(crate) fn proposal_or_ref_type(&self) -> ProposalOrRefType {
        match self {
            ProposalOrRef::Proposal(ref _p) => ProposalOrRefType::Proposal,
            ProposalOrRef::Reference(ref _r) => ProposalOrRefType::Reference,
        }
    }
}

/// Proposal
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Proposal {
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
    PreSharedKey(PreSharedKeyProposal),
    ReInit(ReInitProposal),
}

impl Proposal {
    pub(crate) fn proposal_type(&self) -> ProposalType {
        match self {
            Proposal::Add(ref _a) => ProposalType::Add,
            Proposal::Update(ref _u) => ProposalType::Update,
            Proposal::Remove(ref _r) => ProposalType::Remove,
            Proposal::PreSharedKey(ref _p) => ProposalType::Presharedkey,
            Proposal::ReInit(ref _r) => ProposalType::Reinit,
        }
    }
    pub(crate) fn is_type(&self, proposal_type: ProposalType) -> bool {
        self.proposal_type() == proposal_type
    }
    pub(crate) fn as_add(&self) -> Option<AddProposal> {
        match self {
            Proposal::Add(add_proposal) => Some(add_proposal.clone()),
            _ => None,
        }
    }
    pub(crate) fn as_update(&self) -> Option<UpdateProposal> {
        match self {
            Proposal::Update(update_proposal) => Some(update_proposal.clone()),
            _ => None,
        }
    }
    pub(crate) fn as_remove(&self) -> Option<RemoveProposal> {
        match self {
            Proposal::Remove(remove_proposal) => Some(remove_proposal.clone()),
            _ => None,
        }
    }
    pub(crate) fn as_presharedkey(&self) -> Option<PreSharedKeyProposal> {
        match self {
            Proposal::PreSharedKey(psk_proposal) => Some(psk_proposal.clone()),
            _ => None,
        }
    }
}

/// Reference to a Proposal. This can be used in Commit messages to reference
/// proposals that have already been sent
#[derive(
    Debug, Eq, PartialEq, Hash, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct ProposalReference {
    pub(crate) value: TlsByteVecU8,
}

impl ProposalReference {
    pub(crate) fn from_proposal(
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        proposal: &Proposal,
    ) -> Result<Self, tls_codec::Error> {
        let encoded = proposal.tls_serialize_detached()?;
        let value = ciphersuite.hash(backend, &encoded).into();
        Ok(Self { value })
    }
}

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct AddProposal {
    pub(crate) key_package: KeyPackage,
}

impl AddProposal {
    /// Get a reference to the key package in the proposal.
    pub(crate) fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }
}

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct UpdateProposal {
    pub(crate) key_package: KeyPackage,
}

impl UpdateProposal {
    /// Get a reference to the key package in the proposal.
    pub(crate) fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }
}

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct RemoveProposal {
    pub(crate) removed: u32,
}

impl RemoveProposal {
    /// Get the `u32` index in this proposal.
    pub(crate) fn removed(&self) -> u32 {
        self.removed
    }
}

/// Preshared Key proposal
/// 11.1.4
/// struct {
///     PreSharedKeyID psk;
/// } PreSharedKey;
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct PreSharedKeyProposal {
    psk: PreSharedKeyId,
}

impl PreSharedKeyProposal {
    /// Create a new PSK proposal
    pub(crate) fn new(psk: PreSharedKeyId) -> Self {
        Self { psk }
    }

    /// Get a reference to the [`PreSharedKeyId`] in this proposal.
    pub(crate) fn _psk(&self) -> &PreSharedKeyId {
        &self.psk
    }

    /// Get the [`PreSharedKeyId`] and consume this proposal.
    pub(crate) fn into_psk_id(self) -> PreSharedKeyId {
        self.psk
    }
}

/// ReInit proposal
/// 11.1.5
/// struct {
///     opaque group_id<0..255>;
///     ProtocolVersion version;
///     CipherSuite cipher_suite;
///     Extension extensions<0..2^32-1>;
/// } ReInit;
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ReInitProposal {
    pub(crate) group_id: GroupId,
    pub(crate) version: ProtocolVersion,
    pub(crate) ciphersuite: CiphersuiteName,
    pub(crate) extensions: TlsVecU32<Extension>,
}
