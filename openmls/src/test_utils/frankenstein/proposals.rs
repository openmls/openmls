use tls_codec::*;

use super::{extensions::FrankenExtension, FrankenKeyPackage, FrankenLeafNode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrankenProposalType {
    Add,
    Update,
    Remove,
    PreSharedKey,
    Reinit,
    ExternalInit,
    GroupContextExtensions,
    AppAck,
    Custom(u16),
}

impl From<u16> for FrankenProposalType {
    fn from(value: u16) -> Self {
        match value {
            1 => FrankenProposalType::Add,
            2 => FrankenProposalType::Update,
            3 => FrankenProposalType::Remove,
            4 => FrankenProposalType::PreSharedKey,
            5 => FrankenProposalType::Reinit,
            6 => FrankenProposalType::ExternalInit,
            7 => FrankenProposalType::GroupContextExtensions,
            8 => FrankenProposalType::AppAck,
            other => FrankenProposalType::Custom(other),
        }
    }
}

impl From<FrankenProposalType> for u16 {
    fn from(value: FrankenProposalType) -> Self {
        match value {
            FrankenProposalType::Add => 1,
            FrankenProposalType::Update => 2,
            FrankenProposalType::Remove => 3,
            FrankenProposalType::PreSharedKey => 4,
            FrankenProposalType::Reinit => 5,
            FrankenProposalType::ExternalInit => 6,
            FrankenProposalType::GroupContextExtensions => 7,
            FrankenProposalType::AppAck => 8,
            FrankenProposalType::Custom(id) => id,
        }
    }
}

impl FrankenProposal {
    pub fn proposal_type(&self) -> FrankenProposalType {
        match self {
            FrankenProposal::Add(_) => FrankenProposalType::Add,
            FrankenProposal::Update(_) => FrankenProposalType::Update,
            FrankenProposal::Remove(_) => FrankenProposalType::Remove,
            FrankenProposal::PreSharedKey(_) => FrankenProposalType::PreSharedKey,
            FrankenProposal::ReInit(_) => FrankenProposalType::Reinit,
            FrankenProposal::ExternalInit(_) => FrankenProposalType::ExternalInit,
            FrankenProposal::GroupContextExtensions(_) => {
                FrankenProposalType::GroupContextExtensions
            }
            FrankenProposal::AppAck(_) => FrankenProposalType::AppAck,
            FrankenProposal::Custom(FrankenCustomProposal {
                proposal_type,
                payload: _,
            }) => FrankenProposalType::Custom(proposal_type.to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum FrankenProposal {
    Add(FrankenAddProposal),
    Update(FrankenUpdateProposal),
    Remove(FrankenRemoveProposal),
    PreSharedKey(FrankenPreSharedKeyProposal),
    ReInit(FrankenReInitProposal),
    ExternalInit(FrankenExternalInitProposal),
    GroupContextExtensions(Vec<FrankenExtension>),
    AppAck(FrankenAppAckProposal),
    Custom(FrankenCustomProposal),
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenAddProposal {
    pub key_package: FrankenKeyPackage,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenUpdateProposal {
    pub leaf_node: FrankenLeafNode,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenRemoveProposal {
    pub removed: u32,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenPreSharedKeyProposal {
    pub psk: FrankenPreSharedKeyId,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenPreSharedKeyId {
    pub psk: FrankenPsk,
    pub psk_nonce: VLBytes,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
#[repr(u8)]
pub enum FrankenPsk {
    #[tls_codec(discriminant = 1)]
    External(FrankenExternalPsk),
    #[tls_codec(discriminant = 2)]
    Resumption(FrankenResumptionPsk),
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenExternalPsk {
    pub psk_id: VLBytes,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenResumptionPsk {
    pub usage: FrankenResumptionPskUsage,
    pub psk_group_id: VLBytes,
    pub psk_epoch: u64,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
#[repr(u8)]
pub enum FrankenResumptionPskUsage {
    Application = 1,
    Reinit = 2,
    Branch = 3,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenReInitProposal {
    pub group_id: VLBytes,
    pub version: u16,
    pub ciphersuite: u16,
    pub extensions: Vec<FrankenExtension>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenExternalInitProposal {
    pub kem_output: VLBytes,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenAppAckProposal {
    pub received_ranges: Vec<FrankenMessageRange>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenMessageRange {
    pub sender: VLBytes,
    pub first_generation: u32,
    pub last_generation: u32,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenCustomProposal {
    pub proposal_type: u16,
    pub payload: VLBytes,
}
