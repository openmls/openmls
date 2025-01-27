//! # Codec
//!
//! This module contains the encoding and decoding logic for Proposals.

use tls_codec::{Deserialize, DeserializeBytes, Serialize, Size};

use super::{
    proposals::{
        AppAckProposal, ExternalInitProposal, GroupContextExtensionProposal, PreSharedKeyProposal,
        Proposal, ProposalType, ReInitProposal, RemoveProposal,
    },
    proposals_in::{AddProposalIn, ProposalIn, UpdateProposalIn},
    CustomProposal,
};

impl Size for Proposal {
    fn tls_serialized_len(&self) -> usize {
        self.proposal_type().tls_serialized_len()
            + match self {
                Proposal::Add(p) => p.tls_serialized_len(),
                Proposal::Update(p) => p.tls_serialized_len(),
                Proposal::Remove(p) => p.tls_serialized_len(),
                Proposal::PreSharedKey(p) => p.tls_serialized_len(),
                Proposal::ReInit(p) => p.tls_serialized_len(),
                Proposal::ExternalInit(p) => p.tls_serialized_len(),
                Proposal::GroupContextExtensions(p) => p.tls_serialized_len(),
                Proposal::AppAck(p) => p.tls_serialized_len(),
                Proposal::SelfRemove => 0,
                Proposal::Custom(p) => p.payload().tls_serialized_len(),
            }
    }
}

impl Serialize for Proposal {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = self.proposal_type().tls_serialize(writer)?;
        match self {
            Proposal::Add(p) => p.tls_serialize(writer),
            Proposal::Update(p) => p.tls_serialize(writer),
            Proposal::Remove(p) => p.tls_serialize(writer),
            Proposal::PreSharedKey(p) => p.tls_serialize(writer),
            Proposal::ReInit(p) => p.tls_serialize(writer),
            Proposal::ExternalInit(p) => p.tls_serialize(writer),
            Proposal::GroupContextExtensions(p) => p.tls_serialize(writer),
            Proposal::AppAck(p) => p.tls_serialize(writer),
            Proposal::SelfRemove => Ok(0),
            Proposal::Custom(p) => p.payload().tls_serialize(writer),
        }
        .map(|l| written + l)
    }
}

impl Size for &ProposalIn {
    fn tls_serialized_len(&self) -> usize {
        self.proposal_type().tls_serialized_len()
            + match self {
                ProposalIn::Add(p) => p.tls_serialized_len(),
                ProposalIn::Update(p) => p.tls_serialized_len(),
                ProposalIn::Remove(p) => p.tls_serialized_len(),
                ProposalIn::PreSharedKey(p) => p.tls_serialized_len(),
                ProposalIn::ReInit(p) => p.tls_serialized_len(),
                ProposalIn::ExternalInit(p) => p.tls_serialized_len(),
                ProposalIn::GroupContextExtensions(p) => p.tls_serialized_len(),
                ProposalIn::AppAck(p) => p.tls_serialized_len(),
                ProposalIn::SelfRemove => 0,
                ProposalIn::Custom(p) => p.payload().tls_serialized_len(),
            }
    }
}

impl Size for ProposalIn {
    fn tls_serialized_len(&self) -> usize {
        (&self).tls_serialized_len()
    }
}

impl Serialize for &ProposalIn {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = self.proposal_type().tls_serialize(writer)?;
        match self {
            ProposalIn::Add(p) => p.tls_serialize(writer),
            ProposalIn::Update(p) => p.tls_serialize(writer),
            ProposalIn::Remove(p) => p.tls_serialize(writer),
            ProposalIn::PreSharedKey(p) => p.tls_serialize(writer),
            ProposalIn::ReInit(p) => p.tls_serialize(writer),
            ProposalIn::ExternalInit(p) => p.tls_serialize(writer),
            ProposalIn::GroupContextExtensions(p) => p.tls_serialize(writer),
            ProposalIn::AppAck(p) => p.tls_serialize(writer),
            ProposalIn::SelfRemove => Ok(0),
            ProposalIn::Custom(p) => p.payload().tls_serialize(writer),
        }
        .map(|l| written + l)
    }
}

impl Serialize for ProposalIn {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        (&self).tls_serialize(writer)
    }
}

impl Deserialize for ProposalIn {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let proposal_type = ProposalType::tls_deserialize(bytes)?;
        let proposal = match proposal_type {
            ProposalType::Add => ProposalIn::Add(AddProposalIn::tls_deserialize(bytes)?),
            ProposalType::Update => ProposalIn::Update(UpdateProposalIn::tls_deserialize(bytes)?),
            ProposalType::Remove => ProposalIn::Remove(RemoveProposal::tls_deserialize(bytes)?),
            ProposalType::PreSharedKey => {
                ProposalIn::PreSharedKey(PreSharedKeyProposal::tls_deserialize(bytes)?)
            }
            ProposalType::Reinit => ProposalIn::ReInit(ReInitProposal::tls_deserialize(bytes)?),
            ProposalType::ExternalInit => {
                ProposalIn::ExternalInit(ExternalInitProposal::tls_deserialize(bytes)?)
            }
            ProposalType::GroupContextExtensions => ProposalIn::GroupContextExtensions(
                GroupContextExtensionProposal::tls_deserialize(bytes)?,
            ),
            ProposalType::AppAck => ProposalIn::AppAck(AppAckProposal::tls_deserialize(bytes)?),
            ProposalType::SelfRemove => ProposalIn::SelfRemove,
            ProposalType::Custom(_) => {
                let payload = Vec::<u8>::tls_deserialize(bytes)?;
                let custom_proposal = CustomProposal::new(proposal_type.into(), payload);
                ProposalIn::Custom(custom_proposal)
            }
        };
        Ok(proposal)
    }
}

impl DeserializeBytes for ProposalIn {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let proposal = ProposalIn::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[proposal.tls_serialized_len()..];
        Ok((proposal, remainder))
    }
}
