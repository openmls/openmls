//! Codec implementations for message structs.

use super::*;

use std::convert::TryFrom;
use std::io::{Read, Write};

impl tls_codec::Size for GroupInfo {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        let payload_len = match self.payload.unsigned_payload() {
            Ok(p) => p.len(),
            Err(e) => {
                log::error!("Unable to get unsigned payload from GroupInfo {:?}", e);
                0
            }
        };
        payload_len + self.signature.tls_serialized_len()
    }
}

impl tls_codec::Serialize for GroupInfo {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let unsigned_payload = &self.payload.unsigned_payload()?;
        let written = writer.write(unsigned_payload)?;
        debug_assert_eq!(written, unsigned_payload.len());
        self.signature.tls_serialize(writer).map(|l| l + written)
    }
}

impl tls_codec::Deserialize for GroupInfo {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let payload = GroupInfoPayload::tls_deserialize(bytes)?;
        let signature = Signature::tls_deserialize(bytes)?;
        Ok(GroupInfo { payload, signature })
    }
}

impl tls_codec::Size for Proposal {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        ProposalType::Add.tls_serialized_len()
            + match self {
                Proposal::Add(add) => add.tls_serialized_len(),
                Proposal::Update(update) => update.tls_serialized_len(),
                Proposal::Remove(remove) => remove.tls_serialized_len(),
                Proposal::PreSharedKey(pre_shared_key) => pre_shared_key.tls_serialized_len(),
                Proposal::ReInit(re_init) => re_init.tls_serialized_len(),
                Proposal::ExternalInit(external_init) => external_init.tls_serialized_len(),
                Proposal::AppAck(app_ack) => app_ack.tls_serialized_len(),
                Proposal::GroupContextExtensions(group_context_extensions) => {
                    group_context_extensions.tls_serialized_len()
                }
            }
    }
}

impl tls_codec::Serialize for Proposal {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self {
            Proposal::Add(add) => {
                let written = ProposalType::Add.tls_serialize(writer)?;
                add.tls_serialize(writer).map(|l| l + written)
            }
            Proposal::Update(update) => {
                let written = ProposalType::Update.tls_serialize(writer)?;
                update.tls_serialize(writer).map(|l| l + written)
            }
            Proposal::Remove(remove) => {
                let written = ProposalType::Remove.tls_serialize(writer)?;
                remove.tls_serialize(writer).map(|l| l + written)
            }
            Proposal::PreSharedKey(presharedkey) => {
                let written = ProposalType::Presharedkey.tls_serialize(writer)?;
                presharedkey.tls_serialize(writer).map(|l| l + written)
            }
            Proposal::ReInit(reinit) => {
                let written = ProposalType::Reinit.tls_serialize(writer)?;
                reinit.tls_serialize(writer).map(|l| l + written)
            }
            Proposal::ExternalInit(external_init) => {
                let written = ProposalType::ExternalInit.tls_serialize(writer)?;
                external_init.tls_serialize(writer).map(|l| l + written)
            }
            Proposal::AppAck(app_ack) => {
                let written = ProposalType::AppAck.tls_serialize(writer)?;
                app_ack.tls_serialize(writer).map(|l| l + written)
            }
            Proposal::GroupContextExtensions(group_context_extensions) => {
                let written = ProposalType::GroupContextExtensions.tls_serialize(writer)?;
                group_context_extensions
                    .tls_serialize(writer)
                    .map(|l| l + written)
            }
        }
    }
}

impl tls_codec::Deserialize for Proposal {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let proposal_type = match ProposalType::try_from(u16::tls_deserialize(bytes)?) {
            Ok(proposal_type) => proposal_type,
            Err(e) => {
                return Err(tls_codec::Error::DecodingError(format!(
                    "Deserialization error {}",
                    e
                )))
            }
        };
        match proposal_type {
            ProposalType::Add => Ok(Proposal::Add(AddProposal::tls_deserialize(bytes)?)),
            ProposalType::Update => Ok(Proposal::Update(UpdateProposal::tls_deserialize(bytes)?)),
            ProposalType::Remove => Ok(Proposal::Remove(RemoveProposal::tls_deserialize(bytes)?)),
            ProposalType::Presharedkey => Ok(Proposal::PreSharedKey(
                PreSharedKeyProposal::tls_deserialize(bytes)?,
            )),
            ProposalType::Reinit => Ok(Proposal::ReInit(ReInitProposal::tls_deserialize(bytes)?)),
            ProposalType::ExternalInit => Ok(Proposal::ExternalInit(
                ExternalInitProposal::tls_deserialize(bytes)?,
            )),
            ProposalType::AppAck => Err(tls_codec::Error::DecodingError(
                "App ack is not supported yet in OpenMLS.".to_string(),
            )),
            ProposalType::GroupContextExtensions => Ok(Proposal::GroupContextExtensions(
                GroupContextExtensionProposal::tls_deserialize(bytes)?,
            )),
        }
    }
}
