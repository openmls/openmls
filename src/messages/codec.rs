//! Codec implementations for message structs.

use super::*;
use crate::key_packages::KeyPackage;

use std::convert::TryFrom;

impl Codec for GroupInfo {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.append(&mut self.unsigned_payload()?);
        self.signature.encode(buffer)?;
        Ok(())
    }
}

impl Codec for Commit {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU32, buffer, &self.proposals)?;
        self.path.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let proposals = decode_vec(VecSize::VecU32, cursor)?;
        let path = Option::<UpdatePath>::decode(cursor)?;
        Ok(Commit { proposals, path })
    }
}

impl Codec for ConfirmationTag {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let mac = Mac::decode(cursor)?;
        Ok(ConfirmationTag(mac))
    }
}

impl Codec for PathSecret {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.path_secret.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let path_secret = Secret::decode(cursor)?;
        Ok(PathSecret { path_secret })
    }
}

impl Codec for EncryptedGroupSecrets {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.key_package_hash)?;
        self.encrypted_group_secrets.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_package_hash = decode_vec(VecSize::VecU8, cursor)?;
        let encrypted_group_secrets = HpkeCiphertext::decode(cursor)?;
        Ok(EncryptedGroupSecrets {
            key_package_hash,
            encrypted_group_secrets,
        })
    }
}

impl Codec for Welcome {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.version.encode(buffer)?;
        self.cipher_suite.name().encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.secrets)?;
        encode_vec(VecSize::VecU32, buffer, &self.encrypted_group_info)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let version = ProtocolVersion::decode(cursor)?;
        let cipher_suite = CiphersuiteName::decode(cursor)?;
        let secrets = decode_vec(VecSize::VecU32, cursor)?;
        let encrypted_group_info = decode_vec(VecSize::VecU32, cursor)?;
        Ok(Welcome {
            version,
            cipher_suite: Config::ciphersuite(cipher_suite)?,
            secrets,
            encrypted_group_info,
        })
    }
}

impl Codec for GroupSecrets {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.joiner_secret.encode(buffer)?;
        self.path_secret.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let joiner_secret = JoinerSecret::decode(cursor)?;
        let path_secret = Option::<PathSecret>::decode(cursor)?;
        Ok(GroupSecrets::new(joiner_secret, path_secret))
    }
}

// === Proposals ===

impl Codec for ProposalType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
}

impl Codec for ProposalOrRefType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
}

impl Codec for ProposalOrRef {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.proposal_or_ref_type().encode(buffer)?;
        match self {
            ProposalOrRef::Proposal(proposal) => {
                proposal.encode(buffer)?;
            }
            ProposalOrRef::Reference(reference) => {
                reference.encode(buffer)?;
            }
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        match ProposalOrRefType::try_from(u8::decode(cursor)?)? {
            ProposalOrRefType::Proposal => Ok(ProposalOrRef::Proposal(Proposal::decode(cursor)?)),
            ProposalOrRefType::Reference => {
                Ok(ProposalOrRef::Reference(ProposalReference::decode(cursor)?))
            }
        }
    }
}

impl Codec for Proposal {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Proposal::Add(add) => {
                ProposalType::Add.encode(buffer)?;
                add.encode(buffer)?;
            }
            Proposal::Update(update) => {
                ProposalType::Update.encode(buffer)?;
                update.encode(buffer)?;
            }
            Proposal::Remove(remove) => {
                ProposalType::Remove.encode(buffer)?;
                remove.encode(buffer)?;
            }
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let proposal_type = match ProposalType::try_from(u8::decode(cursor)?) {
            Ok(proposal_type) => proposal_type,
            Err(_) => return Err(CodecError::DecodingError),
        };
        match proposal_type {
            ProposalType::Add => Ok(Proposal::Add(AddProposal::decode(cursor)?)),
            ProposalType::Update => Ok(Proposal::Update(UpdateProposal::decode(cursor)?)),
            ProposalType::Remove => Ok(Proposal::Remove(RemoveProposal::decode(cursor)?)),
        }
    }
}

impl Codec for ProposalReference {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.value)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = decode_vec(VecSize::VecU8, cursor)?;
        Ok(ProposalReference { value })
    }
}

impl Codec for AddProposal {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.key_package.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_package = KeyPackage::decode(cursor)?;
        Ok(AddProposal { key_package })
    }
}

impl Codec for UpdateProposal {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.key_package.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_package = KeyPackage::decode(cursor)?;
        Ok(UpdateProposal { key_package })
    }
}

impl Codec for RemoveProposal {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.removed.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let removed = u32::decode(cursor)?;
        Ok(RemoveProposal { removed })
    }
}
