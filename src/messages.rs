// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::ciphersuite::*;
use crate::codec::*;
use crate::creds::*;
use crate::extensions::*;
use crate::framing::*;
use crate::group::*;
use crate::kp::*;
use crate::tree::*;
use std::collections::HashMap;
use std::convert::From;
use std::fmt;

#[derive(Debug)]
pub enum MessageError {
    UnknownOperation,
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub struct NodeIndex(u32);

impl NodeIndex {
    pub fn as_u32(self) -> u32 {
        self.0
    }
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl From<u32> for NodeIndex {
    fn from(i: u32) -> NodeIndex {
        NodeIndex(i)
    }
}

impl From<usize> for NodeIndex {
    fn from(i: usize) -> NodeIndex {
        NodeIndex(i as u32)
    }
}

impl From<LeafIndex> for NodeIndex {
    fn from(roster_index: LeafIndex) -> NodeIndex {
        NodeIndex(roster_index.as_u32() * 2)
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub struct LeafIndex(u32);

impl LeafIndex {
    pub fn as_u32(self) -> u32 {
        self.0
    }
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl From<u32> for LeafIndex {
    fn from(i: u32) -> LeafIndex {
        LeafIndex(i)
    }
}

impl From<usize> for LeafIndex {
    fn from(i: usize) -> LeafIndex {
        LeafIndex(i as u32)
    }
}

impl From<NodeIndex> for LeafIndex {
    fn from(tree_index: NodeIndex) -> LeafIndex {
        LeafIndex((tree_index.as_u32() + 1) / 2)
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum ProposalType {
    Invalid = 0,
    Add = 1,
    Update = 2,
    Remove = 3,
    Default = 255,
}

impl From<u8> for ProposalType {
    fn from(value: u8) -> Self {
        match value {
            0 => ProposalType::Invalid,
            1 => ProposalType::Add,
            2 => ProposalType::Update,
            3 => ProposalType::Remove,
            _ => ProposalType::Default,
        }
    }
}

impl Codec for ProposalType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(ProposalType::from(u8::decode(cursor)?))
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone)]
pub enum Proposal {
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
}

impl Proposal {
    pub fn to_proposal_id(&self, ciphersuite: Ciphersuite) -> ProposalID {
        ProposalID::from_proposal(ciphersuite, self)
    }
    pub fn as_add(&self) -> Option<AddProposal> {
        match self {
            Proposal::Add(add_proposal) => Some(add_proposal.clone()),
            _ => None,
        }
    }
    pub fn as_update(&self) -> Option<UpdateProposal> {
        match self {
            Proposal::Update(update_proposal) => Some(update_proposal.clone()),
            _ => None,
        }
    }
    pub fn as_remove(&self) -> Option<RemoveProposal> {
        match self {
            Proposal::Remove(remove_proposal) => Some(remove_proposal.clone()),
            _ => None,
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
        let proposal_type = ProposalType::from(u8::decode(cursor)?);
        match proposal_type {
            ProposalType::Add => Ok(Proposal::Add(AddProposal::decode(cursor)?)),
            ProposalType::Update => Ok(Proposal::Update(UpdateProposal::decode(cursor)?)),
            ProposalType::Remove => Ok(Proposal::Remove(RemoveProposal::decode(cursor)?)),
            _ => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ProposalID {
    value: Vec<u8>,
}

impl ProposalID {
    pub fn from_proposal(ciphersuite: Ciphersuite, proposal: &Proposal) -> Self {
        let encoded = proposal.encode_detached().unwrap();
        let value = ciphersuite.hash(&encoded);
        Self { value }
    }
}

impl Codec for ProposalID {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.value)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = decode_vec(VecSize::VecU8, cursor)?;
        Ok(ProposalID { value })
    }
}

#[derive(Eq, PartialEq, Hash, Copy, Clone)]
pub struct ShortProposalID([u8; 32]);

impl ShortProposalID {
    pub fn from_proposal_id(proposal_id: &ProposalID) -> ShortProposalID {
        let mut inner = [0u8; 32];
        inner.copy_from_slice(&proposal_id.value[..32]);
        ShortProposalID(inner)
    }
}

impl Codec for ShortProposalID {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.0)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = decode_vec(VecSize::VecU8, cursor)?;
        let mut inner = [0u8; 32];
        inner.copy_from_slice(&value[..32]);
        Ok(ShortProposalID(inner))
    }
}

#[derive(Clone)]
pub struct QueuedProposal {
    pub proposal: Proposal,
    pub sender: Sender,
    pub own_kpb: Option<KeyPackageBundle>,
}

impl QueuedProposal {
    pub fn new(proposal: Proposal, sender: LeafIndex, own_kpb: Option<KeyPackageBundle>) -> Self {
        Self {
            proposal,
            sender: Sender::member(sender),
            own_kpb,
        }
    }
}

impl Codec for QueuedProposal {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.proposal.encode(buffer)?;
        self.sender.encode(buffer)?;
        self.own_kpb.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let proposal = Proposal::decode(cursor)?;
        let sender = Sender::decode(cursor)?;
        let own_kpb = Option::<KeyPackageBundle>::decode(cursor)?;
        Ok(QueuedProposal {
            proposal,
            sender,
            own_kpb,
        })
    }
}

#[derive(Clone)]
pub struct ProposalQueue {
    ciphersuite: Ciphersuite,
    tuples: HashMap<ShortProposalID, (ProposalID, QueuedProposal)>,
}

impl ProposalQueue {
    pub fn new(ciphersuite: Ciphersuite) -> Self {
        ProposalQueue {
            ciphersuite,
            tuples: HashMap::new(),
        }
    }
    pub fn add(&mut self, queued_proposal: QueuedProposal) {
        let pi = ProposalID::from_proposal(self.ciphersuite, &queued_proposal.proposal);
        let spi = ShortProposalID::from_proposal_id(&pi);
        self.tuples.entry(spi).or_insert((pi, queued_proposal));
    }
    pub fn get(&self, proposal_id: &ProposalID) -> Option<&(ProposalID, QueuedProposal)> {
        let spi = ShortProposalID::from_proposal_id(&proposal_id);
        self.tuples.get(&spi)
    }
    pub fn get_commit_lists(&self) -> ProposalIDList {
        let mut updates = vec![];
        let mut removes = vec![];
        let mut adds = vec![];
        for (_spi, p) in self.tuples.values() {
            match p.proposal {
                Proposal::Update(_) => updates.push(p.proposal.to_proposal_id(self.ciphersuite)),
                Proposal::Remove(_) => removes.push(p.proposal.to_proposal_id(self.ciphersuite)),
                Proposal::Add(_) => adds.push(p.proposal.to_proposal_id(self.ciphersuite)),
            }
        }
        ProposalIDList {
            updates,
            removes,
            adds,
        }
    }
}

impl Codec for ProposalQueue {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.ciphersuite.encode(buffer)?;
        self.tuples.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let ciphersuite = Ciphersuite::decode(cursor)?;
        let tuples = HashMap::<ShortProposalID, (ProposalID, QueuedProposal)>::decode(cursor)?;
        Ok(ProposalQueue {
            ciphersuite,
            tuples,
        })
    }
}

#[derive(Clone)]
pub struct ProposalIDList {
    pub updates: Vec<ProposalID>,
    pub removes: Vec<ProposalID>,
    pub adds: Vec<ProposalID>,
}
pub struct MembershipChanges {
    pub updates: Vec<Credential>,
    pub removes: Vec<Credential>,
    pub adds: Vec<Credential>,
}

impl MembershipChanges {
    pub fn path_required(&self) -> bool {
        !self.updates.is_empty() || !self.removes.is_empty() || self.adds.is_empty()
    }
}

impl fmt::Debug for MembershipChanges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn list_members(f: &mut fmt::Formatter<'_>, members: &[Credential]) -> fmt::Result {
            for m in members {
                let Credential::Basic(bc) = m;
                write!(f, "{} ", String::from_utf8(bc.identity.clone()).unwrap())?;
            }
            Ok(())
        }
        write!(f, "Membership changes:")?;
        write!(f, "\n\tUpdates: ")?;
        list_members(f, &self.updates)?;
        write!(f, "\n\tRemoves: ")?;
        list_members(f, &self.removes)?;
        write!(f, "\n\tAdds: ")?;
        list_members(f, &self.adds)?;
        writeln!(f)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Commit {
    pub updates: Vec<ProposalID>,
    pub removes: Vec<ProposalID>,
    pub adds: Vec<ProposalID>,
    pub path: Option<DirectPath>,
}

impl Codec for Commit {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU32, buffer, &self.updates)?;
        encode_vec(VecSize::VecU32, buffer, &self.removes)?;
        encode_vec(VecSize::VecU32, buffer, &self.adds)?;
        self.path.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let updates = decode_vec(VecSize::VecU32, cursor)?;
        let removes = decode_vec(VecSize::VecU32, cursor)?;
        let adds = decode_vec(VecSize::VecU32, cursor)?;
        let path = Option::<DirectPath>::decode(cursor)?;
        Ok(Commit {
            updates,
            removes,
            adds,
            path,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Confirmation(pub Vec<u8>);

impl Confirmation {
    pub fn new(
        ciphersuite: Ciphersuite,
        confirmation_key: &[u8],
        confirmed_transcript_hash: &[u8],
    ) -> Self {
        Confirmation(ciphersuite.hmac(confirmation_key, confirmed_transcript_hash))
    }
    pub fn new_empty() -> Self {
        Confirmation(vec![])
    }
}

impl Codec for Confirmation {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.0)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let inner = decode_vec(VecSize::VecU8, cursor)?;
        Ok(Confirmation(inner))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct CommitSecret(pub Vec<u8>);

impl Codec for CommitSecret {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.0)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let inner = decode_vec(VecSize::VecU8, cursor)?;
        Ok(CommitSecret(inner))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct AddProposal {
    pub key_package: KeyPackage,
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

#[derive(Debug, PartialEq, Clone)]
pub struct UpdateProposal {
    pub key_package: KeyPackage,
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

#[derive(Debug, PartialEq, Clone)]
pub struct RemoveProposal {
    pub removed: u32,
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

pub struct GroupInfo {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: Vec<u8>,
    pub interim_transcript_hash: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub confirmation: Vec<u8>,
    pub signer_index: LeafIndex,
    pub signature: Signature,
}

impl Codec for GroupInfo {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.append(&mut self.unsigned_payload()?);
        self.signature.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let tree_hash = decode_vec(VecSize::VecU8, cursor)?;
        let confirmed_transcript_hash = decode_vec(VecSize::VecU8, cursor)?;
        let interim_transcript_hash = decode_vec(VecSize::VecU8, cursor)?;
        let extensions = decode_vec(VecSize::VecU16, cursor)?;
        let confirmation = decode_vec(VecSize::VecU8, cursor)?;
        let signer_index = LeafIndex::from(u32::decode(cursor)?);
        let signature = Signature::decode(cursor)?;
        Ok(GroupInfo {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            interim_transcript_hash,
            extensions,
            confirmation,
            signer_index,
            signature,
        })
    }
}

impl Signable for GroupInfo {
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        let buffer = &mut vec![];
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.tree_hash)?;
        encode_vec(VecSize::VecU8, buffer, &self.confirmed_transcript_hash)?;
        encode_vec(VecSize::VecU8, buffer, &self.interim_transcript_hash)?;
        encode_vec(VecSize::VecU16, buffer, &self.extensions)?;
        encode_vec(VecSize::VecU8, buffer, &self.confirmation)?;
        self.signer_index.as_u32().encode(buffer)?;
        Ok(buffer.to_vec())
    }
}

pub struct PathSecret {
    pub path_secret: Vec<u8>,
}

impl Codec for PathSecret {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.path_secret)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let path_secret = decode_vec(VecSize::VecU8, cursor)?;
        Ok(PathSecret { path_secret })
    }
}

pub struct GroupSecrets {
    pub epoch_secret: Vec<u8>,
    pub path_secret: Option<PathSecret>,
}

impl Codec for GroupSecrets {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.epoch_secret)?;
        self.path_secret.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let epoch_secret = decode_vec(VecSize::VecU8, cursor)?;
        let path_secret = Option::<PathSecret>::decode(cursor)?;
        Ok(GroupSecrets {
            epoch_secret,
            path_secret,
        })
    }
}

#[derive(Clone)]
pub struct EncryptedGroupSecrets {
    pub key_package_hash: Vec<u8>,
    pub encrypted_group_secrets: HpkeCiphertext,
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

#[derive(Clone)]
pub struct Welcome {
    pub version: ProtocolVersion,
    pub cipher_suite: CiphersuiteName,
    pub secrets: Vec<EncryptedGroupSecrets>,
    pub encrypted_group_info: Vec<u8>,
}

impl Codec for Welcome {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.version.encode(buffer)?;
        self.cipher_suite.encode(buffer)?;
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
            cipher_suite,
            secrets,
            encrypted_group_info,
        })
    }
}

pub type WelcomeBundle = (Welcome, Extension);
