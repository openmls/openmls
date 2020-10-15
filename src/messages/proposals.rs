use crate::ciphersuite::*;
use crate::codec::*;
use crate::framing::{sender::*, *};
use crate::key_packages::*;
use std::collections::HashMap;

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
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     Ok(ProposalType::from(u8::decode(cursor)?))
    // }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone)]
pub enum Proposal {
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
}

impl Proposal {
    pub fn to_proposal_id(&self, ciphersuite: &Ciphersuite) -> ProposalID {
        ProposalID::from_proposal(ciphersuite, self)
    }

    pub fn is_type(&self, proposal_type: ProposalType) -> bool {
        match proposal_type {
            ProposalType::Add => matches!(self, Proposal::Add(ref _a)),
            ProposalType::Update => matches!(self, Proposal::Update(ref _u)),
            ProposalType::Remove => matches!(self, Proposal::Remove(ref _r)),
            _ => false,
        }
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
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let proposal_type = ProposalType::from(u8::decode(cursor)?);
    //     match proposal_type {
    //         ProposalType::Add => Ok(Proposal::Add(AddProposal::decode(cursor)?)),
    //         ProposalType::Update => Ok(Proposal::Update(UpdateProposal::decode(cursor)?)),
    //         ProposalType::Remove => Ok(Proposal::Remove(RemoveProposal::decode(cursor)?)),
    //         _ => Err(CodecError::DecodingError),
    //     }
    // }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct ProposalID {
    value: Vec<u8>,
}

impl ProposalID {
    pub fn from_proposal(ciphersuite: &Ciphersuite, proposal: &Proposal) -> Self {
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
}

#[derive(Debug)]
pub struct QueuedProposal {
    pub proposal: Proposal,
    pub sender: Sender,
}

impl QueuedProposal {
    pub fn new(mls_plaintext: MLSPlaintext) -> Self {
        debug_assert!(mls_plaintext.content_type == ContentType::Proposal);
        let proposal = match mls_plaintext.content {
            MLSPlaintextContentType::Proposal(p) => p,
            _ => panic!("API misuse. Only proposals can end up in the proposal queue"),
        };
        Self {
            proposal,
            sender: mls_plaintext.sender,
        }
    }
}

#[derive(Default)]
pub struct ProposalQueue {
    queued_proposals: HashMap<ProposalID, QueuedProposal>,
}

impl ProposalQueue {
    pub fn new() -> Self {
        ProposalQueue {
            queued_proposals: HashMap::new(),
        }
    }
    pub fn new_from_proposals(proposals: Vec<MLSPlaintext>, ciphersuite: &Ciphersuite) -> Self {
        let mut proposal_queue = ProposalQueue::new();
        for mls_plaintext in proposals {
            let queued_proposal = QueuedProposal::new(mls_plaintext);
            proposal_queue.add(queued_proposal, &ciphersuite);
        }
        proposal_queue
    }
    pub(crate) fn contains(&self, proposal_id_list: &[ProposalID]) -> bool {
        for proposal_id in proposal_id_list {
            if !self.queued_proposals.contains_key(proposal_id) {
                return false;
            }
        }
        true
    }
    pub(crate) fn add(&mut self, queued_proposal: QueuedProposal, ciphersuite: &Ciphersuite) {
        let proposal_id = ProposalID::from_proposal(ciphersuite, &queued_proposal.proposal);
        self.queued_proposals
            .entry(proposal_id)
            .or_insert(queued_proposal);
    }
    pub(crate) fn _get(&self, proposal_id: &ProposalID) -> Option<&QueuedProposal> {
        match self.queued_proposals.get(&proposal_id) {
            Some(queued_proposal) => Some(queued_proposal),
            None => None,
        }
    }
    pub(crate) fn get_proposal_id_list(&self) -> Vec<ProposalID> {
        self.queued_proposals.keys().into_iter().cloned().collect()
    }
    pub(crate) fn get_filtered_proposals(
        &self,
        proposal_id_list: &[ProposalID],
        proposal_type: ProposalType,
    ) -> Vec<&QueuedProposal> {
        let mut filtered_proposal_id_list = Vec::new();
        for proposal_id in proposal_id_list.iter() {
            if let Some(queued_proposal) = self.queued_proposals.get(proposal_id) {
                if queued_proposal.proposal.is_type(proposal_type) {
                    filtered_proposal_id_list.push(queued_proposal);
                }
            }
        }
        filtered_proposal_id_list
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
}
