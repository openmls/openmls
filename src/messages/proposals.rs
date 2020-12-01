use crate::ciphersuite::*;
use crate::codec::*;
use crate::framing::{sender::*, *};
use crate::key_packages::*;
use crate::tree::index::*;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(PartialEq, Clone, Copy, Debug)]
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
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Proposal {
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
}

impl Proposal {
    pub(crate) fn proposal_type(&self) -> ProposalType {
        match self {
            Proposal::Add(ref _a) => ProposalType::Add,
            Proposal::Update(ref _u) => ProposalType::Update,
            Proposal::Remove(ref _r) => ProposalType::Remove,
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

#[derive(Debug, Eq, PartialEq, Hash, Clone, Serialize, Deserialize)]
pub struct ProposalID {
    value: Vec<u8>,
}

impl ProposalID {
    pub(crate) fn from_proposal(ciphersuite: &Ciphersuite, proposal: &Proposal) -> Self {
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

/// Alternative representation of a Proposal, where the sender is extracted from
/// the encapsulating MLSPlaintext and the ProposalID is attached.
#[derive(Clone)]
pub struct QueuedProposal {
    proposal: Proposal,
    proposal_id: ProposalID,
    sender: Sender,
}

impl QueuedProposal {
    /// Creates a new `QueuedProposal` from an `MLSPlaintext`
    pub(crate) fn new(ciphersuite: &Ciphersuite, mls_plaintext: &MLSPlaintext) -> Self {
        debug_assert!(mls_plaintext.content_type == ContentType::Proposal);
        let proposal = match &mls_plaintext.content {
            MLSPlaintextContentType::Proposal(p) => p.clone(),
            _ => panic!("API misuse. Only proposals can end up in the proposal queue"),
        };
        let proposal_id = ProposalID::from_proposal(ciphersuite, &proposal);
        Self {
            proposal,
            proposal_id,
            sender: mls_plaintext.sender,
        }
    }
    /// Returns the `Proposal` as a reference
    pub(crate) fn proposal(&self) -> &Proposal {
        &self.proposal
    }
    /// Returns the `ProposalID` as a reference
    pub(crate) fn proposal_id(&self) -> &ProposalID {
        &self.proposal_id
    }
    /// Returns the `Sender` as a reference
    pub(crate) fn sender(&self) -> &Sender {
        &self.sender
    }
}

/// Proposal queue that helps filtering and sorting the Proposals from one
/// epoch.
#[derive(Default)]
pub struct ProposalQueue {
    queued_proposals: HashMap<ProposalID, QueuedProposal>,
}

impl ProposalQueue {
    // Returns a new empty `ProposalQueue`
    pub(crate) fn new() -> Self {
        ProposalQueue {
            queued_proposals: HashMap::new(),
        }
    }
    /// Returns a new `ProposalQueue` from proposals that were committed and
    /// don't need filtering
    pub(crate) fn new_from_committed_proposals(
        ciphersuite: &Ciphersuite,
        proposals: Vec<MLSPlaintext>,
    ) -> Self {
        let mut proposal_queue = ProposalQueue::new();
        for mls_plaintext in proposals {
            let queued_proposal = QueuedProposal::new(ciphersuite, &mls_plaintext);
            proposal_queue.add(queued_proposal);
        }
        proposal_queue
    }
    /// Filters received proposals
    ///
    /// 11.2 Commit
    /// If there are multiple proposals that apply to the same leaf,
    /// the committer chooses one and includes only that one in the Commit,
    /// considering the rest invalid. The committer MUST prefer any Remove
    /// received, or the most recent Update for the leaf if there are no
    /// Removes. If there are multiple Add proposals for the same client,
    /// the committer again chooses one to include and considers the rest
    /// invalid.
    ///
    /// The function performs the following steps:
    ///
    /// - Extract Adds and filter for duplicates
    /// - Build member list with chains: Updates & Removes
    /// - Check for invalid indexes and drop proposal
    /// - Check for presence of Removes and delete Updates
    /// - Only keep the last Update
    ///
    /// Return a `ProposalQueue` a bool that indicates whether Updates for the
    /// own node were included
    pub(crate) fn filter_proposals(
        ciphersuite: &Ciphersuite,
        proposals: &[MLSPlaintext],
        own_index: LeafIndex,
        tree_size: LeafIndex,
    ) -> (Self, bool) {
        #[derive(Clone)]
        struct Member {
            updates: Vec<QueuedProposal>,
            removes: Vec<QueuedProposal>,
        }
        let mut members: Vec<Member> = vec![
            Member {
                updates: vec![],
                removes: vec![],
            };
            tree_size.as_usize()
        ];
        let mut adds: HashSet<ProposalID> = HashSet::new();
        let mut valid_proposals: HashSet<ProposalID> = HashSet::new();
        let mut proposal_queue = ProposalQueue::new();
        let mut contains_own_updates = false;

        // Parse proposals and build adds and member list
        for mls_plaintext in proposals.iter() {
            let queued_proposal = QueuedProposal::new(ciphersuite, mls_plaintext);
            match queued_proposal.proposal.proposal_type() {
                ProposalType::Add => {
                    adds.insert(queued_proposal.proposal_id().clone());
                    proposal_queue.add(queued_proposal);
                }
                ProposalType::Update => {
                    let sender_index = queued_proposal.sender.sender.as_usize();
                    if sender_index != own_index.as_usize() {
                        members[sender_index].updates.push(queued_proposal.clone());
                    } else {
                        contains_own_updates = true;
                    }
                    proposal_queue.add(queued_proposal);
                }
                ProposalType::Remove => {
                    let removed_index =
                        queued_proposal.proposal.as_remove().unwrap().removed as usize;
                    if removed_index < tree_size.as_usize() {
                        members[removed_index].updates.push(queued_proposal.clone());
                    }
                    proposal_queue.add(queued_proposal);
                }
                _ => {}
            }
        }
        // Check for presence of Removes and delete Updates
        for member in members.iter_mut() {
            // Check if there are Removes
            if !member.removes.is_empty() {
                // Delete all Updates when a Remove is found
                member.updates = Vec::new();
                // Only keep the last Remove
                valid_proposals.insert(member.removes.last().unwrap().proposal_id().clone());
            }
            if !member.updates.is_empty() {
                // Only keep the last Update
                valid_proposals.insert(member.updates.last().unwrap().proposal_id().clone());
            }
        }
        // Only retain valid proposals
        proposal_queue.retain(|k, _| valid_proposals.get(k).is_some() || adds.get(k).is_some());
        (proposal_queue, contains_own_updates)
    }
    /// Returns `true` if all `ProposalID` values from the list are contained in
    /// the queue
    pub(crate) fn contains(&self, proposal_id_list: &[ProposalID]) -> bool {
        for proposal_id in proposal_id_list {
            if !self.queued_proposals.contains_key(proposal_id) {
                return false;
            }
        }
        true
    }
    /// Add a new `QueuedProposal` to the queue
    pub(crate) fn add(&mut self, queued_proposal: QueuedProposal) {
        self.queued_proposals
            .entry(queued_proposal.proposal_id.clone())
            .or_insert(queued_proposal);
    }
    /// Retains only the elements specified by the predicate
    pub(crate) fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&ProposalID, &mut QueuedProposal) -> bool,
    {
        self.queued_proposals.retain(f);
    }
    /// Gets the list of all `ProposalID`
    pub(crate) fn proposal_id_list(&self) -> Vec<ProposalID> {
        self.queued_proposals.keys().into_iter().cloned().collect()
    }
    /// Return a list of fileterd `QueuedProposal`
    pub(crate) fn filtered_queued_proposals(
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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
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
