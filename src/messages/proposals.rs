use crate::ciphersuite::*;
use crate::codec::*;
use crate::framing::{sender::*, *};
use crate::key_packages::*;
use crate::tree::index::*;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;

use super::errors::*;

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
#[derive(PartialEq, Clone, Copy, Debug)]
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
/// TODO #141: We should cover other types of proposals
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

/// Reference to a Proposal. This can be used in Commit messages to reference
/// proposals that have already been sent
#[derive(Debug, Eq, PartialEq, Hash, Clone, Serialize, Deserialize)]
pub struct ProposalReference {
    pub(crate) value: Vec<u8>,
}

impl ProposalReference {
    pub(crate) fn from_proposal(ciphersuite: &Ciphersuite, proposal: &Proposal) -> Self {
        let encoded = proposal.encode_detached().unwrap();
        let value = ciphersuite.hash(&encoded);
        Self { value }
    }
}

/// Alternative representation of a Proposal, where the sender is extracted from
/// the encapsulating MLSPlaintext and the ProposalReference is attached.
#[derive(Clone)]
pub(crate) struct QueuedProposal<'a> {
    proposal: &'a Proposal,
    proposal_id: ProposalReference,
    sender: Sender,
    proposal_or_ref_type: ProposalOrRefType,
}

impl<'a> QueuedProposal<'a> {
    /// Creates a new `QueuedProposal` from an `MLSPlaintext`
    pub(crate) fn from_mls_plaintext(
        ciphersuite: &Ciphersuite,
        mls_plaintext: &'a MLSPlaintext,
    ) -> Result<Self, QueuedProposalError> {
        debug_assert!(mls_plaintext.content_type == ContentType::Proposal);
        let proposal = match &mls_plaintext.content {
            MLSPlaintextContentType::Proposal(p) => p,
            _ => return Err(QueuedProposalError::WrongContentType),
        };
        let proposal_id = ProposalReference::from_proposal(ciphersuite, &proposal);
        Ok(Self {
            proposal,
            proposal_id,
            sender: mls_plaintext.sender,
            proposal_or_ref_type: ProposalOrRefType::Reference,
        })
    }
    /// Creates a new `QueuedProposal` from a `Proposal` and `Sender`
    pub(crate) fn from_proposal_and_sender(
        ciphersuite: &Ciphersuite,
        proposal: &'a Proposal,
        sender: Sender,
    ) -> Self {
        let proposal_id = ProposalReference::from_proposal(ciphersuite, &proposal);
        Self {
            proposal,
            proposal_id,
            sender,
            proposal_or_ref_type: ProposalOrRefType::Proposal,
        }
    }
    /// Returns the `Proposal` as a reference
    pub(crate) fn proposal(&self) -> &Proposal {
        &self.proposal
    }
    /// Returns the `ProposalReference` as a reference
    pub(crate) fn proposal_id(&self) -> &ProposalReference {
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
pub struct ProposalQueue<'a> {
    proposal_references: Vec<ProposalReference>,
    queued_proposals: HashMap<ProposalReference, QueuedProposal<'a>>,
}

impl<'a> ProposalQueue<'a> {
    // Returns a new empty `ProposalQueue`
    pub(crate) fn new() -> Self {
        ProposalQueue {
            proposal_references: Vec::new(),
            queued_proposals: HashMap::new(),
        }
    }
    /// Returns a new `ProposalQueue` from proposals that were committed and
    /// don't need filtering
    pub(crate) fn from_proposals_by_reference(
        ciphersuite: &Ciphersuite,
        proposals: &'a [&MLSPlaintext],
    ) -> Self {
        let mut proposal_queue = ProposalQueue::new();
        for mls_plaintext in proposals {
            // It is safe to unwrap here, because we checked that only proposals can end up
            // here.
            let queued_proposal =
                QueuedProposal::from_mls_plaintext(ciphersuite, &mls_plaintext).unwrap();
            proposal_queue.add(queued_proposal);
        }
        proposal_queue
    }
    /// Returns a new `ProposalQueue` from proposals that were committed and
    /// don't need filtering
    pub(crate) fn from_committed_proposals(
        ciphersuite: &Ciphersuite,
        committed_proposals: &'a [ProposalOrRef],
        proposals_by_reference: &'a [&'a MLSPlaintext],
        sender: Sender,
    ) -> Result<Self, ProposalQueueError> {
        let mut proposals_by_reference_queue: HashMap<ProposalReference, QueuedProposal> =
            HashMap::new();
        for mls_plaintext in proposals_by_reference {
            let queued_proposal =
                QueuedProposal::from_mls_plaintext(ciphersuite, mls_plaintext).unwrap();
            proposals_by_reference_queue
                .insert(queued_proposal.proposal_id().clone(), queued_proposal);
        }

        let mut proposal_queue = ProposalQueue::new();

        for proposal_or_ref in committed_proposals.iter() {
            let queued_proposal = match proposal_or_ref {
                ProposalOrRef::Proposal(proposal) => {
                    QueuedProposal::from_proposal_and_sender(ciphersuite, proposal, sender)
                }
                ProposalOrRef::Reference(proposal_id) => {
                    match proposals_by_reference_queue.get(proposal_id) {
                        Some(queued_proposal) => queued_proposal.clone(),
                        None => return Err(ProposalQueueError::ProposalNotFound),
                    }
                }
            };
            proposal_queue.add(queued_proposal);
        }
        Ok(proposal_queue)
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
        proposals_by_reference: &'a [&MLSPlaintext],
        proposals_by_value: &'a [&Proposal],
        own_index: LeafIndex,
        tree_size: LeafIndex,
    ) -> (Self, bool) {
        #[derive(Clone)]
        struct Member<'a> {
            updates: Vec<QueuedProposal<'a>>,
            removes: Vec<QueuedProposal<'a>>,
        }
        let mut members: Vec<Member> = vec![
            Member {
                updates: vec![],
                removes: vec![],
            };
            tree_size.as_usize()
        ];
        let mut adds: HashSet<ProposalReference> = HashSet::new();
        let mut valid_proposals: HashSet<ProposalReference> = HashSet::new();
        let mut proposal_queue = ProposalQueue::new();
        let mut contains_own_updates = false;

        let sender = Sender {
            sender_type: SenderType::Member,
            sender: own_index,
        };

        // Aggregate both proposal types to a common iterator
        // It is safe to unwrap here, because we checked eralier that only proposals can
        // end up here
        let mut queued_proposal_list = proposals_by_reference
            .iter()
            .map(|mls_plaintext| {
                QueuedProposal::from_mls_plaintext(ciphersuite, mls_plaintext).unwrap()
            })
            .collect::<Vec<QueuedProposal>>();

        queued_proposal_list.extend(
            proposals_by_value
                .iter()
                .map(|p| QueuedProposal::from_proposal_and_sender(ciphersuite, p, sender))
                .collect::<Vec<QueuedProposal>>()
                .into_iter(),
        );

        // Parse proposals and build adds and member list
        for queued_proposal in queued_proposal_list {
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

    /// Returns `true` if all `ProposalReference` values from the list are
    /// contained in the queue
    #[cfg(test)]
    pub(crate) fn contains(&self, proposal_id_list: &[ProposalReference]) -> bool {
        for proposal_id in proposal_id_list {
            if !self.queued_proposals.contains_key(proposal_id) {
                return false;
            }
        }
        true
    }

    /// Returns proposal for a given proposal ID
    pub(crate) fn get(&self, proposal_reference: &ProposalReference) -> Option<&QueuedProposal> {
        self.queued_proposals.get(proposal_reference)
    }

    /// Add a new `QueuedProposal` to the queue
    pub(crate) fn add(&mut self, queued_proposal: QueuedProposal<'a>) {
        let proposal_reference = queued_proposal.proposal_id();
        if !self.queued_proposals.contains_key(proposal_reference) {
            self.proposal_references.push(proposal_reference.clone());
            self.queued_proposals
                .insert(proposal_reference.clone(), queued_proposal);
        }
    }

    /// Retains only the elements specified by the predicate
    pub(crate) fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&ProposalReference, &mut QueuedProposal<'a>) -> bool,
    {
        self.queued_proposals.retain(f);
    }
    /// Gets the list of all `ProposalReference`
    pub(crate) fn commit_list(&self) -> Vec<ProposalOrRef> {
        self.queued_proposals
            .iter()
            .map(
                |(proposal_id, queued_proposal)| match queued_proposal.proposal_or_ref_type {
                    ProposalOrRefType::Proposal => {
                        ProposalOrRef::Proposal(queued_proposal.proposal.clone())
                    }
                    ProposalOrRefType::Reference => ProposalOrRef::Reference(proposal_id.clone()),
                },
            )
            .collect::<Vec<ProposalOrRef>>()
    }
    /// Returns an iterator over a list of `QueuedProposal` filtered by proposal
    /// type
    pub(crate) fn filtered_by_type(
        &self,
        proposal_type: ProposalType,
    ) -> impl Iterator<Item = &ProposalReference> {
        self.proposal_references
            .iter()
            .filter(move |&pr| match self.queued_proposals.get(pr) {
                Some(p) => p.proposal.is_type(proposal_type),
                None => false,
            })
            .into_iter()
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AddProposal {
    pub key_package: KeyPackage,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct UpdateProposal {
    pub key_package: KeyPackage,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RemoveProposal {
    pub removed: u32,
}
