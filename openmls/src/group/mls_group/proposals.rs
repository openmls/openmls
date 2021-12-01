use crate::group::errors::*;

use crate::messages::proposals::{
    AddProposal, PreSharedKeyProposal, Proposal, ProposalOrRef, ProposalOrRefType,
    ProposalReference, ProposalType, RemoveProposal, UpdateProposal,
};
use crate::tree::index::LeafIndex;
use crate::{ciphersuite::*, framing::*};

use openmls_traits::OpenMlsCryptoProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::collections::{hash_map::Entry, HashMap};

/// A [ProposalStore] can store the standalone proposals that are received from the DS
/// in between two commit messages.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ProposalStore {
    staged_proposals: Vec<StagedProposal>,
}

impl ProposalStore {
    pub fn new() -> Self {
        Self {
            staged_proposals: Vec::new(),
        }
    }
    pub fn from_staged_proposal(staged_proposal: StagedProposal) -> Self {
        Self {
            staged_proposals: vec![staged_proposal],
        }
    }
    pub fn add(&mut self, staged_proposal: StagedProposal) {
        self.staged_proposals.push(staged_proposal);
    }
    pub fn proposals(&self) -> impl Iterator<Item = &StagedProposal> {
        self.staged_proposals.iter()
    }
    pub fn is_empty(&self) -> bool {
        self.staged_proposals.is_empty()
    }
    pub fn empty(&mut self) {
        self.staged_proposals = Vec::new();
    }
}

/// Alternative representation of a Proposal, where the sender is extracted from
/// the encapsulating MlsPlaintext and the ProposalReference is attached.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StagedProposal {
    proposal: Proposal,
    proposal_reference: ProposalReference,
    sender: Sender,
    proposal_or_ref_type: ProposalOrRefType,
}

impl StagedProposal {
    /// Creates a new [StagedProposal] from an [MlsPlaintext]
    pub fn from_mls_plaintext(
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        mls_plaintext: MlsPlaintext,
    ) -> Result<Self, StagedProposalError> {
        let proposal = match mls_plaintext.content() {
            MlsPlaintextContentType::Proposal(p) => p,
            _ => return Err(StagedProposalError::WrongContentType),
        };
        let proposal_reference = ProposalReference::from_proposal(ciphersuite, backend, proposal)?;
        Ok(Self {
            proposal: proposal.clone(), // FIXME
            proposal_reference,
            sender: *mls_plaintext.sender(),
            proposal_or_ref_type: ProposalOrRefType::Reference,
        })
    }
    /// Creates a new [StagedProposal] from a [Proposal] and [Sender]
    pub(crate) fn from_proposal_and_sender(
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        proposal: Proposal,
        sender: Sender,
    ) -> Result<Self, StagedProposalError> {
        let proposal_reference = ProposalReference::from_proposal(ciphersuite, backend, &proposal)?;
        Ok(Self {
            proposal,
            proposal_reference,
            sender,
            proposal_or_ref_type: ProposalOrRefType::Proposal,
        })
    }
    /// Returns the `Proposal` as a reference
    pub fn proposal(&self) -> &Proposal {
        &self.proposal
    }
    /// Returns the `ProposalReference`.
    pub(crate) fn proposal_reference(&self) -> ProposalReference {
        self.proposal_reference.clone()
    }
    /// Returns the `Sender` as a reference
    pub fn sender(&self) -> &Sender {
        &self.sender
    }
}

/// Proposal queue that helps filtering and sorting the staged Proposals from one
/// epoch. The Proposals are stored in a `HashMap` which maps Proposal
/// references to Proposals, such that, given a reference, a proposal can be
/// accessed efficiently. To enable iteration over the queue in order, the
/// `ProposalQueue` also contains a vector of `ProposalReference`s.
#[derive(Default, Debug)]
pub struct StagedProposalQueue {
    /// `proposal_references` holds references to the proposals in the queue and
    /// determines the order of the queue.
    proposal_references: Vec<ProposalReference>,
    /// `queued_proposals` contains the actual proposals in the queue. They are
    /// stored in a `HashMap` to allow for efficient access to the proposals.
    queued_proposals: HashMap<ProposalReference, StagedProposal>,
}

impl StagedProposalQueue {
    /// Returns a new `StagedProposalQueue` from proposals that were committed and
    /// don't need filtering.
    /// This functions does the following checks:
    ///  - ValSem200
    pub(crate) fn from_committed_proposals(
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        committed_proposals: Vec<ProposalOrRef>,
        proposal_store: &ProposalStore,
        sender: Sender,
    ) -> Result<Self, StagedProposalQueueError> {
        // Feed the `proposals_by_reference` in a `HashMap` so that we can easily
        // extract then by reference later
        let mut proposals_by_reference_queue: HashMap<ProposalReference, StagedProposal> =
            HashMap::new();
        for staged_proposal in proposal_store.proposals() {
            proposals_by_reference_queue.insert(
                staged_proposal.proposal_reference(),
                staged_proposal.clone(),
            );
        }

        // Build the actual queue
        let mut proposal_queue = StagedProposalQueue::default();

        // Iterate over the committed proposals and insert the proposals in the queue
        for proposal_or_ref in committed_proposals.into_iter() {
            let queued_proposal = match proposal_or_ref {
                ProposalOrRef::Proposal(proposal) => {
                    // ValSem200
                    if let Proposal::Remove(ref remove_proposal) = proposal {
                        if remove_proposal.removed() == sender.sender.as_u32() {
                            return Err(StagedProposalQueueError::SelfRemoval);
                        }
                    }

                    StagedProposal::from_proposal_and_sender(
                        ciphersuite,
                        backend,
                        proposal,
                        sender,
                    )?
                }
                ProposalOrRef::Reference(ref proposal_reference) => {
                    match proposals_by_reference_queue.get(proposal_reference) {
                        Some(staged_proposal) => {
                            // ValSem200
                            if let Proposal::Remove(ref remove_proposal) = staged_proposal.proposal
                            {
                                if remove_proposal.removed() == sender.sender.as_u32() {
                                    return Err(StagedProposalQueueError::SelfRemoval);
                                }
                            }

                            staged_proposal.clone()
                        }
                        None => return Err(StagedProposalQueueError::ProposalNotFound),
                    }
                }
            };
            proposal_queue.add(queued_proposal);
        }

        Ok(proposal_queue)
    }

    /// Returns proposal for a given proposal ID
    pub(crate) fn get(&self, proposal_reference: &ProposalReference) -> Option<&StagedProposal> {
        self.queued_proposals.get(proposal_reference)
    }

    /// Add a new [StagedProposal] to the queue
    pub(crate) fn add(&mut self, staged_proposal: StagedProposal) {
        let proposal_reference = staged_proposal.proposal_reference();
        // Only add the proposal if it's not already there
        if let Entry::Vacant(entry) = self.queued_proposals.entry(proposal_reference.clone()) {
            // Add the proposal reference to ensure the correct order
            self.proposal_references.push(proposal_reference);
            // Add the proposal to the queue
            entry.insert(staged_proposal);
        }
    }

    /// Returns an iterator over a list of `StagedProposal` filtered by proposal
    /// type
    pub(crate) fn filtered_by_type(
        &self,
        proposal_type: ProposalType,
    ) -> impl Iterator<Item = &StagedProposal> {
        // Iterate over the reference to extract the proposals in the right order
        self.proposal_references
            .iter()
            .filter(move |&pr| match self.queued_proposals.get(pr) {
                Some(p) => p.proposal.is_type(proposal_type),
                None => false,
            })
            .map(move |reference| self.get(reference).unwrap())
    }

    /// Returns an iterator over all `StagedProposal` in the queue  
    /// in the order of the the Commit message
    pub(crate) fn staged_proposals(&self) -> impl Iterator<Item = &StagedProposal> {
        // Iterate over the reference to extract the proposals in the right order
        self.proposal_references
            .iter()
            .map(move |reference| self.get(reference).unwrap())
    }

    /// Returns an iterator over all Add proposals in the queue  
    /// in the order of the the Commit message
    pub fn add_proposals(&self) -> impl Iterator<Item = StagedAddProposal> {
        self.staged_proposals().filter_map(|staged_proposal| {
            if let Proposal::Add(add_proposal) = staged_proposal.proposal() {
                let sender = staged_proposal.sender();
                Some(StagedAddProposal {
                    add_proposal,
                    sender,
                })
            } else {
                None
            }
        })
    }

    /// Returns an iterator over all Remove proposals in the queue  
    /// in the order of the the Commit message
    pub fn remove_proposals(&self) -> impl Iterator<Item = StagedRemoveProposal> {
        self.staged_proposals().filter_map(|staged_proposal| {
            if let Proposal::Remove(remove_proposal) = staged_proposal.proposal() {
                let sender = staged_proposal.sender();
                Some(StagedRemoveProposal {
                    remove_proposal,
                    sender,
                })
            } else {
                None
            }
        })
    }

    /// Returns an iterator over all Update in the queue  
    /// in the order of the the Commit message
    pub fn update_proposals(&self) -> impl Iterator<Item = StagedUpdateProposal> {
        self.staged_proposals().filter_map(|staged_proposal| {
            if let Proposal::Update(update_proposal) = staged_proposal.proposal() {
                let sender = staged_proposal.sender();
                Some(StagedUpdateProposal {
                    update_proposal,
                    sender,
                })
            } else {
                None
            }
        })
    }

    /// Returns an iterator over all PresharedKey proposals in the queue  
    /// in the order of the the Commit message
    pub fn psk_proposals(&self) -> impl Iterator<Item = StagedPskProposal> {
        self.staged_proposals().filter_map(|staged_proposal| {
            if let Proposal::PreSharedKey(psk_proposal) = staged_proposal.proposal() {
                let sender = staged_proposal.sender();
                Some(StagedPskProposal {
                    psk_proposal,
                    sender,
                })
            } else {
                None
            }
        })
    }
}

/// A staged Add proposal
pub struct StagedAddProposal<'a> {
    add_proposal: &'a AddProposal,
    sender: &'a Sender,
}

impl<'a> StagedAddProposal<'a> {
    /// Returns a reference to the proposal
    pub fn add_proposal(&self) -> &AddProposal {
        self.add_proposal
    }

    /// Returns a reference to the sender
    pub fn sender(&self) -> &Sender {
        self.sender
    }
}

/// A staged Remove proposal
pub struct StagedRemoveProposal<'a> {
    remove_proposal: &'a RemoveProposal,
    sender: &'a Sender,
}

impl<'a> StagedRemoveProposal<'a> {
    /// Returns a reference to the proposal
    pub fn remove_proposal(&self) -> &RemoveProposal {
        self.remove_proposal
    }

    /// Returns a reference to the sender
    pub fn sender(&self) -> &Sender {
        self.sender
    }
}

/// A staged Update proposal
pub struct StagedUpdateProposal<'a> {
    update_proposal: &'a UpdateProposal,
    sender: &'a Sender,
}

impl<'a> StagedUpdateProposal<'a> {
    /// Returns a reference to the proposal
    pub fn update_proposal(&self) -> &UpdateProposal {
        self.update_proposal
    }

    /// Returns a reference to the sender
    pub fn sender(&self) -> &Sender {
        self.sender
    }
}

/// A staged PresharedKey proposal
pub struct StagedPskProposal<'a> {
    psk_proposal: &'a PreSharedKeyProposal,
    sender: &'a Sender,
}

impl<'a> StagedPskProposal<'a> {
    /// Returns a reference to the proposal
    pub fn psk_proposal(&self) -> &PreSharedKeyProposal {
        self.psk_proposal
    }

    /// Returns a reference to the sender
    pub fn sender(&self) -> &Sender {
        self.sender
    }
}

/// Alternative representation of a Proposal, where the sender is extracted from
/// the encapsulating MlsPlaintext and the ProposalReference is attached.
#[derive(Debug, Clone)]
pub(crate) struct QueuedProposal<'a> {
    proposal: &'a Proposal,
    proposal_reference: ProposalReference,
    sender: Sender,
    proposal_or_ref_type: ProposalOrRefType,
}

impl<'a> QueuedProposal<'a> {
    /// Creates a new [QueuedProposal] from a [Proposal] and [Sender].
    /// Note that the proposal type will always be `Proposal`.
    pub(crate) fn from_proposal_and_sender(
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        proposal: &'a Proposal,
        sender: Sender,
    ) -> Result<Self, StagedProposalError> {
        let proposal_reference = ProposalReference::from_proposal(ciphersuite, backend, proposal)?;
        Ok(Self {
            proposal,
            proposal_reference,
            sender,
            proposal_or_ref_type: ProposalOrRefType::Proposal,
        })
    }
    /// Creates a new [QueuedProposal] from a [StagedProposal].
    /// /// Note that the proposal type will always be `Reference`.
    pub(crate) fn from_staged_proposal(
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        staged_proposal: &'a StagedProposal,
    ) -> Result<Self, StagedProposalError> {
        let proposal_reference =
            ProposalReference::from_proposal(ciphersuite, backend, staged_proposal.proposal())?;
        Ok(Self {
            proposal: staged_proposal.proposal(),
            proposal_reference,
            sender: *staged_proposal.sender(),
            proposal_or_ref_type: ProposalOrRefType::Reference,
        })
    }
    /// Returns the `Proposal` as a reference
    pub(crate) fn proposal(&self) -> &Proposal {
        self.proposal
    }
    /// Returns the `ProposalReference` as a reference
    pub(crate) fn proposal_reference(&self) -> ProposalReference {
        self.proposal_reference.clone()
    }
    /// Returns the `Sender` as a reference
    pub(crate) fn sender(&self) -> &Sender {
        &self.sender
    }
}

/// Proposal queue that helps filtering and sorting the Proposals from one
/// epoch. The Proposals are stored in a `HashMap` which maps Proposal
/// references to Proposals, such that, given a reference, a proposal can be
/// accessed efficiently. To enable iteration over the queue in order, the
/// `ProposalQueue` also contains a vector of `ProposalReference`s.
#[derive(Default, Debug)]
pub struct CreationProposalQueue<'a> {
    /// `proposal_references` holds references to the proposals in the queue and
    /// determines the order of the queue.
    proposal_references: Vec<ProposalReference>,
    /// `queued_proposals` contains the actual proposals in the queue. They are
    /// stored in a `HashMap` to allow for efficient access to the proposals.
    queued_proposals: HashMap<ProposalReference, QueuedProposal<'a>>,
}

impl<'a> CreationProposalQueue<'a> {
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
    /// Return a [CreationProposalQueue] and a bool that indicates whether Updates for the
    /// own node were included
    pub(crate) fn filter_proposals(
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        proposal_store: &'a ProposalStore,
        inline_proposals: &'a [Proposal],
        own_index: LeafIndex,
        tree_size: LeafIndex,
    ) -> Result<(Self, bool), CreationProposalQueueError> {
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
        let mut proposal_pool: HashMap<ProposalReference, QueuedProposal> = HashMap::new();
        let mut contains_own_updates = false;

        let sender = Sender {
            sender_type: SenderType::Member,
            sender: own_index,
        };

        // Aggregate both proposal types to a common iterator
        // We checked earlier that only proposals can end up here
        let mut queued_proposal_list = proposal_store
            .proposals()
            .map(|staged_proposal| {
                QueuedProposal::from_staged_proposal(ciphersuite, backend, staged_proposal)
            })
            .collect::<Result<Vec<QueuedProposal<'a>>, _>>()?;

        queued_proposal_list.extend(
            inline_proposals
                .iter()
                .map(|p| QueuedProposal::from_proposal_and_sender(ciphersuite, backend, p, sender))
                .collect::<Result<Vec<QueuedProposal<'a>>, _>>()?
                .into_iter(),
        );

        // Parse proposals and build adds and member list
        for queued_proposal in queued_proposal_list {
            match queued_proposal.proposal.proposal_type() {
                ProposalType::Add => {
                    adds.insert(queued_proposal.proposal_reference());
                    proposal_pool.insert(queued_proposal.proposal_reference(), queued_proposal);
                }
                ProposalType::Update => {
                    let sender_index = queued_proposal.sender.sender.as_usize();
                    if sender_index != own_index.as_usize() {
                        members[sender_index].updates.push(queued_proposal.clone());
                    } else {
                        contains_own_updates = true;
                    }
                    let proposal_reference = queued_proposal.proposal_reference();
                    proposal_pool.insert(proposal_reference, queued_proposal);
                }
                ProposalType::Remove => {
                    let removed_index =
                        queued_proposal.proposal.as_remove().unwrap().removed as usize;
                    if removed_index < tree_size.as_usize() {
                        members[removed_index].updates.push(queued_proposal.clone());
                    }
                    let proposal_reference = queued_proposal.proposal_reference();
                    proposal_pool.insert(proposal_reference, queued_proposal);
                }
                ProposalType::Presharedkey => {
                    valid_proposals.insert(queued_proposal.proposal_reference());
                    proposal_pool.insert(queued_proposal.proposal_reference(), queued_proposal);
                }
                ProposalType::Reinit => {
                    // TODO #141: Only keep one ReInit
                    proposal_pool.insert(queued_proposal.proposal_reference(), queued_proposal);
                }
                ProposalType::ExternalInit => unimplemented!("See #556"),
                ProposalType::AppAck => unimplemented!("See #291"),
                ProposalType::GroupContextExtensions => {
                    // TODO: Validate proposal?
                    proposal_pool.insert(queued_proposal.proposal_reference(), queued_proposal);
                }
            }
        }
        // Check for presence of Removes and delete Updates
        for member in members.iter_mut() {
            // Check if there are Removes
            if !member.removes.is_empty() {
                // Delete all Updates when a Remove is found
                member.updates = Vec::new();
                // Only keep the last Remove
                valid_proposals.insert(member.removes.last().unwrap().proposal_reference());
            }
            if !member.updates.is_empty() {
                // Only keep the last Update
                valid_proposals.insert(member.updates.last().unwrap().proposal_reference());
            }
        }
        // Only retain `adds` and `valid_proposals`
        let mut proposal_queue = CreationProposalQueue::default();
        for proposal_reference in adds.iter().chain(valid_proposals.iter()) {
            proposal_queue.add(match proposal_pool.get(proposal_reference) {
                Some(queued_proposal) => queued_proposal.clone(),
                None => return Err(CreationProposalQueueError::ProposalNotFound),
            });
        }
        Ok((proposal_queue, contains_own_updates))
    }
    /// Returns `true` if all `ProposalReference` values from the list are
    /// contained in the queue
    #[cfg(test)]
    pub(crate) fn contains(&self, proposal_reference_list: &[ProposalReference]) -> bool {
        for proposal_reference in proposal_reference_list {
            if !self.queued_proposals.contains_key(proposal_reference) {
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
        let proposal_reference = queued_proposal.proposal_reference();
        // Only add the proposal if it's not already there
        if let Entry::Vacant(entry) = self.queued_proposals.entry(proposal_reference.clone()) {
            // Add the proposal reference to ensure the correct order
            self.proposal_references.push(proposal_reference);
            // Add the proposal to the queue
            entry.insert(queued_proposal);
        }
    }
    /// Returns the list of all proposals that are covered by a Commit
    pub(crate) fn commit_list(&self) -> Vec<ProposalOrRef> {
        // Iterate over the reference to extract the proposals in the right order
        self.proposal_references
            .iter()
            .map(|proposal_reference| {
                // Extract the proposal from the queue
                let queued_proposal = self.queued_proposals.get(proposal_reference).unwrap();
                // Differentiate the type of proposal
                match queued_proposal.proposal_or_ref_type {
                    ProposalOrRefType::Proposal => {
                        ProposalOrRef::Proposal(queued_proposal.proposal.clone())
                    }
                    ProposalOrRefType::Reference => {
                        ProposalOrRef::Reference(proposal_reference.clone())
                    }
                }
            })
            .collect::<Vec<ProposalOrRef>>()
    }
    /// Returns an iterator over a list of `QueuedProposal` filtered by proposal
    /// type
    pub(crate) fn filtered_by_type(
        &self,
        proposal_type: ProposalType,
    ) -> impl Iterator<Item = &QueuedProposal> {
        // Iterate over the reference to extract the proposals in the right order
        self.proposal_references
            .iter()
            .filter(move |&pr| match self.queued_proposals.get(pr) {
                Some(p) => p.proposal.is_type(proposal_type),
                None => false,
            })
            .map(move |reference| self.get(reference).unwrap())
    }
}
