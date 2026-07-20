#[cfg(feature = "migration-export")]
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    ciphersuite::hash_ref::ProposalRef,
    framing::Sender,
    messages::proposals::{Proposal, ProposalOrRefType},
    utils::vector_converter,
};

/// A [ProposalStore] can store the standalone proposals that are received from
/// the DS in between two commit messages.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ProposalStore {
    queued_proposals: Vec<QueuedProposal>,
}

#[cfg(feature = "migration-export")]
impl ProposalStore {
    /// Create a new [`ProposalStore`].
    pub fn new() -> Self {
        Self {
            queued_proposals: Vec::new(),
        }
    }
    pub(crate) fn add(&mut self, queued_proposal: QueuedProposal) {
        self.queued_proposals.push(queued_proposal);
    }
    pub(crate) fn empty(&mut self) {
        self.queued_proposals.clear();
    }
}

/// Alternative representation of a Proposal, where the sender is extracted from
/// the encapsulating PublicMessage and the ProposalRef is attached.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueuedProposal {
    proposal: Proposal,
    proposal_reference: ProposalRef,
    sender: Sender,
    proposal_or_ref_type: ProposalOrRefType,
}

impl QueuedProposal {
    #[cfg(feature = "migration-export")]
    /// Returns the `ProposalRef`.
    pub(crate) fn proposal_reference(&self) -> ProposalRef {
        self.proposal_reference.clone()
    }
}

/// Proposal queue that helps filtering and sorting Proposals received during
/// one epoch. The Proposals are stored in a `HashMap` which maps Proposal
/// references to Proposals, such that, given a reference, a proposal can be
/// accessed efficiently. To enable iteration over the queue in order, the
/// `ProposalQueue` also contains a vector of `ProposalRef`s.
#[derive(Default, Debug, Serialize, Deserialize)]
pub(crate) struct ProposalQueue {
    /// `proposal_references` holds references to the proposals in the queue and
    /// determines the order of the queue.
    proposal_references: Vec<ProposalRef>,
    /// `queued_proposals` contains the actual proposals in the queue. They are
    /// stored in a `HashMap` to allow for efficient access to the proposals.
    #[serde(with = "vector_converter")]
    queued_proposals: HashMap<ProposalRef, QueuedProposal>,
}

#[cfg(feature = "migration-export")]
impl ProposalQueue {
    /// Returns proposal for a given proposal ID
    pub fn get(&self, proposal_reference: &ProposalRef) -> Option<&QueuedProposal> {
        self.queued_proposals.get(proposal_reference)
    }

    /// Add a new [QueuedProposal] to the queue
    pub(crate) fn add(&mut self, queued_proposal: QueuedProposal) {
        let proposal_reference = queued_proposal.proposal_reference();
        // Only add the proposal if it's not already there
        if let Entry::Vacant(entry) = self.queued_proposals.entry(proposal_reference.clone()) {
            // Add the proposal reference to ensure the correct order
            self.proposal_references.push(proposal_reference);
            // Add the proposal to the queue
            entry.insert(queued_proposal);
        }
    }
}

#[cfg(feature = "migration-export")]
impl Extend<QueuedProposal> for ProposalQueue {
    fn extend<T: IntoIterator<Item = QueuedProposal>>(&mut self, iter: T) {
        for proposal in iter {
            self.add(proposal)
        }
    }
}
