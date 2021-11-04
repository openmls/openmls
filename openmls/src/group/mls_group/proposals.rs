use crate::messages::proposals::{
    Proposal, ProposalOrRef, ProposalOrRefType, ProposalReference, ProposalType,
};
use crate::{ciphersuite::*, framing::*};

use openmls_traits::OpenMlsCryptoProvider;
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap};
use tls_codec::Error as TlsCodecError;

implement_error! {
    pub enum StagedProposalError {
        Simple {
            WrongContentType = "API misuse. Only proposals can end up in the proposal queue",
        }
        Complex {
            TlsCodecError(TlsCodecError) = "Error serializing",
        }
    }
}

implement_error! {
    pub enum StagedProposalQueueError {
        Simple {
            ProposalNotFound = "Not all proposals in the Commit were found locally.",
        }
        Complex {
            NotAProposal(StagedProposalError) = "The given MLS Plaintext was not a Proposal.",
        }
    }
}

/// A [ProposalStore] can store the standalone proposals that are received from the DS
/// in between two commit messages.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProposalStore {
    staged_proposals: Vec<StagedProposal>,
}

impl ProposalStore {
    pub fn new() -> Self {
        Self {
            staged_proposals: Vec::new(),
        }
    }
    pub fn add(&mut self, staged_proposal: StagedProposal) {
        self.staged_proposals.push(staged_proposal);
    }
    pub fn proposals(&self) -> impl Iterator<Item = &StagedProposal> {
        self.staged_proposals.iter()
    }
    pub fn empty(&mut self) {
        self.staged_proposals = Vec::new();
    }
}

/// Alternative representation of a Proposal, where the sender is extracted from
/// the encapsulating MlsPlaintext and the ProposalReference is attached.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub(crate) fn proposal(&self) -> &Proposal {
        &self.proposal
    }
    /// Returns the `ProposalReference`.
    pub(crate) fn proposal_reference(&self) -> ProposalReference {
        self.proposal_reference.clone()
    }
    /// Returns the `Sender` as a reference
    pub(crate) fn sender(&self) -> &Sender {
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
    /// don't need filtering
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
                ProposalOrRef::Proposal(proposal) => StagedProposal::from_proposal_and_sender(
                    ciphersuite,
                    backend,
                    proposal,
                    sender,
                )?,
                ProposalOrRef::Reference(ref proposal_reference) => {
                    match proposals_by_reference_queue.get(proposal_reference) {
                        Some(queued_proposal) => queued_proposal.clone(),
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

    /// Returns an iterator over a list of `QueuedProposal` filtered by proposal
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
}
