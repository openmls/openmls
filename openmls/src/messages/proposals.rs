use crate::ciphersuite::*;
use crate::config::ProtocolVersion;
use crate::extensions::Extension;
use crate::framing::*;
use crate::group::GroupId;
use crate::key_packages::*;
use crate::schedule::psk::*;
use crate::tree::index::*;

use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::convert::TryFrom;
use tls_codec::{
    Serialize as TlsSerializeTrait, Size, TlsByteVecU8, TlsDeserialize, TlsSerialize, TlsSize,
    TlsVecU32,
};

use super::errors::*;

#[derive(PartialEq, Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum ProposalType {
    Add = 1,
    Update = 2,
    Remove = 3,
    Presharedkey = 4,
    Reinit = 5,
}

impl TryFrom<u8> for ProposalType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ProposalType::Add),
            2 => Ok(ProposalType::Update),
            3 => Ok(ProposalType::Remove),
            4 => Ok(ProposalType::Presharedkey),
            5 => Ok(ProposalType::Reinit),
            _ => Err("Unknown proposal type."),
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
#[derive(PartialEq, Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
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
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Proposal {
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
    PreSharedKey(PreSharedKeyProposal),
    ReInit(ReInitProposal),
}

impl Proposal {
    pub(crate) fn proposal_type(&self) -> ProposalType {
        match self {
            Proposal::Add(ref _a) => ProposalType::Add,
            Proposal::Update(ref _u) => ProposalType::Update,
            Proposal::Remove(ref _r) => ProposalType::Remove,
            Proposal::PreSharedKey(ref _p) => ProposalType::Presharedkey,
            Proposal::ReInit(ref _r) => ProposalType::Reinit,
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
    pub(crate) fn as_presharedkey(&self) -> Option<PreSharedKeyProposal> {
        match self {
            Proposal::PreSharedKey(psk_proposal) => Some(psk_proposal.clone()),
            _ => None,
        }
    }
}

/// Reference to a Proposal. This can be used in Commit messages to reference
/// proposals that have already been sent
#[derive(
    Debug, Eq, PartialEq, Hash, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct ProposalReference {
    pub(crate) value: TlsByteVecU8,
}

impl ProposalReference {
    pub(crate) fn from_proposal(
        ciphersuite: &Ciphersuite,
        proposal: &Proposal,
    ) -> Result<Self, tls_codec::Error> {
        let encoded = proposal.tls_serialize_detached()?;
        let value = ciphersuite.hash(&encoded).into();
        Ok(Self { value })
    }
}

/// Alternative representation of a Proposal, where the sender is extracted from
/// the encapsulating MlsPlaintext and the ProposalReference is attached.
#[derive(Clone)]
pub(crate) struct QueuedProposal<'a> {
    proposal: &'a Proposal,
    proposal_reference: ProposalReference,
    sender: Sender,
    proposal_or_ref_type: ProposalOrRefType,
}

impl<'a> QueuedProposal<'a> {
    /// Creates a new `QueuedProposal` from an `MlsPlaintext`
    pub(crate) fn from_mls_plaintext(
        ciphersuite: &Ciphersuite,
        mls_plaintext: &'a MlsPlaintext,
    ) -> Result<Self, QueuedProposalError> {
        debug_assert!(mls_plaintext.content_type() == MlsPlaintextContentType::Proposal);
        let proposal = match mls_plaintext.content() {
            MlsPlaintextContent::Proposal(p) => p,
            _ => return Err(QueuedProposalError::WrongContentType),
        };
        let proposal_reference = ProposalReference::from_proposal(ciphersuite, proposal)?;
        Ok(Self {
            proposal,
            proposal_reference,
            sender: *mls_plaintext.sender(),
            proposal_or_ref_type: ProposalOrRefType::Reference,
        })
    }
    /// Creates a new `QueuedProposal` from a `Proposal` and `Sender`
    pub(crate) fn from_proposal_and_sender(
        ciphersuite: &Ciphersuite,
        proposal: &'a Proposal,
        sender: Sender,
    ) -> Result<Self, QueuedProposalError> {
        let proposal_reference = ProposalReference::from_proposal(ciphersuite, proposal)?;
        Ok(Self {
            proposal,
            proposal_reference,
            sender,
            proposal_or_ref_type: ProposalOrRefType::Proposal,
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
#[derive(Default)]
pub struct ProposalQueue<'a> {
    /// `proposal_references` holds references to the proposals in the queue and
    /// determines the order of the queue.
    proposal_references: Vec<ProposalReference>,
    /// `queued_proposals` contains the actual proposals in the queue. They are
    /// stored in a `HashMap` to allow for efficient access to the proposals.
    queued_proposals: HashMap<ProposalReference, QueuedProposal<'a>>,
}

impl<'a> ProposalQueue<'a> {
    /// Returns a new `ProposalQueue` from proposals that were committed and
    /// don't need filtering
    pub(crate) fn from_proposals_by_reference(
        ciphersuite: &Ciphersuite,
        proposals: &'a [&MlsPlaintext],
    ) -> Self {
        let mut proposal_queue = ProposalQueue::default();
        for mls_plaintext in proposals {
            // It is safe to unwrap here, because we checked that only proposals can end up
            // here.
            let queued_proposal =
                QueuedProposal::from_mls_plaintext(ciphersuite, mls_plaintext).unwrap();
            proposal_queue.add(queued_proposal);
        }
        proposal_queue
    }
    /// Returns a new `ProposalQueue` from proposals that were committed and
    /// don't need filtering
    pub(crate) fn from_committed_proposals(
        ciphersuite: &Ciphersuite,
        committed_proposals: &'a [ProposalOrRef],
        proposals_by_reference: &[&'a MlsPlaintext],
        sender: Sender,
    ) -> Result<Self, ProposalQueueError> {
        // Feed the `proposals_by_reference` in a `HashMap` so that we can easily
        // extract then by reference later
        let mut proposals_by_reference_queue: HashMap<ProposalReference, QueuedProposal> =
            HashMap::new();
        for mls_plaintext in proposals_by_reference {
            let queued_proposal = QueuedProposal::from_mls_plaintext(ciphersuite, mls_plaintext)?;
            proposals_by_reference_queue
                .insert(queued_proposal.proposal_reference(), queued_proposal);
        }

        // Build the actual queue
        let mut proposal_queue = ProposalQueue::default();

        // Iterate over the committed proposals and insert the proposals in the queue
        for proposal_or_ref in committed_proposals.iter() {
            let queued_proposal = match proposal_or_ref {
                ProposalOrRef::Proposal(proposal) => {
                    QueuedProposal::from_proposal_and_sender(ciphersuite, proposal, sender)?
                }
                ProposalOrRef::Reference(proposal_reference) => {
                    match proposals_by_reference_queue.get(proposal_reference) {
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
        proposals_by_reference: &'a [&MlsPlaintext],
        proposals_by_value: &'a [&Proposal],
        own_index: LeafIndex,
        tree_size: LeafIndex,
    ) -> Result<(Self, bool), ProposalQueueError> {
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
        let mut queued_proposal_list = proposals_by_reference
            .iter()
            .map(|&mls_plaintext| QueuedProposal::from_mls_plaintext(ciphersuite, mls_plaintext))
            .collect::<Result<Vec<QueuedProposal>, _>>()?;

        queued_proposal_list.extend(
            proposals_by_value
                .iter()
                .map(|&p| QueuedProposal::from_proposal_and_sender(ciphersuite, p, sender))
                .collect::<Result<Vec<QueuedProposal>, _>>()?
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
        let mut proposal_queue = ProposalQueue::default();
        for proposal_reference in adds.iter().chain(valid_proposals.iter()) {
            proposal_queue.add(match proposal_pool.get(proposal_reference) {
                Some(queued_proposal) => queued_proposal.clone(),
                None => return Err(ProposalQueueError::ProposalNotFound),
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

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct AddProposal {
    pub(crate) key_package: KeyPackage,
}

impl AddProposal {
    /// Get a reference to the key package in the proposal.
    pub(crate) fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }
}

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct UpdateProposal {
    pub(crate) key_package: KeyPackage,
}

impl UpdateProposal {
    /// Get a reference to the key package in the proposal.
    pub(crate) fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }
}

#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct RemoveProposal {
    pub(crate) removed: u32,
}

impl RemoveProposal {
    /// Get the `u32` index in this proposal.
    pub(crate) fn removed(&self) -> u32 {
        self.removed
    }
}

/// Preshared Key proposal
/// 11.1.4
/// struct {
///     PreSharedKeyID psk;
/// } PreSharedKey;
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct PreSharedKeyProposal {
    psk: PreSharedKeyId,
}

impl PreSharedKeyProposal {
    /// Create a new PSK proposal
    pub(crate) fn new(psk: PreSharedKeyId) -> Self {
        Self { psk }
    }

    /// Get a reference to the [`PreSharedKeyId`] in this proposal.
    pub(crate) fn psk(&self) -> &PreSharedKeyId {
        &self.psk
    }

    /// Get the [`PreSharedKeyId`] and consume this proposal.
    pub(crate) fn into_psk_id(self) -> PreSharedKeyId {
        self.psk
    }
}

/// ReInit proposal
/// 11.1.5
/// struct {
///     opaque group_id<0..255>;
///     ProtocolVersion version;
///     CipherSuite cipher_suite;
///     Extension extensions<0..2^32-1>;
/// } ReInit;
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ReInitProposal {
    pub(crate) group_id: GroupId,
    pub(crate) version: ProtocolVersion,
    pub(crate) ciphersuite: CiphersuiteName,
    pub(crate) extensions: TlsVecU32<Extension>,
}
