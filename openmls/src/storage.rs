#[derive(Debug, Clone, Default)]
pub struct OpenMlsTypes;

use openmls_traits::storage::*;

use crate::ciphersuite::hash_ref::ProposalRef;
use crate::group::GroupContext;
use crate::group::GroupId;
use crate::group::InterimTranscriptHash;
use crate::group::QueuedProposal;
use crate::messages::ConfirmationTag;
use crate::treesync::TreeSync;

impl Entity<1> for QueuedProposal {}
impl QueuedProposalEntity<1> for QueuedProposal {}

impl Entity<1> for TreeSync {}
impl TreeSyncEntity<1> for TreeSync {}

impl Key<1> for GroupId {}
impl GroupIdKey<1> for GroupId {}

impl Key<1> for ProposalRef {}
impl Entity<1> for ProposalRef {}
impl ProposalRefKey<1> for ProposalRef {}
impl ProposalRefEntity<1> for ProposalRef {}

impl Entity<1> for GroupContext {}
impl GroupContextEntity<1> for GroupContext {}

impl Entity<1> for InterimTranscriptHash {}
impl InterimTranscriptHashEntity<1> for InterimTranscriptHash {}

impl Entity<1> for ConfirmationTag {}
impl ConfirmationTagEntity<1> for ConfirmationTag {}

impl Types<1> for OpenMlsTypes {
    type QueuedProposal = QueuedProposal;
    type GroupId = GroupId;
    type ProposalRef = ProposalRef;
    type TreeSync = TreeSync;
    type GroupContext = GroupContext;
    type InterimTranscriptHash = InterimTranscriptHash;
    type ConfirmationTag = ConfirmationTag;
}

pub trait StorageProvider:
    openmls_traits::storage::StorageProvider<1, Types = OpenMlsTypes>
{
}

impl<P: openmls_traits::storage::StorageProvider<1, Types = OpenMlsTypes>> StorageProvider for P {}

pub trait RefinedProvider:
    openmls_traits::OpenMlsProvider<StorageProvider = Self::Storage>
{
    type Storage: StorageProvider;
}

impl<SP: StorageProvider, OP: openmls_traits::OpenMlsProvider<StorageProvider = SP>> RefinedProvider
    for OP
{
    type Storage = SP;
}
